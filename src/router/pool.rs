//! A simple DHCP pool used for assigning addresses to LAN clients. It is a collection of
//! disjoint intervals of addresses, range inclusive. The `take` method removes addresses from the pool,
//! and the `merge` method merges adjacent intervals.

use std::{net::Ipv4Addr, sync::Arc};

use crate::core::spinlock::SpinLock;

#[derive(Clone)]
pub struct SharedAddressPool {
    inner: Arc<SpinLock<AddressPool>>,
}

impl SharedAddressPool {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self {
            inner: Arc::new(SpinLock::new(AddressPool::new(start, end))),
        }
    }

    pub fn take(&self, n: usize) -> Option<Vec<Ipv4Addr>> {
        self.inner.with(|inner| inner.take(n))
    }

    pub fn release(&self, ip: Ipv4Addr) {
        self.inner.with(|inner| inner.release(ip));
    }

    pub fn reserve(&self, ip: Ipv4Addr) -> Option<Ipv4Addr> {
        self.inner.with(|inner| inner.reserve(ip))
    }

    pub fn start(&self) -> Ipv4Addr {
        self.inner.with(|inner| inner.start())
    }

    pub fn end(&self) -> Ipv4Addr {
        self.inner.with(|inner| inner.end())
    }
}

pub struct AddressPool {
    start: Ipv4Addr,
    end: Ipv4Addr,
    intervals: Vec<(Ipv4Addr, Ipv4Addr)>,
}

impl AddressPool {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        assert!(start <= end, "invalid address pool");

        Self {
            start,
            end,
            intervals: vec![(start, end)],
        }
    }

    /// Reserve an address from the pool so it won't be handed out by [`take`].
    /// Returns `Some(addr)` if it was in the free pool (now removed), or `None`
    /// if it wasn't (already reserved/taken, in a gap, or out of range).
    /// Idempotent — repeated calls for the same address return `None` after
    /// the first.
    ///
    /// [`take`]: AddressPool::take
    pub fn reserve(&mut self, addr: Ipv4Addr) -> Option<Ipv4Addr> {
        // The matching interval (if any) is the **last** one whose start is
        // `<= addr`. `partition_point` returns the count of leading intervals
        // satisfying the predicate, so subtract one to index the candidate.
        let pos = self
            .intervals
            .partition_point(|(s, _)| u32::from(*s) <= u32::from(addr));
        if pos == 0 {
            return None; // addr is before every interval
        }
        let idx = pos - 1;
        let (start, end) = self.intervals[idx];
        if u32::from(addr) > u32::from(end) {
            return None; // addr sits in the gap after this interval
        }

        // start <= addr <= end: split, shrink, or remove the interval.
        if start == addr && end == addr {
            // Single-element interval — drop it entirely.
            self.intervals.remove(idx);
        } else if start == addr {
            self.intervals[idx].0 = Ipv4Addr::from(u32::from(addr) + 1);
        } else if end == addr {
            self.intervals[idx].1 = Ipv4Addr::from(u32::from(addr) - 1);
        } else {
            self.intervals
                .insert(idx + 1, (Ipv4Addr::from(u32::from(addr) + 1), end));
            self.intervals[idx].1 = Ipv4Addr::from(u32::from(addr) - 1);
        }
        Some(addr)
    }

    /// Take `n` addresses from the pool, returning them as a vector. If the pool has fewer than `n` addresses, returns `None` and leaves the pool unchanged.
    pub fn take(&mut self, n: usize) -> Option<Vec<Ipv4Addr>> {
        // bail before mutating.
        let mut available = 0usize;
        for (s, e) in &self.intervals {
            available += (u32::from(*e) - u32::from(*s) + 1) as usize;
            if available >= n {
                break;
            }
        }
        if available < n {
            return None;
        }

        // Bulk-consume from the head.
        let mut out = Vec::with_capacity(n);
        let mut full_consumed = 0;
        let mut remaining = n;
        for (s, e) in self.intervals.iter_mut() {
            let span = (u32::from(*e) - u32::from(*s) + 1) as usize;
            if span <= remaining {
                for v in u32::from(*s)..=u32::from(*e) {
                    out.push(Ipv4Addr::from(v));
                }
                full_consumed += 1;
                remaining -= span;
                if remaining == 0 {
                    break;
                }
            } else {
                let s_u = u32::from(*s);
                for v in s_u..(s_u + remaining as u32) {
                    out.push(Ipv4Addr::from(v));
                }
                *s = Ipv4Addr::from(s_u + remaining as u32);
                break;
            }
        }
        // One O(k) shift instead of one per emptied interval.
        self.intervals.drain(..full_consumed);

        Some(out)
    }

    pub fn release(&mut self, ip: Ipv4Addr) {
        // Address must actually be within the original bounds of the pool
        assert!(
            self.start <= ip && ip <= self.end,
            "IP is not in pool bounds"
        );

        // Find point to insert the releases address.
        let pos = self
            .intervals
            .partition_point(|(s, _)| u32::from(*s) < u32::from(ip));
        // pos points to the first interval whose start >= ip; the interval before it
        // (if any) is the candidate left neighbour, intervals[pos] the right neighbour.
        let left_adj = pos > 0 && u32::from(self.intervals[pos - 1].1) + 1 == u32::from(ip);
        let right_adj =
            pos < self.intervals.len() && u32::from(self.intervals[pos].0) == u32::from(ip) + 1;
        match (left_adj, right_adj) {
            (true, true) => {
                self.intervals[pos - 1].1 = self.intervals[pos].1;
                self.intervals.remove(pos);
            }
            (true, false) => {
                self.intervals[pos - 1].1 = ip;
            }
            (false, true) => {
                self.intervals[pos].0 = ip;
            }
            (false, false) => {
                self.intervals.insert(pos, (ip, ip));
            }
        }
    }

    pub fn start(&self) -> Ipv4Addr {
        self.start
    }

    pub fn end(&self) -> Ipv4Addr {
        self.end
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::router::pool::AddressPool;

    #[test]
    fn test_roundtrip() {
        let mut pool = AddressPool::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 254),
        );

        let addrs = pool.take(10).expect("enough addresses");
        assert_eq!(addrs.len(), 10);
        assert_eq!(addrs[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addrs[9], Ipv4Addr::new(192, 168, 1, 10));

        assert_eq!(
            pool.intervals,
            vec![(
                Ipv4Addr::new(192, 168, 1, 11),
                Ipv4Addr::new(192, 168, 1, 254)
            )]
        );

        // Release some addresses and check they are re-allocated.
        for addr in addrs {
            pool.release(addr);
        }

        assert_eq!(
            pool.intervals,
            vec![(
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 254)
            )]
        );
    }

    #[test]
    fn reserve_splits_shrinks_and_removes() {
        // Reserve in the middle of a single interval -> the interval splits.
        let mut p = AddressPool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(
            p.reserve(Ipv4Addr::new(10, 0, 0, 5)),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
        assert_eq!(
            p.intervals,
            vec![
                (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 4)),
                (Ipv4Addr::new(10, 0, 0, 6), Ipv4Addr::new(10, 0, 0, 10)),
            ]
        );
        // Idempotent — already removed; subsequent reserve returns None.
        assert_eq!(p.reserve(Ipv4Addr::new(10, 0, 0, 5)), None);

        // Reserve at start/end shrinks the interval.
        let mut p = AddressPool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(
            p.reserve(Ipv4Addr::new(10, 0, 0, 1)),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            p.reserve(Ipv4Addr::new(10, 0, 0, 3)),
            Some(Ipv4Addr::new(10, 0, 0, 3))
        );
        assert_eq!(
            p.intervals,
            vec![(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 2))]
        );
        // Now the only interval is a single element — reserving it removes it.
        assert_eq!(
            p.reserve(Ipv4Addr::new(10, 0, 0, 2)),
            Some(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert!(p.intervals.is_empty());
    }

    #[test]
    fn reserve_handles_interior_address_in_pool() {
        // Regression: the previous implementation used `partition_point(|s|
        // s < addr)`, which returned the wrong index for addresses strictly
        // inside an interval, making `reserve` silently a no-op for nearly
        // every realistic address.
        let mut p = AddressPool::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
        );
        assert_eq!(
            p.reserve(Ipv4Addr::new(192, 168, 1, 150)),
            Some(Ipv4Addr::new(192, 168, 1, 150))
        );
        // Out-of-range addresses are quietly ignored.
        assert_eq!(p.reserve(Ipv4Addr::new(192, 168, 1, 50)), None);
        assert_eq!(p.reserve(Ipv4Addr::new(192, 168, 1, 250)), None);
        assert_eq!(p.reserve(Ipv4Addr::new(0, 0, 0, 0)), None);
    }

    #[test]
    fn take_after_reserve_skips_the_reserved_address() {
        let mut p = AddressPool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 10));
        p.reserve(Ipv4Addr::new(10, 0, 0, 5));
        let addrs = p.take(9).expect("9 available after one reserved");
        assert!(addrs.iter().all(|&ip| ip != Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(addrs.len(), 9);
        // The pool is now empty.
        assert!(p.take(1).is_none());
    }
}
