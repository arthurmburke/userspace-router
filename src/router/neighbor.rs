//! Active ARP-based neighbor resolution for IPv4 over Ethernet.
//!
//! [`NeighborTable`] is a cache *plus* a per-target pending queue with
//! retransmits and aging. Egress packets needing a next-hop MAC go through
//! [`NeighborTable::resolve`]:
//!
//! - **Cache hit** → `Forward { mac, packet }`; transmit immediately.
//! - **Cache miss** → the packet is queued under `target_ip`. If this is the
//!   first miss for that target, an ARP request is built into the caller's
//!   buffer to transmit; subsequent misses for the same target queue silently.
//! - **Queue full** → `Drop { packet }`; the caller drops it.
//!
//! Inbound ARP frames are fed to [`NeighborTable::on_arp`], which learns the
//! sender mapping (so both requests and replies populate the cache) and returns
//! any packets that the new mapping unblocked.
//!
//! Time is passed in as a [`Tick`] so this stays fully deterministic and
//! testable. Call [`NeighborTable::sweep`] periodically (e.g. once a loop
//! iteration) to retransmit unanswered requests, expire pending entries whose
//! target never replied, and age out stale cache entries.

use crate::net::arp;
use crate::core::spinlock::RwSpinLock;
use crate::net::ethernet::{MacAddr, MacAddrFmt};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// Cap on packets queued per unresolved target IP. A flapping or unreachable
/// host can't pin unbounded memory; excess packets are returned to the caller.
pub const MAX_PENDING_PER_IP: usize = 4;

/// How long to wait between ARP request attempts for the same target.
pub const REQUEST_INTERVAL_MS: u64 = 1000;
/// Number of ARP request attempts before giving up and dropping the queue.
pub const MAX_REQUEST_ATTEMPTS: u8 = 3;
/// Cache entries older than this are aged out by [`NeighborTable::sweep`].
pub const CACHE_TTL_MS: u64 = 5 * 60 * 1000;

/// Monotonic millisecond tick. Callers pass `now` to every state-changing
/// operation; the table never reads the clock itself, so tests drive time
/// explicitly and the production loop can use any source it likes (`Instant`,
/// `rte_get_tsc_cycles`, ...).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Tick(pub u64);

impl Tick {
    pub const fn ms(v: u64) -> Self {
        Self(v)
    }
    /// Milliseconds elapsed since `earlier`, saturating at 0 if `earlier` is in
    /// the future (clock skew, freshly inserted entry, ...).
    pub fn elapsed_since(self, earlier: Tick) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

impl std::fmt::Display for Tick {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ms", self.0)
    }
}

/// A cache entry plus when it was learned, so [`NeighborTable::sweep`] can age
/// it out.
#[derive(Clone, Copy)]
struct CachedEntry {
    mac: MacAddr,
    learned_at: Tick,
}

/// Per-target pending state: queued packets plus retransmit bookkeeping.
struct Pending<P> {
    packets: Vec<P>,
    /// When the most recent ARP request for this target was sent.
    last_request_at: Tick,
    /// How many request attempts have been made so far.
    attempts: u8,
}

/// Active resolver: cache + pending queues + retransmit/aging.
pub struct NeighborTable<P> {
    our_mac: MacAddr,
    our_ip: Ipv4Addr,
    resolved: HashMap<MacAddr, Ipv4Addr>,
    cache: HashMap<Ipv4Addr, CachedEntry>,
    pending: HashMap<Ipv4Addr, Pending<P>>,
}

/// Outcome of [`NeighborTable::resolve`].
pub enum Action<P> {
    /// Cache hit — forward `packet` to `mac`.
    Forward { mac: MacAddr, packet: P },
    /// Cache miss; `packet` was queued. `request_len` is `Some(n)` iff an ARP
    /// request of `n` bytes was built into the caller's buffer to transmit
    /// (only the first miss for a given target emits one; later misses queue
    /// silently). It can also be `None` if `req_buf` was too small.
    Queued { request_len: Option<usize> },
    /// Cache miss and the pending queue for this target is full; `packet` is
    /// returned to the caller to drop.
    Drop { packet: P },
}

impl<P> NeighborTable<P> {
    pub fn new(our_mac: MacAddr, our_ip: Ipv4Addr) -> Self {
        Self {
            our_mac,
            our_ip,
            resolved: HashMap::new(),
            cache: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Update the interface's own IP (e.g. once the WAN DHCP lease binds).
    pub fn set_our_ip(&mut self, ip: Ipv4Addr) {
        self.our_ip = ip;
    }

    pub fn known(&self) -> usize {
        self.cache.len()
    }
    pub fn pending_targets(&self) -> usize {
        self.pending.len()
    }

    /// Look up a MAC without touching the pending queue.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.cache.get(&ip).map(|e| e.mac)
    }

    /// Reverse lookup an IP from a MAC address without touching the pending queue.
    pub fn reverse_lookup(&self, mac: MacAddr) -> Option<Ipv4Addr> {
        self.resolved.get(&mac).copied()
    }

    /// Insert a mapping directly (e.g. one learned from a DHCP exchange).
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr, now: Tick) {
        self.cache.insert(
            ip,
            CachedEntry {
                mac,
                learned_at: now,
            },
        );
        self.resolved.insert(mac, ip);
    }

    /// Try to resolve `target_ip` for `packet`, queuing on miss and emitting an
    /// ARP request when this is the first pending packet for that target.
    pub fn resolve(
        &mut self,
        target_ip: Ipv4Addr,
        packet: P,
        req_buf: &mut [u8],
        now: Tick,
    ) -> Action<P> {
        if let Some(e) = self.cache.get(&target_ip) {
            return Action::Forward { mac: e.mac, packet };
        }
        let entry = self.pending.entry(target_ip).or_insert_with(|| Pending {
            packets: Vec::new(),
            last_request_at: now,
            attempts: 0,
        });
        if entry.packets.len() >= MAX_PENDING_PER_IP {
            return Action::Drop { packet };
        }
        let first_miss = entry.packets.is_empty();
        entry.packets.push(packet);

        let request_len = if first_miss {
            entry.attempts = 1;
            entry.last_request_at = now;
            arp::build_request(req_buf, self.our_mac, self.our_ip, target_ip)
        } else {
            None
        };
        Action::Queued { request_len }
    }

    /// Feed an inbound ARP packet. Learns the sender's mapping (regardless of
    /// opcode) and returns any packets that were waiting on that sender, paired
    /// with its now-known MAC.
    pub fn on_arp(&mut self, ip: Ipv4Addr, mac: MacAddr, now: Tick) -> Option<(MacAddr, Vec<P>)> {
        self.cache.insert(
            ip,
            CachedEntry {
                mac,
                learned_at: now,
            },
        );
        self.resolved.insert(mac, ip);
        let drained = self.pending.remove(&ip).map(|p| p.packets);
        match drained {
            Some(packets) if !packets.is_empty() => Some((mac, packets)),
            _ => None,
        }
    }

    /// Drive retransmits and aging. For each pending target whose last request
    /// is at least [`REQUEST_INTERVAL_MS`] old: build a fresh ARP request and
    /// call `emit_request` with the bytes to transmit. Targets that have hit
    /// [`MAX_REQUEST_ATTEMPTS`] have their queued packets returned to the
    /// caller (to free) and the pending entry removed. Cache entries older
    /// than [`CACHE_TTL_MS`] are evicted.
    ///
    /// Call once per main-loop iteration with the current time.
    pub fn sweep(&mut self, now: Tick, mut emit_request: impl FnMut(&[u8])) -> Vec<P> {
        let mut dropped: Vec<P> = Vec::new();
        let mut req = [0u8; arp::FRAME_LEN];
        // Copy the interface identity out so the `retain` closure doesn't try
        // to also borrow `self` while we hold `&mut self.pending`.
        let our_mac = self.our_mac;
        let our_ip = self.our_ip;

        self.pending.retain(|target, p| {
            if now.elapsed_since(p.last_request_at) < REQUEST_INTERVAL_MS {
                return true; // not time to retry yet
            }
            if p.attempts >= MAX_REQUEST_ATTEMPTS {
                // Give up: hand back the queued packets and drop the entry.
                dropped.append(&mut p.packets);
                return false;
            }
            p.attempts += 1;
            p.last_request_at = now;
            if arp::build_request(&mut req, our_mac, our_ip, *target).is_some() {
                emit_request(&req);
            }
            true
        });

        // Age out stale cache entries.
        self.cache
            .retain(|_, e| now.elapsed_since(e.learned_at) < CACHE_TTL_MS);
        // Clear out old entries from the resolved mac table.
        self.resolved.retain(|_, ip| self.cache.contains_key(ip));

        dropped
    }

    pub fn status(&self, f: &mut impl std::fmt::Write) -> std::fmt::Result {
        writeln!(f, "ARP:")?;
        writeln!(f, "  our_mac: {}, our_ip: {}", MacAddrFmt(&self.our_mac), self.our_ip)?;
        writeln!(f, "  cache:")?;
        for (ip, entry) in &self.cache {
            writeln!(f, "    {} -> {} (learned at {:?})", ip, MacAddrFmt(&entry.mac), entry.learned_at)?;
        }
        writeln!(f, "  pending:")?;
        for (ip, pending) in &self.pending {
            writeln!(f, "    {}: {} packets, last request at {:?}, attempts {}", ip, pending.packets.len(), pending.last_request_at, pending.attempts)?;
        }
        writeln!(f, "}}")
    }
}

/// A thread-safe handle to a [`NeighborTable`] shared across workers. Each
/// `Clone` is another handle to the same table (refcounted via [`Arc`]); the
/// inner spinlock serializes every operation.
///
/// `SharedNeighbor<P>: Send + Sync` whenever `P: Send`, so the same handle can
/// be held by multiple per-lcore workers — they all see and update one shared
/// cache and pending queue.
///
/// Locking note: `sweep`'s `emit_request` closure runs **while the lock is
/// held**; it must not call back into this same `SharedNeighbor` or you will
/// deadlock the spinlock.
pub struct SharedNeighbor<P> {
    inner: Arc<RwSpinLock<NeighborTable<P>>>,
}

impl<P> Clone for SharedNeighbor<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<P> SharedNeighbor<P> {
    pub fn new(our_mac: MacAddr, our_ip: Ipv4Addr) -> Self {
        Self {
            inner: Arc::new(RwSpinLock::new(NeighborTable::new(our_mac, our_ip))),
        }
    }

    pub fn set_our_ip(&self, ip: Ipv4Addr) {
        self.inner.with_write(|inner| inner.set_our_ip(ip));
    }

    pub fn known(&self) -> usize {
        self.inner.with_read(|inner| inner.known())
    }

    pub fn pending_targets(&self) -> usize {
        self.inner.with_read(|inner| inner.pending_targets())
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.inner.with_read(|inner| inner.lookup(ip))
    }

    pub fn reverse_lookup(&self, mac: MacAddr) -> Option<Ipv4Addr> {
        self.inner.with_read(|inner| inner.reverse_lookup(mac))
    }

    pub fn insert(&self, ip: Ipv4Addr, mac: MacAddr, now: Tick) {
        self.inner.with_write(|inner| inner.insert(ip, mac, now));
    }

    pub fn resolve(
        &self,
        target_ip: Ipv4Addr,
        packet: P,
        req_buf: &mut [u8],
        now: Tick,
    ) -> Action<P> {
        self.inner
            .with_write(|inner| inner.resolve(target_ip, packet, req_buf, now))
    }

    pub fn on_arp(&self, ip: Ipv4Addr, mac: MacAddr, now: Tick) -> Option<(MacAddr, Vec<P>)> {
        self.inner.with_write(|inner| inner.on_arp(ip, mac, now))
    }

    pub fn sweep(&self, now: Tick, emit_request: impl FnMut(&[u8])) -> Vec<P> {
        self.inner
            .with_write(|inner| inner.sweep(now, emit_request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::arp as narp;
    use crate::net::view;

    const OUR_MAC: MacAddr = [0x02, 0, 0, 0, 0, 0x01];
    const OUR_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
    const PEER_MAC: MacAddr = [0x02, 0, 0, 0, 0, 0x50];
    const T0: Tick = Tick::ms(0);

    #[test]
    fn cache_hit_forwards_immediately() {
        let mut n = NeighborTable::<u32>::new(OUR_MAC, OUR_IP);
        n.insert(PEER_IP, PEER_MAC, T0);
        let mut req = [0u8; narp::FRAME_LEN];
        match n.resolve(PEER_IP, 42, &mut req, T0) {
            Action::Forward { mac, packet } => {
                assert_eq!(mac, PEER_MAC);
                assert_eq!(packet, 42);
            }
            _ => panic!("expected Forward"),
        }
        assert!(req.iter().all(|b| *b == 0), "no request should be built");
    }

    #[test]
    fn miss_queues_and_emits_request_only_on_first() {
        let mut n = NeighborTable::<u32>::new(OUR_MAC, OUR_IP);
        let mut req = [0u8; narp::FRAME_LEN];

        let first = n.resolve(PEER_IP, 1, &mut req, T0);
        if let Action::Queued {
            request_len: Some(len),
        } = first
        {
            assert_eq!(len, narp::FRAME_LEN);
            let arp = view::parse(&req).unwrap().arp().unwrap();
            assert!(arp.is_request());
            assert_eq!(arp.target_ip(), PEER_IP);
            assert_eq!(arp.sender_ip(), OUR_IP);
        } else {
            panic!("first miss should queue + build a request");
        }

        let mut req2 = [0u8; narp::FRAME_LEN];
        let second = n.resolve(PEER_IP, 2, &mut req2, T0);
        assert!(matches!(second, Action::Queued { request_len: None }));
        assert!(req2.iter().all(|b| *b == 0));
        assert_eq!(n.pending_targets(), 1);
    }

    #[test]
    fn arp_reply_unblocks_queued_packets() {
        let mut n = NeighborTable::<u32>::new(OUR_MAC, OUR_IP);
        let mut req = [0u8; narp::FRAME_LEN];
        let _ = n.resolve(PEER_IP, 10, &mut req, T0);
        let _ = n.resolve(PEER_IP, 11, &mut req, T0);
        let _ = n.resolve(PEER_IP, 12, &mut req, T0);
        assert_eq!(n.pending_targets(), 1);

        let mut reply = [0u8; narp::FRAME_LEN];
        narp::build_reply(&mut reply, PEER_MAC, PEER_IP, OUR_MAC, OUR_IP).unwrap();
        let pkt = view::parse(&reply).unwrap().arp().unwrap();

        let (mac, mut drained) = n
            .on_arp(pkt.sender_ip(), pkt.sha, T0)
            .expect("queued packets should drain");
        assert_eq!(mac, PEER_MAC);
        drained.sort();
        assert_eq!(drained, vec![10, 11, 12]);
        assert_eq!(n.pending_targets(), 0);
        assert_eq!(n.lookup(PEER_IP), Some(PEER_MAC));
    }

    #[test]
    fn pending_queue_overflows_into_drop() {
        let mut n = NeighborTable::<u32>::new(OUR_MAC, OUR_IP);
        let mut req = [0u8; narp::FRAME_LEN];
        for i in 0..MAX_PENDING_PER_IP as u32 {
            assert!(matches!(
                n.resolve(PEER_IP, i, &mut req, T0),
                Action::Queued { .. }
            ));
        }
        match n.resolve(PEER_IP, 999, &mut req, T0) {
            Action::Drop { packet } => assert_eq!(packet, 999),
            _ => panic!("expected Drop on overflow"),
        }
    }

    #[test]
    fn on_arp_learns_even_without_pending_packets() {
        let mut n = NeighborTable::<u32>::new(OUR_MAC, OUR_IP);
        let mut frame = [0u8; narp::FRAME_LEN];
        narp::build_request(&mut frame, PEER_MAC, PEER_IP, OUR_IP).unwrap();
        let pkt = view::parse(&frame).unwrap().arp().unwrap();
        assert!(n.on_arp(pkt.sender_ip(), pkt.sha, T0).is_none());
        assert_eq!(n.lookup(PEER_IP), Some(PEER_MAC));
    }

    #[test]
    fn sweep_retransmits_then_drops() {
        let mut n = NeighborTable::<u32>::new(OUR_MAC, OUR_IP);
        let mut req = [0u8; narp::FRAME_LEN];
        // Attempt 1 at t=0.
        assert!(matches!(
            n.resolve(PEER_IP, 7, &mut req, T0),
            Action::Queued {
                request_len: Some(_)
            }
        ));

        let mut emitted = 0usize;
        // No retry yet: not enough time has passed.
        let dropped = n.sweep(Tick::ms(REQUEST_INTERVAL_MS - 1), |_| emitted += 1);
        assert_eq!(emitted, 0);
        assert!(dropped.is_empty());

        // Attempt 2 at t=interval.
        let dropped = n.sweep(Tick::ms(REQUEST_INTERVAL_MS), |_| emitted += 1);
        assert_eq!(emitted, 1);
        assert!(dropped.is_empty());

        // Attempt 3 at t=2*interval.
        let dropped = n.sweep(Tick::ms(2 * REQUEST_INTERVAL_MS), |_| emitted += 1);
        assert_eq!(emitted, 2);
        assert!(dropped.is_empty());

        // At t=3*interval we've hit MAX_REQUEST_ATTEMPTS: queue is returned for
        // the caller to free, and the pending entry is removed.
        let dropped = n.sweep(Tick::ms(3 * REQUEST_INTERVAL_MS), |_| emitted += 1);
        assert_eq!(emitted, 2, "no further requests after the cap");
        assert_eq!(dropped, vec![7]);
        assert_eq!(n.pending_targets(), 0);
    }

    #[test]
    fn sweep_ages_out_stale_cache_entries() {
        let mut n = NeighborTable::<u32>::new(OUR_MAC, OUR_IP);
        n.insert(PEER_IP, PEER_MAC, T0);
        assert_eq!(n.lookup(PEER_IP), Some(PEER_MAC));

        // Just inside TTL: still cached.
        let _ = n.sweep(Tick::ms(CACHE_TTL_MS - 1), |_| {});
        assert_eq!(n.lookup(PEER_IP), Some(PEER_MAC));

        // At/past TTL: evicted.
        let _ = n.sweep(Tick::ms(CACHE_TTL_MS), |_| {});
        assert_eq!(n.lookup(PEER_IP), None);
    }

    /// Compile-time check: a `SharedNeighbor<u32>` is `Send + Sync`, the
    /// property the multi-worker design depends on.
    fn _assert_shared_send_sync() {
        fn requires_send_sync<T: Send + Sync>() {}
        requires_send_sync::<SharedNeighbor<u32>>();
    }

    #[test]
    fn shared_clones_observe_one_table() {
        let a = SharedNeighbor::<u32>::new(OUR_MAC, OUR_IP);
        let b = a.clone();
        a.insert(PEER_IP, PEER_MAC, T0);
        assert_eq!(b.lookup(PEER_IP), Some(PEER_MAC));
        assert_eq!(a.known(), 1);
        assert_eq!(b.known(), 1);
    }

    #[test]
    fn shared_is_safe_across_threads() {
        let a = SharedNeighbor::<u32>::new(OUR_MAC, OUR_IP);
        let b = a.clone();
        let writer = std::thread::spawn(move || {
            b.insert(PEER_IP, PEER_MAC, T0);
        });
        writer.join().unwrap();
        // The main thread sees the insert another thread did.
        assert_eq!(a.lookup(PEER_IP), Some(PEER_MAC));
    }

    #[test]
    fn shared_resolve_and_on_arp_round_trip() {
        let n = SharedNeighbor::<u32>::new(OUR_MAC, OUR_IP);
        let mut req = [0u8; narp::FRAME_LEN];
        assert!(matches!(
            n.resolve(PEER_IP, 7, &mut req, T0),
            Action::Queued {
                request_len: Some(_)
            }
        ));

        let mut reply = [0u8; narp::FRAME_LEN];
        narp::build_reply(&mut reply, PEER_MAC, PEER_IP, OUR_MAC, OUR_IP).unwrap();
        let pkt = view::parse(&reply).unwrap().arp().unwrap();
        let (mac, drained) = n.on_arp(pkt.sender_ip(), pkt.sha, T0).unwrap();
        assert_eq!(mac, PEER_MAC);
        assert_eq!(drained, vec![7]);
        // Cache populated; a second clone sees the same MAC.
        assert_eq!(n.clone().lookup(PEER_IP), Some(PEER_MAC));
    }
}
