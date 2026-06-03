//! Shared DHCP lease table.
//!
//! On a **bridged LAN** every physical LAN port is one broadcast domain, so a
//! client roaming between ports must keep its lease — the per-port
//! [`DhcpServer`](crate::router::dhcp::DhcpServer) instances therefore share a
//! single [`SharedLeases`] alongside their [`SharedAddressPool`].
//!
//! `Clone` on the handle is `Arc::clone` (cheap); every method takes `&self`
//! and locks internally, mirroring the address-pool wrapper.

use crate::core::spinlock::SpinLock;
use crate::net::ethernet::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// A thread-safe handle to one [`LeaseTable`]. Cloning gives another handle to
/// the same underlying state.
#[derive(Clone)]
pub struct SharedLeases {
    inner: Arc<SpinLock<LeaseTable>>,
}

impl SharedLeases {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(SpinLock::new(LeaseTable::default())),
        }
    }

    /// IP currently bound to `mac`, if any.
    pub fn lookup(&self, mac: MacAddr) -> Option<Ipv4Addr> {
        self.inner.with(|t| t.lookup(mac))
    }

    /// Record a `mac -> ip` binding, replacing any previous binding for `mac`.
    pub fn insert(&self, mac: MacAddr, ip: Ipv4Addr) {
        self.inner.with(|t| t.insert(mac, ip));
    }

    /// Remove and return the binding for `mac`, if it existed.
    pub fn remove(&self, mac: MacAddr) -> Option<Ipv4Addr> {
        self.inner.with(|t| t.remove(mac))
    }

    /// Number of bindings currently held.
    pub fn len(&self) -> usize {
        self.inner.with(|t| t.len())
    }

    pub fn is_empty(&self) -> bool {
        self.inner.with(|t| t.is_empty())
    }

    pub fn status(&self, f: &mut impl std::fmt::Write) -> std::fmt::Result {
        self.inner.with(|t| t.status(f))
    }
}

impl Default for SharedLeases {
    fn default() -> Self {
        Self::new()
    }
}

/// The non-shared inner table. Public so callers wanting fully exclusive
/// access (e.g. tests) can construct one directly, but the runtime always uses
/// [`SharedLeases`].
#[derive(Default)]
pub struct LeaseTable {
    by_mac: HashMap<MacAddr, Ipv4Addr>,
}

impl LeaseTable {
    pub fn lookup(&self, mac: MacAddr) -> Option<Ipv4Addr> {
        self.by_mac.get(&mac).copied()
    }
    pub fn insert(&mut self, mac: MacAddr, ip: Ipv4Addr) {
        self.by_mac.insert(mac, ip);
    }
    pub fn remove(&mut self, mac: MacAddr) -> Option<Ipv4Addr> {
        self.by_mac.remove(&mac)
    }
    pub fn len(&self) -> usize {
        self.by_mac.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_mac.is_empty()
    }
    pub fn status(&self, f: &mut impl std::fmt::Write) -> std::fmt::Result {
        writeln!(f, "  Leases:")?;
        for (mac, ip) in &self.by_mac {
            writeln!(f, "    {:02x?} → {}", mac, ip)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_A: MacAddr = [0x02, 0, 0, 0, 0, 0x10];
    const MAC_B: MacAddr = [0x02, 0, 0, 0, 0, 0x11];
    const IP_A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
    const IP_B: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 101);

    /// Compile-time check: the handle is `Send + Sync` so workers can share it.
    fn _assert_send_sync() {
        fn req<T: Send + Sync>() {}
        req::<SharedLeases>();
    }

    #[test]
    fn clones_observe_one_table() {
        let a = SharedLeases::new();
        let b = a.clone();
        a.insert(MAC_A, IP_A);
        assert_eq!(b.lookup(MAC_A), Some(IP_A));
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn safe_across_threads() {
        let a = SharedLeases::new();
        let b = a.clone();
        let writer = std::thread::spawn(move || {
            b.insert(MAC_B, IP_B);
        });
        writer.join().unwrap();
        assert_eq!(a.lookup(MAC_B), Some(IP_B));
    }

    #[test]
    fn remove_returns_then_clears() {
        let l = SharedLeases::new();
        l.insert(MAC_A, IP_A);
        l.insert(MAC_B, IP_B);
        assert_eq!(l.remove(MAC_A), Some(IP_A));
        assert!(l.lookup(MAC_A).is_none());
        // Idempotent.
        assert_eq!(l.remove(MAC_A), None);
        // The other binding is untouched.
        assert_eq!(l.lookup(MAC_B), Some(IP_B));
        assert_eq!(l.len(), 1);
    }
}
