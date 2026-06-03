//! A forwarding database (FDB) for Ethernet frames: a plain MAC → port map.
//!
//! The data plane floods on a miss (unknown-unicast flood, the standard bridge
//! behaviour), so the FDB doesn't need to queue packets while waiting to learn
//! a destination MAC — the flood reaches it. That makes the FDB a pure cache:
//! `insert` records `src → port` on every observed frame, and `lookup` returns
//! the cached egress port (if any). No packet types, no pending lists, no
//! generic parameter.

use std::{collections::BTreeMap, sync::Arc};

use crate::{
    core::spinlock::SpinLock,
    net::ethernet::{MacAddr, display_mac},
};

pub struct Fdb {
    table: BTreeMap<MacAddr, u16>,
}

impl Fdb {
    pub fn new() -> Self {
        Self {
            table: BTreeMap::new(),
        }
    }

    /// Record `src → port`. Overwrites any previous mapping for `src` so that
    /// a host that roams between physical ports gets re-learned on the new
    /// port the next time we see traffic from it.
    pub fn insert(&mut self, src: MacAddr, port: u16) {
        self.table.insert(src, port);
    }

    /// Look up the egress port we last learned for `dst`. `None` means
    /// "unknown unicast" — the caller should flood.
    pub fn lookup(&self, dst: MacAddr) -> Option<u16> {
        self.table.get(&dst).copied()
    }

    /// Number of MACs currently learned.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn status(&self, f: &mut impl std::fmt::Write) -> std::fmt::Result {
        writeln!(f, "FDB entries:")?;
        for (mac, port) in &self.table {
            writeln!(f, "  {} → port {}", display_mac(mac), port)?;
        }
        Ok(())
    }
}

impl Default for Fdb {
    fn default() -> Self {
        Self::new()
    }
}

/// Cloneable handle to an [`Fdb`] shared across workers. Operations take the
/// spinlock briefly; both `insert` and `lookup` are O(log n) BTree ops.
#[derive(Clone)]
pub struct SharedFdb {
    inner: Arc<SpinLock<Fdb>>,
}

impl SharedFdb {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(SpinLock::new(Fdb::new())),
        }
    }

    pub fn insert(&self, src: MacAddr, port: u16) {
        self.inner.with(|inner| inner.insert(src, port));
    }

    pub fn lookup(&self, dst: MacAddr) -> Option<u16> {
        self.inner.with(|inner| inner.lookup(dst))
    }

    pub fn len(&self) -> usize {
        self.inner.with(|inner| inner.len())
    }
}

impl Default for SharedFdb {
    fn default() -> Self {
        Self::new()
    }
}
