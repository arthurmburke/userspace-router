//! A forwarding database (FDB) for Ethernet frames, mapping destination MAC addresses to output ports.

use std::{collections::BTreeMap, sync::Arc};

use crate::{
    core::spinlock::SpinLock,
    net::ethernet::{MacAddr, display_mac},
};

enum Entry<P> {
    Resolved(u16),
    Pending(Vec<P>),
}

pub struct Fdb<P> {
    table: BTreeMap<MacAddr, Entry<P>>,
    cache_size: usize,
}

impl<P> Fdb<P> {
    pub fn new(cache_size: usize) -> Self {
        Self {
            table: BTreeMap::new(),
            cache_size,
        }
    }

    pub fn insert(&mut self, src: MacAddr, port: u16) -> Option<Vec<P>> {
        if let Some(Entry::Pending(packets)) = self.table.insert(src, Entry::Resolved(port)) {
            Some(packets)
        } else {
            None
        }
    }

    pub fn resolve(&mut self, dst: MacAddr, packet: P) -> Option<u16> {
        let e = self
            .table
            .entry(dst)
            .or_insert_with(|| Entry::Pending(Vec::with_capacity(self.cache_size)));
        match e {
            Entry::Resolved(port) => Some(*port),
            Entry::Pending(packets) => {
                if packets.len() == self.cache_size {
                    // Cache is full; drop the packet and don't add it to the pending list.
                    eprintln!(
                        "[WARN]: FDB pending list for {} is full; dropping packet",
                        display_mac(&dst)
                    );
                } else {
                    packets.push(packet);
                }
                None
            }
        }
    }
}

pub struct SharedFdb<P> {
    inner: Arc<SpinLock<Fdb<P>>>,
}

impl<P> SharedFdb<P> {
    pub fn new(cache_size: usize) -> Self {
        Self {
            inner: Arc::new(SpinLock::new(Fdb::new(cache_size))),
        }
    }

    pub fn insert(&self, src: MacAddr, port: u16) -> Option<Vec<P>> {
        self.inner.with(|inner| inner.insert(src, port))
    }

    pub fn resolve(&self, dst: MacAddr, packet: P) -> Option<u16> {
        self.inner.with(|inner| inner.resolve(dst, packet))
    }
}
