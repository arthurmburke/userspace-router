//! Utility functions for DPDK.

use std::collections::BTreeMap;

use crate::dpdk::{lcore::Lcore, port::PortInfo};

/// A greedy algorithm to assign ports to lcores.
/// First attempts to assign ports to lcores on the same socket,
/// then assigns remaining ports to the least loaded lcore regardless of socket.
pub fn assign_ports<'a, P: Iterator<Item = &'a PortInfo>, L: Iterator<Item = &'a Lcore>>(
    ports: P,
    lcores: L,
) -> BTreeMap<u16, u32> {
    let mut assignments = BTreeMap::new();

    let mut load: BTreeMap<u32, usize> = BTreeMap::new();
    let ports = ports.collect::<Vec<_>>();
    let lcores = lcores.collect::<Vec<_>>();

    for &port in ports.iter() {
        let selected = lcores
            .iter()
            .filter(|l| l.socket == port.socket_id as u32)
            .min_by_key(|l| load[&l.id])
            .or_else(|| lcores.iter().min_by_key(|l| load[&l.id]))
            .expect("at least one lcore required");

        assignments.insert(port.port_id, selected.id);

        *load.entry(selected.id).or_default() += 1;
    }

    assignments
}
