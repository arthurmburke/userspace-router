//! Router control plane: ARP responses, DHCP (LAN server + WAN client), and the
//! frame builders they rely on. Pure logic, independent of DPDK so it can be
//! unit-tested on any host; `src/main.rs` wires it onto the NIC.

pub mod arp;
pub mod conf;
pub mod dhcp;
pub mod frame;
