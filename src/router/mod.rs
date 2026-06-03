//! Router control plane: ARP responses, DHCP (LAN server + WAN client), and the
//! frame builders they rely on. Pure logic, independent of DPDK so it can be
//! unit-tested on any host; `src/main.rs` wires it onto the NIC.

pub mod arp;
pub mod conf;
pub mod conntrack;
pub mod dhcp;
pub mod fdb;
pub mod frame;
pub mod leases;
pub mod nat;
pub mod neighbor;
pub mod pool;

// `app` and `worker` reach into `crate::dpdk` (Mbuf, Port, FFI), which is itself
// `#[cfg(feature = "dpdk")]`. Gate them together so the crate still type-checks
// without DPDK installed.
#[cfg(feature = "dpdk")]
pub mod app;
#[cfg(feature = "dpdk")]
pub mod worker;
