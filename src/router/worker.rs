//! Per-core datapath worker. Currently the egress (LAN→WAN) NAT path; ingress
//! and the multi-core fabric layer on top later.
use crate::dpdk::mbuf::Mbuf;
use crate::net::ethernet::{EthernetHeader, MacAddr};
use crate::net::wire::mut_from_prefix;
use crate::router::nat::{Ingress, Nat, translate_egress, translate_ingress};

/// Apply egress NAT to `m` in place and rewrite its Ethernet addresses for the
/// WAN next hop, leaving it ready to transmit on the WAN port.
///
/// Returns `true` if the packet was translated (TX it on WAN); `false` if it
/// isn't an IPv4 TCP/UDP packet or the NAT pool is exhausted (the caller
/// decides whether to drop or handle it another way).
#[inline]
pub fn egress(m: &mut Mbuf, nat: &mut Nat, wan_mac: MacAddr, gateway_mac: MacAddr) -> bool {
    let data = m.data_mut();
    if translate_egress(data, nat).is_none() {
        return false;
    }
    // L3/L4 are rewritten; now point L2 at the WAN gateway.
    rewrite_ethernet(data, wan_mac, gateway_mac);
    true
}

/// Reverse NAT a WAN→LAN return packet in `m` in place. Returns the internal
/// host endpoint (`dst_ip`, `dst_port`) so the caller can pick the LAN egress
/// port and resolve the host's MAC; `None` if the packet matches no binding.
///
/// L2 is **not** rewritten here: the destination MAC is the internal host's,
/// which requires a neighbor-cache lookup keyed by the returned `dst_ip`. After
/// resolving it, call [`set_ethernet`] before transmitting on the LAN port.
#[inline]
pub fn ingress(m: &mut Mbuf, nat: &Nat) -> Option<Ingress> {
    translate_ingress(m.data_mut(), nat)
}

/// Rewrite the Ethernet source/destination of `m` (e.g. once the LAN next-hop
/// MAC is resolved for an ingress packet).
#[inline]
pub fn set_ethernet(m: &mut Mbuf, src: MacAddr, dst: MacAddr) {
    rewrite_ethernet(m.data_mut(), src, dst);
}

fn rewrite_ethernet(data: &mut [u8], src: MacAddr, dst: MacAddr) {
    if let Some((eth, _)) = mut_from_prefix::<EthernetHeader>(data) {
        eth.src = src;
        eth.dst = dst;
    }
}
