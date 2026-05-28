//! ARP responder for the router's own addresses.
//!
//! A router does not *forward* ARP — ARP is link-local, scoped to one segment.
//! What it does is answer requests for the IPs it owns on a given interface
//! (its gateway IP, the DHCP server IP, etc.). Listing extra addresses in
//! `owned` also gives you proxy-ARP: the router answers on their behalf.

use crate::net::arp;
use crate::net::ethernet::MacAddr;
use crate::net::view::EthernetView;
use std::net::Ipv4Addr;

/// If `frame` is an ARP request for one of `owned`, build the reply (from
/// `our_mac`) into `out` and return its length. Otherwise `None`.
pub fn respond(
    our_mac: MacAddr,
    owned: &[Ipv4Addr],
    frame: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let pkt = EthernetView::parse(frame)?.arp()?;
    if !pkt.is_request() {
        return None;
    }
    let target = pkt.target_ip();
    if !owned.contains(&target) {
        return None;
    }
    // We are `target`; reply to the requester (its MAC + IP from the request).
    arp::build_reply(out, our_mac, target, pkt.sha, pkt.sender_ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::arp as narp;
    use crate::net::view;

    #[test]
    fn replies_only_for_owned_ips() {
        let our_mac = [0x02, 0, 0, 0, 0, 1];
        let our_ip = Ipv4Addr::new(192, 168, 1, 1);
        let peer_mac = [0x02, 0, 0, 0, 0, 2];
        let peer_ip = Ipv4Addr::new(192, 168, 1, 50);

        let mut req = [0u8; narp::FRAME_LEN];
        narp::build_request(&mut req, peer_mac, peer_ip, our_ip).unwrap();

        let mut out = [0u8; narp::FRAME_LEN];
        let n = respond(our_mac, &[our_ip], &req, &mut out).expect("reply for owned ip");
        assert_eq!(n, narp::FRAME_LEN);

        let reply = view::parse(&out[..n]).unwrap().arp().unwrap();
        assert!(reply.is_reply());
        assert_eq!(reply.sender_ip(), our_ip);
        assert_eq!(reply.sha, our_mac);
        assert_eq!(reply.target_ip(), peer_ip);

        // A request for an address we don't own is ignored.
        let other = Ipv4Addr::new(192, 168, 1, 99);
        let mut req2 = [0u8; narp::FRAME_LEN];
        narp::build_request(&mut req2, peer_mac, peer_ip, other).unwrap();
        assert!(respond(our_mac, &[our_ip], &req2, &mut out).is_none());
    }
}
