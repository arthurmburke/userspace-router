//! ARP packet for IPv4-over-Ethernet (the common case).

use crate::net::ethernet::{self, BROADCAST, EthernetHeader, MacAddr};
use crate::net::wire::{Pod, U16Be, mut_from_prefix};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Hardware type.
pub mod htype {
    pub const ETHERNET: u16 = 1;
}

/// Protocol type (reuses EtherType values).
pub mod ptype {
    pub const IPV4: u16 = 0x0800;
}

/// Operation code.
pub mod oper {
    pub const REQUEST: u16 = 1;
    pub const REPLY: u16 = 2;
}

/// Hardware address length for Ethernet: a MAC is 6 bytes.
const ETHERNET_HLEN: u8 = 6;
/// Protocol address length for IPv4: an address is 4 bytes.
const IPV4_PLEN: u8 = 4;

/// Target hardware address used in a request: it is unknown (that is what we
/// are asking for), so it is sent as all zeros.
const UNKNOWN_HARDWARE_ADDR: MacAddr = [0; 6];

/// Total length of an Ethernet-framed IPv4 ARP message: L2 header + payload.
pub const FRAME_LEN: usize = EthernetHeader::LEN + ArpPacket::LEN;

/// ARP packet, fixed at 28 bytes for 6-byte MACs and 4-byte IPv4 addresses.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ArpPacket {
    htype: U16Be,
    ptype: U16Be,
    pub hlen: u8,
    pub plen: u8,
    oper: U16Be,
    /// Sender hardware address.
    pub sha: MacAddr,
    /// Sender protocol address.
    spa: [u8; 4],
    /// Target hardware address.
    pub tha: MacAddr,
    /// Target protocol address.
    tpa: [u8; 4],
}

unsafe impl Pod for ArpPacket {}

impl ArpPacket {
    pub const LEN: usize = 28;

    #[inline]
    pub fn htype(&self) -> u16 {
        self.htype.get()
    }
    #[inline]
    pub fn ptype(&self) -> u16 {
        self.ptype.get()
    }
    #[inline]
    pub fn oper(&self) -> u16 {
        self.oper.get()
    }
    #[inline]
    pub fn set_oper(&mut self, v: u16) {
        self.oper.set(v);
    }

    #[inline]
    pub fn is_request(&self) -> bool {
        self.oper() == oper::REQUEST
    }
    #[inline]
    pub fn is_reply(&self) -> bool {
        self.oper() == oper::REPLY
    }

    #[inline]
    pub fn sender_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.spa)
    }
    #[inline]
    pub fn target_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.tpa)
    }
    #[inline]
    pub fn set_sender_ip(&mut self, addr: Ipv4Addr) {
        self.spa = addr.octets();
    }
    #[inline]
    pub fn set_target_ip(&mut self, addr: Ipv4Addr) {
        self.tpa = addr.octets();
    }

    /// Fill in an Ethernet/IPv4 ARP request header (does not set the L2 frame).
    pub fn init_ethernet_ipv4(&mut self, op: u16) {
        self.htype.set(htype::ETHERNET);
        self.ptype.set(ptype::IPV4);
        self.hlen = ETHERNET_HLEN;
        self.plen = IPV4_PLEN;
        self.oper.set(op);
    }

    /// True if this is a well-formed Ethernet/IPv4 ARP packet.
    #[inline]
    pub fn is_ethernet_ipv4(&self) -> bool {
        self.htype() == htype::ETHERNET
            && self.ptype() == ptype::IPV4
            && self.hlen == ETHERNET_HLEN
            && self.plen == IPV4_PLEN
    }
}

/// Build a "who has `target_ip`?" broadcast request into `buf`, returning the
/// number of bytes written ([`FRAME_LEN`]). Fails if `buf` is too small.
///
/// The bytes are written in place, so `buf` can be an mbuf's data region.
pub fn build_request(
    buf: &mut [u8],
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Option<usize> {
    let (eth, rest) = mut_from_prefix::<EthernetHeader>(buf)?;
    eth.dst = BROADCAST;
    eth.src = sender_mac;
    eth.set_ethertype(ethernet::ethertype::ARP);

    let (arp, _) = mut_from_prefix::<ArpPacket>(rest)?;
    arp.init_ethernet_ipv4(oper::REQUEST);
    arp.sha = sender_mac;
    arp.set_sender_ip(sender_ip);
    arp.tha = UNKNOWN_HARDWARE_ADDR;
    arp.set_target_ip(target_ip);

    Some(FRAME_LEN)
}

/// Build a unicast reply ("`sender_ip` is at `sender_mac`") addressed to the
/// requester into `buf`, returning the number of bytes written.
pub fn build_reply(
    buf: &mut [u8],
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Option<usize> {
    let (eth, rest) = mut_from_prefix::<EthernetHeader>(buf)?;
    eth.dst = target_mac;
    eth.src = sender_mac;
    eth.set_ethertype(ethernet::ethertype::ARP);

    let (arp, _) = mut_from_prefix::<ArpPacket>(rest)?;
    arp.init_ethernet_ipv4(oper::REPLY);
    arp.sha = sender_mac;
    arp.set_sender_ip(sender_ip);
    arp.tha = target_mac;
    arp.set_target_ip(target_ip);

    Some(FRAME_LEN)
}

/// IPv4 -> MAC mapping learned from observed ARP traffic.
///
/// This is intentionally a plain map with no expiry; a real stack would age
/// entries out. It exists so the data plane can resolve next-hop MACs without
/// blocking.
#[derive(Debug, Default)]
pub struct NeighborCache {
    entries: HashMap<Ipv4Addr, MacAddr>,
}

impl NeighborCache {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        self.entries.insert(ip, mac);
    }

    #[inline]
    pub fn lookup(&self, ip: &Ipv4Addr) -> Option<MacAddr> {
        self.entries.get(ip).copied()
    }

    #[inline]
    pub fn remove(&mut self, ip: &Ipv4Addr) -> Option<MacAddr> {
        self.entries.remove(ip)
    }

    /// Record the sender's IP -> MAC mapping from any ARP packet (request or
    /// reply); both carry a valid sender hardware/protocol address.
    #[inline]
    pub fn learn_from(&mut self, arp: &ArpPacket) {
        self.insert(arp.sender_ip(), arp.sha);
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// What the caller should do after [`handle`] processes an inbound ARP packet.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// A reply of this many bytes was written to the output buffer; transmit it.
    SendReply(usize),
    /// Nothing to transmit (not for us, was a reply, or malformed).
    Nothing,
}

/// Process one inbound ARP packet for the interface identified by
/// `(our_mac, our_ip)`.
///
/// The sender's mapping is learned into `cache` regardless of opcode. If the
/// packet is a request targeting `our_ip`, a reply is built into `out_buf` and
/// [`Action::SendReply`] is returned.
pub fn handle(
    our_mac: MacAddr,
    our_ip: Ipv4Addr,
    cache: &mut NeighborCache,
    in_arp: &ArpPacket,
    out_buf: &mut [u8],
) -> Action {
    if !in_arp.is_ethernet_ipv4() {
        return Action::Nothing;
    }

    cache.learn_from(in_arp);

    if in_arp.is_request() && in_arp.target_ip() == our_ip {
        match build_reply(out_buf, our_mac, our_ip, in_arp.sha, in_arp.sender_ip()) {
            Some(len) => Action::SendReply(len),
            None => Action::Nothing,
        }
    } else {
        Action::Nothing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wire::ref_from_prefix;

    const OUR_MAC: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const PEER_MAC: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const OUR_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn parse(buf: &[u8]) -> (&EthernetHeader, &ArpPacket) {
        let (eth, rest) = ref_from_prefix::<EthernetHeader>(buf).unwrap();
        let (arp, _) = ref_from_prefix::<ArpPacket>(rest).unwrap();
        (eth, arp)
    }

    #[test]
    fn request_is_broadcast_and_well_formed() {
        let mut buf = [0u8; FRAME_LEN];
        let n = build_request(&mut buf, OUR_MAC, OUR_IP, PEER_IP).unwrap();
        assert_eq!(n, FRAME_LEN);

        let (eth, arp) = parse(&buf);
        assert_eq!(eth.dst, BROADCAST);
        assert_eq!(eth.src, OUR_MAC);
        assert_eq!(eth.ethertype(), ethernet::ethertype::ARP);
        assert!(arp.is_ethernet_ipv4());
        assert!(arp.is_request());
        assert_eq!(arp.sender_ip(), OUR_IP);
        assert_eq!(arp.target_ip(), PEER_IP);
        assert_eq!(arp.tha, UNKNOWN_HARDWARE_ADDR);
    }

    #[test]
    fn handle_replies_to_request_for_us() {
        // Craft an inbound request from the peer asking for our IP.
        let mut in_buf = [0u8; FRAME_LEN];
        build_request(&mut in_buf, PEER_MAC, PEER_IP, OUR_IP).unwrap();
        let (_, in_arp) = parse(&in_buf);

        let mut cache = NeighborCache::new();
        let mut out_buf = [0u8; FRAME_LEN];
        let action = handle(OUR_MAC, OUR_IP, &mut cache, in_arp, &mut out_buf);

        assert_eq!(action, Action::SendReply(FRAME_LEN));
        // We learned the requester's mapping.
        assert_eq!(cache.lookup(&PEER_IP), Some(PEER_MAC));

        let (eth, arp) = parse(&out_buf);
        assert_eq!(eth.dst, PEER_MAC);
        assert_eq!(eth.src, OUR_MAC);
        assert!(arp.is_reply());
        assert_eq!(arp.sender_ip(), OUR_IP);
        assert_eq!(arp.target_ip(), PEER_IP);
        assert_eq!(arp.tha, PEER_MAC);
    }

    #[test]
    fn handle_ignores_request_for_other_host() {
        let other_ip = Ipv4Addr::new(10, 0, 0, 99);
        let mut in_buf = [0u8; FRAME_LEN];
        build_request(&mut in_buf, PEER_MAC, PEER_IP, other_ip).unwrap();
        let (_, in_arp) = parse(&in_buf);

        let mut cache = NeighborCache::new();
        let mut out_buf = [0u8; FRAME_LEN];
        let action = handle(OUR_MAC, OUR_IP, &mut cache, in_arp, &mut out_buf);

        assert_eq!(action, Action::Nothing);
        // Still learned the sender even though we don't reply.
        assert_eq!(cache.lookup(&PEER_IP), Some(PEER_MAC));
    }
}
