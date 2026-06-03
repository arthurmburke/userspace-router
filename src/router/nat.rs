//! Source NAT (the egress half): rewrite LAN→WAN packets so they appear to
//! originate from the router's WAN address, and remember the mapping so return
//! traffic can be reversed.
//!
//! This is **endpoint-independent** ("full-cone") mapping: a given internal
//! `(protocol, ip, port)` always maps to the same external port regardless of
//! the remote peer, so the reverse lookup needs only `(protocol, ext_port)`.
//! The external port is drawn from a configurable range — in the multi-core
//! design that range encodes the owning core, which is how WAN return traffic
//! is demuxed back to the right shard without RSS.
//!
//! [`translate_egress`] works on a raw packet slice (an mbuf's `data_mut`), so
//! it's pure and unit-tested here; [`crate::router::worker`] is the DPDK glue.

use crate::core::spinlock::SpinLock;
use crate::net::checksum;
use crate::net::ip::proto;
use crate::net::view;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// Source-address field offset within the IPv4 header.
const IP_SRC_OFFSET: usize = 12;
/// Destination-address field offset within the IPv4 header.
const IP_DST_OFFSET: usize = 16;
/// Checksum field offset within the IPv4 header.
const IP_CKSUM_OFFSET: usize = 10;
/// Source-port field offset within a TCP/UDP header (both put it first).
const L4_SRC_PORT_OFFSET: usize = 0;
/// Destination-port field offset within a TCP/UDP header.
const L4_DST_PORT_OFFSET: usize = 2;
/// Checksum field offset within the TCP header.
const TCP_CKSUM_OFFSET: usize = 16;
/// Checksum field offset within the UDP header.
const UDP_CKSUM_OFFSET: usize = 6;
/// UDP checksum value meaning "not computed".
const UDP_CKSUM_DISABLED: u16 = 0;

/// The transport protocols we NAT.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum L4 {
    Tcp,
    Udp,
}

impl L4 {
    pub fn proto(self) -> u8 {
        match self {
            L4::Tcp => proto::TCP,
            L4::Udp => proto::UDP,
        }
    }
    pub fn from_proto(p: u8) -> Option<Self> {
        match p {
            proto::TCP => Some(L4::Tcp),
            proto::UDP => Some(L4::Udp),
            _ => None,
        }
    }
}

/// An internal (behind-NAT) transport endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Endpoint {
    ip: Ipv4Addr,
    port: u16,
}

/// The source rewrite to apply to an egress packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Egress {
    pub new_src_ip: Ipv4Addr,
    pub new_src_port: u16,
}

/// The destination rewrite applied to an ingress (return) packet — the internal
/// endpoint the flow belongs to. The caller uses this to choose the LAN egress
/// port and resolve the host's next-hop MAC.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ingress {
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

/// A per-shard NAT table: forward and reverse maps plus the external-port pool.
pub struct Nat {
    wan_ip: Ipv4Addr,
    port_lo: u16,
    port_hi: u16,
    next_port: u16,
    /// `(proto, internal ip, internal port)` -> external port.
    fwd: HashMap<(u8, Ipv4Addr, u16), u16>,
    /// `(proto, external port)` -> internal endpoint (for reverse/ingress).
    rev: HashMap<(u8, u16), Endpoint>,
}

impl Nat {
    /// Create a table translating to `wan_ip`, allocating external ports from
    /// the inclusive range `[port_lo, port_hi]`.
    pub fn new(wan_ip: Ipv4Addr, port_lo: u16, port_hi: u16) -> Self {
        assert!(port_lo > 0 && port_lo <= port_hi, "invalid NAT port range");
        Self {
            wan_ip,
            port_lo,
            port_hi,
            next_port: port_lo,
            fwd: HashMap::new(),
            rev: HashMap::new(),
        }
    }

    /// Update the WAN address (e.g. when the DHCP lease changes). Existing
    /// mappings keep their ports; only the address they translate to changes.
    pub fn set_wan_ip(&mut self, ip: Ipv4Addr) {
        self.wan_ip = ip;
    }
    pub fn wan_ip(&self) -> Ipv4Addr {
        self.wan_ip
    }
    /// Number of active bindings.
    pub fn active(&self) -> usize {
        self.fwd.len()
    }

    /// Map an outbound flow's source endpoint to the WAN address + an external
    /// port, creating the binding on first sight. `None` if the pool is full.
    pub fn egress(&mut self, l4: L4, src_ip: Ipv4Addr, src_port: u16) -> Option<Egress> {
        let proto = l4.proto();
        let key = (proto, src_ip, src_port);
        let ext = match self.fwd.get(&key) {
            Some(&e) => e,
            None => {
                let e = self.alloc_port(proto)?;
                self.fwd.insert(key, e);
                self.rev.insert(
                    (proto, e),
                    Endpoint {
                        ip: src_ip,
                        port: src_port,
                    },
                );
                e
            }
        };
        Some(Egress {
            new_src_ip: self.wan_ip,
            new_src_port: ext,
        })
    }

    /// Reverse a return packet's destination (the external port) back to the
    /// internal endpoint, if a binding exists.
    pub fn ingress(&self, l4: L4, ext_port: u16) -> Option<(Ipv4Addr, u16)> {
        self.rev
            .get(&(l4.proto(), ext_port))
            .map(|e| (e.ip, e.port))
    }

    /// Find a free external port for `proto`, scanning circularly from the last
    /// handout. Ports are namespaced per protocol (TCP 40000 ≠ UDP 40000).
    fn alloc_port(&mut self, proto: u8) -> Option<u16> {
        let span = (self.port_hi - self.port_lo) as u32 + 1;
        let mut cand = self.next_port;
        for _ in 0..span {
            let port = cand;
            cand = if port >= self.port_hi {
                self.port_lo
            } else {
                port + 1
            };
            if !self.rev.contains_key(&(proto, port)) {
                self.next_port = cand;
                return Some(port);
            }
        }
        None
    }
}

/// Apply source NAT to an egress IPv4 TCP/UDP packet in `frame`, in place.
///
/// Returns the rewrite that was applied, or `None` if the packet isn't IPv4
/// TCP/UDP (e.g. ARP, ICMP, a non-initial fragment) or the pool is exhausted.
/// IP and L4 checksums are fixed up incrementally (RFC 1624) rather than
/// recomputed.
pub fn translate_egress(frame: &mut [u8], nat: &mut Nat) -> Option<Egress> {
    // Phase 1 — classify with immutable views, capturing offsets + fields.
    // (Offsets are `usize`, so the views' borrows end before we mutate.)
    let (ip_off, l4_off, l4, src_ip, src_port) = {
        let ip = view::parse(frame)?.ipv4()?;
        let l4 = L4::from_proto(ip.protocol())?;
        let (l4_off, src_port) = match l4 {
            L4::Tcp => {
                let t = ip.tcp()?;
                (t.header_offset(), t.src_port())
            }
            L4::Udp => {
                let u = ip.udp()?;
                (u.header_offset(), u.src_port())
            }
        };
        (ip.header_offset(), l4_off, l4, ip.header().src(), src_port)
    };

    // Phase 2 — NAT decision.
    let xlate = nat.egress(l4, src_ip, src_port)?;
    let old_ip = src_ip.octets();
    let new_ip = xlate.new_src_ip.octets();
    let old_port = src_port.to_be_bytes();
    let new_port = xlate.new_src_port.to_be_bytes();

    // Phase 3 — rewrite the source IP + port and fix checksums in place.
    let (l4c_off, is_udp) = l4_checksum_field(l4, l4_off);
    apply_rewrite(
        frame,
        ip_off + IP_SRC_OFFSET,
        ip_off + IP_CKSUM_OFFSET,
        l4_off + L4_SRC_PORT_OFFSET,
        l4c_off,
        is_udp,
        old_ip,
        new_ip,
        old_port,
        new_port,
    );

    Some(xlate)
}

/// Reverse source NAT for an inbound IPv4 TCP/UDP packet addressed to the WAN
/// address: rewrite the *destination* back to the internal endpoint that owns
/// the external (destination) port, fixing checksums in place.
///
/// Returns the internal endpoint (so the caller can pick the LAN egress port
/// and next-hop MAC), or `None` if no binding matches (drop it). Takes `&Nat` —
/// ingress never creates state.
pub fn translate_ingress(frame: &mut [u8], nat: &Nat) -> Option<Ingress> {
    // Phase 1 — classify, capturing the destination (= our external) endpoint.
    let (ip_off, l4_off, l4, dst_ip, dst_port) = {
        let ip = view::parse(frame)?.ipv4()?;
        let l4 = L4::from_proto(ip.protocol())?;
        let (l4_off, dst_port) = match l4 {
            L4::Tcp => {
                let t = ip.tcp()?;
                (t.header_offset(), t.dst_port())
            }
            L4::Udp => {
                let u = ip.udp()?;
                (u.header_offset(), u.dst_port())
            }
        };
        (ip.header_offset(), l4_off, l4, ip.header().dst(), dst_port)
    };

    // Phase 2 — reverse lookup by external port.
    let (new_ip, new_port) = nat.ingress(l4, dst_port)?;
    let old_ip = dst_ip.octets();
    let new_ip_b = new_ip.octets();
    let old_port = dst_port.to_be_bytes();
    let new_port_b = new_port.to_be_bytes();

    // Phase 3 — rewrite the destination IP + port and fix checksums in place.
    let (l4c_off, is_udp) = l4_checksum_field(l4, l4_off);
    apply_rewrite(
        frame,
        ip_off + IP_DST_OFFSET,
        ip_off + IP_CKSUM_OFFSET,
        l4_off + L4_DST_PORT_OFFSET,
        l4c_off,
        is_udp,
        old_ip,
        new_ip_b,
        old_port,
        new_port_b,
    );

    Some(Ingress {
        dst_ip: new_ip,
        dst_port: new_port,
    })
}

/// Checksum field offset + whether this is UDP (for the zero-checksum rules).
fn l4_checksum_field(l4: L4, l4_off: usize) -> (usize, bool) {
    match l4 {
        L4::Tcp => (l4_off + TCP_CKSUM_OFFSET, false),
        L4::Udp => (l4_off + UDP_CKSUM_OFFSET, true),
    }
}

/// Overwrite one IPv4 address field and one L4 port (both absolute offsets into
/// `frame`), then fix the IP header checksum (`ipc_off`) and the L4 checksum
/// (`l4c_off`) incrementally. Egress passes the source offsets, ingress the
/// destination offsets — the checksum maths is identical either way.
#[allow(clippy::too_many_arguments)]
fn apply_rewrite(
    frame: &mut [u8],
    ip_field: usize,
    ipc_off: usize,
    l4_port: usize,
    l4c_off: usize,
    is_udp: bool,
    old_ip: [u8; 4],
    new_ip: [u8; 4],
    old_port: [u8; 2],
    new_port: [u8; 2],
) {
    // IP address field + IP header checksum.
    frame[ip_field..ip_field + 4].copy_from_slice(&new_ip);
    let ipc = u16::from_be_bytes([frame[ipc_off], frame[ipc_off + 1]]);
    let ipc = checksum::update(ipc, &old_ip, &new_ip);
    frame[ipc_off..ipc_off + 2].copy_from_slice(&ipc.to_be_bytes());

    // L4 port.
    frame[l4_port..l4_port + 2].copy_from_slice(&new_port);

    // L4 checksum (covers the IP pseudo-header + the port). A zero UDP checksum
    // means "disabled" — leave it; a computed zero is stored as 0xFFFF.
    let l4c = u16::from_be_bytes([frame[l4c_off], frame[l4c_off + 1]]);
    if !(is_udp && l4c == UDP_CKSUM_DISABLED) {
        let mut updated = checksum::update(l4c, &old_ip, &new_ip);
        updated = checksum::update(updated, &old_port, &new_port);
        if is_udp && updated == UDP_CKSUM_DISABLED {
            updated = 0xffff;
        }
        frame[l4c_off..l4c_off + 2].copy_from_slice(&updated.to_be_bytes());
    }
}

/// Cloneable handle to a [`Nat`] shared across workers. Cloning bumps the
/// `Arc` refcount; every clone observes the same forward/reverse tables and
/// external-port pool.
///
/// Locking: every operation takes the spinlock briefly. NAT translation is
/// short (a hash lookup + a few arithmetic ops), so contention stays low even
/// at line rate.
#[derive(Clone)]
pub struct SharedNat {
    inner: Arc<SpinLock<Nat>>,
}

impl SharedNat {
    pub fn new(nat: Nat) -> Self {
        Self {
            inner: Arc::new(SpinLock::new(nat)),
        }
    }

    /// Update the WAN address (e.g. when the DHCP lease binds or changes).
    pub fn set_wan_ip(&self, ip: Ipv4Addr) {
        self.inner.with(|n| n.set_wan_ip(ip));
    }

    pub fn wan_ip(&self) -> Ipv4Addr {
        self.inner.with(|n| n.wan_ip())
    }

    /// Apply egress NAT to `frame` in place under the lock. See
    /// [`translate_egress`].
    pub fn translate_egress(&self, frame: &mut [u8]) -> Option<Egress> {
        self.inner.with(|n| translate_egress(frame, n))
    }

    /// Apply ingress NAT to `frame` in place under the lock. See
    /// [`translate_ingress`].
    pub fn translate_ingress(&self, frame: &mut [u8]) -> Option<Ingress> {
        self.inner.with(|n| translate_ingress(frame, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::ethernet::{EthernetHeader, ethertype};
    use crate::net::ip::Ipv4Header;
    use crate::net::tcp::TcpHeader;
    use crate::net::wire::mut_from_prefix;
    use crate::router::frame::{UdpV4, build_udp_ipv4};

    const WAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);

    /// One's-complement check of an L4 segment incl. pseudo-header; 0 == valid.
    fn l4_check(src: [u8; 4], dst: [u8; 4], proto: u8, seg: &[u8]) -> u16 {
        let mut acc = 0u32;
        acc = checksum::accumulate(acc, &src);
        acc = checksum::accumulate(acc, &dst);
        acc = acc.wrapping_add(proto as u32);
        acc = acc.wrapping_add(seg.len() as u32);
        acc = checksum::accumulate(acc, seg);
        checksum::finish(acc)
    }

    fn build_tcp(buf: &mut [u8], src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16) -> usize {
        const ETH: usize = 14;
        const IP: usize = 20;
        const TCP: usize = 20;
        let total = ETH + IP + TCP;
        buf[..total].fill(0);
        {
            let (e, rest) = mut_from_prefix::<EthernetHeader>(buf).unwrap();
            e.set_ethertype(ethertype::IPV4);
            let (i, rest) = mut_from_prefix::<Ipv4Header>(rest).unwrap();
            i.set_version_ihl(4, 5);
            i.set_total_len((IP + TCP) as u16);
            i.ttl = 64;
            i.protocol = proto::TCP;
            i.set_src(src);
            i.set_dst(dst);
            let (t, _) = mut_from_prefix::<TcpHeader>(rest).unwrap();
            t.set_src_port(sp);
            t.set_dst_port(dp);
            t.set_data_offset(5);
        }
        let ipc = checksum::ipv4_header(&buf[ETH..ETH + IP]);
        buf[ETH + 10..ETH + 12].copy_from_slice(&ipc.to_be_bytes());
        let c = l4_check(
            src.octets(),
            dst.octets(),
            proto::TCP,
            &buf[ETH + IP..ETH + IP + TCP],
        );
        buf[ETH + IP + 16..ETH + IP + 18].copy_from_slice(&c.to_be_bytes());
        total
    }

    #[test]
    fn mapping_is_stable_unique_and_reversible() {
        let mut nat = Nat::new(WAN_IP, 40000, 40002);
        let host_a = Ipv4Addr::new(192, 168, 1, 2);
        let host_b = Ipv4Addr::new(192, 168, 1, 3);

        let a = nat.egress(L4::Tcp, host_a, 1111).unwrap();
        let a2 = nat.egress(L4::Tcp, host_a, 1111).unwrap();
        assert_eq!(a, a2, "same endpoint -> same mapping");
        assert_eq!(a.new_src_ip, WAN_IP);

        let b = nat.egress(L4::Tcp, host_b, 1111).unwrap();
        assert_ne!(a.new_src_port, b.new_src_port, "distinct endpoints differ");

        assert_eq!(nat.ingress(L4::Tcp, a.new_src_port), Some((host_a, 1111)));

        // TCP pool has 3 ports; a + b used 2, one more, then exhausted.
        let _c = nat
            .egress(L4::Tcp, Ipv4Addr::new(192, 168, 1, 4), 1)
            .unwrap();
        assert!(
            nat.egress(L4::Tcp, Ipv4Addr::new(192, 168, 1, 5), 1)
                .is_none()
        );
        // UDP is a separate namespace, so it still has ports.
        assert!(
            nat.egress(L4::Udp, Ipv4Addr::new(192, 168, 1, 6), 1)
                .is_some()
        );
    }

    #[test]
    fn translate_egress_udp_rewrites_and_checksums() {
        let mut nat = Nat::new(WAN_IP, 40000, 40010);
        let p = UdpV4 {
            src_mac: [2, 0, 0, 0, 0, 1],
            dst_mac: [2, 0, 0, 0, 0, 2],
            src_ip: Ipv4Addr::new(192, 168, 1, 50),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            src_port: 5000,
            dst_port: 53,
            ttl: 64,
        };
        let mut buf = [0u8; 128];
        let n = build_udp_ipv4(&mut buf, &p, &[9, 9]).unwrap();

        let e = translate_egress(&mut buf[..n], &mut nat).unwrap();
        assert_eq!(e.new_src_ip, WAN_IP);

        // Checksums still verify after the rewrite.
        assert_eq!(checksum::checksum(&buf[14..34]), 0);
        let udp_len = 8 + 2;
        assert_eq!(
            l4_check(
                WAN_IP.octets(),
                [8, 8, 8, 8],
                proto::UDP,
                &buf[34..34 + udp_len]
            ),
            0
        );

        // Source rewritten, destination untouched.
        let ip = view::parse(&buf[..n]).unwrap().ipv4().unwrap();
        assert_eq!(ip.header().src(), WAN_IP);
        let udp = ip.udp().unwrap();
        assert_eq!(udp.src_port(), e.new_src_port);
        assert_eq!(udp.dst_port(), 53);
    }

    #[test]
    fn translate_egress_tcp_rewrites_and_checksums() {
        let mut nat = Nat::new(WAN_IP, 40000, 40010);
        let mut buf = [0u8; 128];
        let n = build_tcp(
            &mut buf,
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(8, 8, 8, 8),
            1234,
            80,
        );

        let e = translate_egress(&mut buf[..n], &mut nat).unwrap();

        assert_eq!(checksum::checksum(&buf[14..34]), 0);
        assert_eq!(
            l4_check(WAN_IP.octets(), [8, 8, 8, 8], proto::TCP, &buf[34..34 + 20]),
            0
        );

        let ip = view::parse(&buf[..n]).unwrap().ipv4().unwrap();
        assert_eq!(ip.header().src(), WAN_IP);
        let tcp = ip.tcp().unwrap();
        assert_eq!(tcp.src_port(), e.new_src_port);
        assert_eq!(tcp.dst_port(), 80);
    }

    #[test]
    fn egress_then_ingress_round_trips_udp() {
        let mut nat = Nat::new(WAN_IP, 40000, 40010);
        let host = Ipv4Addr::new(192, 168, 1, 50);
        let remote = Ipv4Addr::new(8, 8, 8, 8);

        // Outbound: learn the binding (host:5000 -> WAN:ext).
        let ext = nat.egress(L4::Udp, host, 5000).unwrap().new_src_port;

        // Craft the return datagram: remote:53 -> WAN:ext.
        let p = UdpV4 {
            src_mac: [2, 0, 0, 0, 0, 2],
            dst_mac: [2, 0, 0, 0, 0, 1],
            src_ip: remote,
            dst_ip: WAN_IP,
            src_port: 53,
            dst_port: ext,
            ttl: 64,
        };
        let mut buf = [0u8; 128];
        let n = build_udp_ipv4(&mut buf, &p, &[7, 7, 7]).unwrap();

        let r = translate_ingress(&mut buf[..n], &nat).unwrap();
        assert_eq!(r.dst_ip, host);
        assert_eq!(r.dst_port, 5000);

        // Checksums verify and the destination is now the internal host.
        assert_eq!(checksum::checksum(&buf[14..34]), 0);
        let udp_len = 8 + 3;
        assert_eq!(
            l4_check(
                remote.octets(),
                host.octets(),
                proto::UDP,
                &buf[34..34 + udp_len]
            ),
            0
        );
        let ip = view::parse(&buf[..n]).unwrap().ipv4().unwrap();
        assert_eq!(ip.header().dst(), host);
        assert_eq!(ip.udp().unwrap().dst_port(), 5000);
    }

    #[test]
    fn ingress_without_binding_is_dropped() {
        let nat = Nat::new(WAN_IP, 40000, 40010);
        let p = UdpV4 {
            src_mac: [2, 0, 0, 0, 0, 2],
            dst_mac: [2, 0, 0, 0, 0, 1],
            src_ip: Ipv4Addr::new(8, 8, 8, 8),
            dst_ip: WAN_IP,
            src_port: 53,
            dst_port: 40005, // no binding ever created for this port
            ttl: 64,
        };
        let mut buf = [0u8; 128];
        let n = build_udp_ipv4(&mut buf, &p, &[0]).unwrap();
        assert!(translate_ingress(&mut buf[..n], &nat).is_none());
    }

    #[test]
    fn non_tcp_udp_is_ignored() {
        let mut nat = Nat::new(WAN_IP, 40000, 40010);
        // An ARP frame: ethertype 0x0806, no IPv4 layer.
        let mut buf = [0u8; 60];
        buf[12..14].copy_from_slice(&ethertype::ARP.to_be_bytes());
        assert!(translate_egress(&mut buf, &mut nat).is_none());
    }
}
