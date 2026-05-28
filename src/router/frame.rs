//! Build an Ethernet/IPv4/UDP frame around a payload, with software checksums.
//! Used to construct DHCP datagrams (and any other locally originated UDP).

use crate::net::checksum;
use crate::net::ethernet::{EthernetHeader, MacAddr, ethertype};
use crate::net::ip::{Ipv4Header, proto};
use crate::net::udp::UdpHeader;
use crate::net::wire::mut_from_prefix;
use std::net::Ipv4Addr;

const ETH: usize = EthernetHeader::LEN;
const IP: usize = Ipv4Header::MIN_LEN;
const UDP: usize = UdpHeader::LEN;
/// Offset of the checksum field within the IPv4 header.
const IP_CKSUM_OFFSET: usize = 10;
/// Offset of the checksum field within the UDP header.
const UDP_CKSUM_OFFSET: usize = 6;
/// IPv4 version (4) and IHL in 32-bit words (5 = no options).
const IPV4_VERSION: u8 = 4;
const IPV4_IHL_NO_OPTIONS: u8 = 5;
/// Default TTL for locally originated datagrams.
pub const DEFAULT_TTL: u8 = 64;

/// Addressing for a UDP/IPv4 datagram.
pub struct UdpV4 {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ttl: u8,
}

/// Total frame length for a UDP/IPv4 datagram carrying `payload_len` bytes.
pub const fn frame_len(payload_len: usize) -> usize {
    ETH + IP + UDP + payload_len
}

/// Build the full frame into `buf`; returns the total length, or `None` if
/// `buf` is too small.
pub fn build_udp_ipv4(buf: &mut [u8], p: &UdpV4, payload: &[u8]) -> Option<usize> {
    let total = frame_len(payload.len());
    if buf.len() < total {
        return None;
    }
    // Zero the header span so fields we don't set (identification, flags /
    // fragment offset, DSCP/ECN) are well defined.
    buf[..ETH + IP + UDP].fill(0);

    let udp_len = UDP + payload.len();
    let ip_len = IP + udp_len;

    {
        let (eth, rest) = mut_from_prefix::<EthernetHeader>(buf)?;
        eth.dst = p.dst_mac;
        eth.src = p.src_mac;
        eth.set_ethertype(ethertype::IPV4);

        let (ip, rest) = mut_from_prefix::<Ipv4Header>(rest)?;
        ip.set_version_ihl(IPV4_VERSION, IPV4_IHL_NO_OPTIONS);
        ip.set_total_len(ip_len as u16);
        ip.ttl = p.ttl;
        ip.protocol = proto::UDP;
        ip.set_src(p.src_ip);
        ip.set_dst(p.dst_ip);

        let (udp, _) = mut_from_prefix::<UdpHeader>(rest)?;
        udp.set_src_port(p.src_port);
        udp.set_dst_port(p.dst_port);
        udp.set_length(udp_len as u16);
    }

    let payload_off = ETH + IP + UDP;
    buf[payload_off..payload_off + payload.len()].copy_from_slice(payload);

    // Checksums (header checksum fields are currently zero).
    let ip_cksum = checksum::ipv4_header(&buf[ETH..ETH + IP]);
    buf[ETH + IP_CKSUM_OFFSET..ETH + IP_CKSUM_OFFSET + 2].copy_from_slice(&ip_cksum.to_be_bytes());

    let udp_off = ETH + IP;
    let udp_cksum = checksum::udp_ipv4(
        p.src_ip.octets(),
        p.dst_ip.octets(),
        &buf[udp_off..udp_off + udp_len],
    );
    buf[udp_off + UDP_CKSUM_OFFSET..udp_off + UDP_CKSUM_OFFSET + 2]
        .copy_from_slice(&udp_cksum.to_be_bytes());

    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::view;

    #[test]
    fn builds_parseable_checksummed_datagram() {
        let mut buf = [0u8; 128];
        let p = UdpV4 {
            src_mac: [0x02, 0, 0, 0, 0, 1],
            dst_mac: [0x02, 0, 0, 0, 0, 2],
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 1234,
            dst_port: 53,
            ttl: DEFAULT_TTL,
        };
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let n = build_udp_ipv4(&mut buf, &p, &payload).unwrap();
        assert_eq!(n, frame_len(payload.len()));

        // IPv4 + UDP checksums verify to zero.
        assert_eq!(checksum::checksum(&buf[ETH..ETH + IP]), 0);

        // And it parses back through the view layer.
        let udp = view::parse(&buf[..n])
            .unwrap()
            .ipv4()
            .unwrap()
            .udp()
            .unwrap();
        assert_eq!(udp.dst_port(), 53);
        assert_eq!(udp.payload(), &payload);
    }
}
