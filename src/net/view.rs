//! Layered, zero-copy interpretation of a packet buffer.
//!
//! Begin with a byte slice — typically `mbuf.data()` — and walk down the
//! protocol stack one layer at a time:
//!
//! ```text
//! Ethernet ─┬─ IPv4 ─┬─ TCP ── DNS
//!           │        └─ UDP ─┬─ DHCP
//!           │                └─ DNS
//!           └─ ARP
//! ```
//!
//! Each step is a bounds check plus a pointer cast — nothing is copied. A
//! `*View` borrows the original buffer for `'a`, so the references and payload
//! slices it hands back point straight into that buffer (e.g. the mbuf data
//! region). Every view also reports the absolute byte offset of its header via
//! `header_offset()`, which you can feed to [`crate::dpdk::mbuf::Mbuf::header_at_mut`]
//! to edit that layer in place.

use crate::net::arp::ArpPacket;
use crate::net::dhcp::{self, DhcpHeader};
use crate::net::dns::DnsHeader;
use crate::net::ethernet::{self, EthernetHeader, VlanTag};
use crate::net::ip::{self, Ipv4Header};
use crate::net::tcp::TcpHeader;
use crate::net::udp::UdpHeader;
use crate::net::wire::{Pod, ref_from};

/// Well-known transport ports used to classify the application layer.
pub mod port {
    /// DNS, over both UDP and TCP.
    pub const DNS: u16 = 53;
    /// DHCP / BOOTP server port.
    pub const DHCP_SERVER: u16 = 67;
    /// DHCP / BOOTP client port.
    pub const DHCP_CLIENT: u16 = 68;
}

/// Cast the bytes of `buf` starting at `off` to `&T`, if they fit.
#[inline]
fn header_at<T: Pod>(buf: &[u8], off: usize) -> Option<&T> {
    buf.get(off..).and_then(ref_from::<T>)
}

/// Entry point: interpret `buf` as an Ethernet frame.
#[inline]
pub fn parse(buf: &[u8]) -> Option<EthernetView<'_>> {
    EthernetView::parse(buf)
}

/// A view of an Ethernet II frame, with any single 802.1Q VLAN tag resolved.
#[derive(Clone, Copy)]
pub struct EthernetView<'a> {
    buf: &'a [u8],
    start: usize,
    /// Ethertype after stripping a VLAN tag (the inner type if tagged).
    ethertype: u16,
    /// Offset where the L3 payload begins (past the header and any VLAN tag).
    l3_start: usize,
}

impl<'a> EthernetView<'a> {
    #[inline]
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        Self::parse_at(buf, 0)
    }

    fn parse_at(buf: &'a [u8], start: usize) -> Option<Self> {
        let eth: &EthernetHeader = header_at(buf, start)?;
        let mut ethertype = eth.ethertype();
        let mut l3_start = start + EthernetHeader::LEN;

        if ethertype == ethernet::ethertype::VLAN {
            let tag: &VlanTag = header_at(buf, l3_start)?;
            ethertype = tag.inner_ethertype();
            l3_start += VlanTag::LEN;
        }
        if l3_start > buf.len() {
            return None;
        }
        Some(Self {
            buf,
            start,
            ethertype,
            l3_start,
        })
    }

    #[inline]
    pub fn header(&self) -> &'a EthernetHeader {
        header_at(self.buf, self.start).expect("validated during parse")
    }
    #[inline]
    pub fn header_offset(&self) -> usize {
        self.start
    }
    /// Ethertype of the payload (inner type if the frame was VLAN-tagged).
    #[inline]
    pub fn ethertype(&self) -> u16 {
        self.ethertype
    }
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.l3_start..]
    }
    #[inline]
    pub fn payload_offset(&self) -> usize {
        self.l3_start
    }

    #[inline]
    pub fn is_ipv4(&self) -> bool {
        self.ethertype == ethernet::ethertype::IPV4
    }
    #[inline]
    pub fn is_arp(&self) -> bool {
        self.ethertype == ethernet::ethertype::ARP
    }

    /// Descend into IPv4 if this frame carries it.
    #[inline]
    pub fn ipv4(&self) -> Option<Ipv4View<'a>> {
        if self.is_ipv4() {
            Ipv4View::parse_at(self.buf, self.l3_start)
        } else {
            None
        }
    }
    /// Interpret the payload as an ARP packet if this frame carries one.
    #[inline]
    pub fn arp(&self) -> Option<&'a ArpPacket> {
        if self.is_arp() {
            header_at(self.buf, self.l3_start)
        } else {
            None
        }
    }
}

/// A view of an IPv4 packet. `end` bounds the L4 region using the IP total
/// length, trimming any Ethernet padding.
#[derive(Clone, Copy)]
pub struct Ipv4View<'a> {
    buf: &'a [u8],
    start: usize,
    l4_start: usize,
    end: usize,
}

impl<'a> Ipv4View<'a> {
    fn parse_at(buf: &'a [u8], start: usize) -> Option<Self> {
        let ip: &Ipv4Header = header_at(buf, start)?;
        let hlen = ip.header_len();
        if hlen < Ipv4Header::MIN_LEN {
            return None;
        }
        let l4_start = start.checked_add(hlen)?;
        if l4_start > buf.len() {
            return None;
        }
        // Prefer the length declared in the header; fall back to the buffer end
        // if it is absent or implausible.
        let total = ip.total_len() as usize;
        let end = match start.checked_add(total) {
            Some(e) if total >= hlen && e <= buf.len() => e,
            _ => buf.len(),
        };
        Some(Self {
            buf,
            start,
            l4_start,
            end: end.max(l4_start),
        })
    }

    #[inline]
    pub fn header(&self) -> &'a Ipv4Header {
        header_at(self.buf, self.start).expect("validated during parse")
    }
    #[inline]
    pub fn header_offset(&self) -> usize {
        self.start
    }
    #[inline]
    pub fn protocol(&self) -> u8 {
        self.header().protocol
    }
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.l4_start..self.end]
    }
    #[inline]
    pub fn payload_offset(&self) -> usize {
        self.l4_start
    }

    #[inline]
    pub fn is_tcp(&self) -> bool {
        self.protocol() == ip::proto::TCP
    }
    #[inline]
    pub fn is_udp(&self) -> bool {
        self.protocol() == ip::proto::UDP
    }

    #[inline]
    pub fn tcp(&self) -> Option<TcpView<'a>> {
        if self.is_tcp() {
            TcpView::parse_at(self.buf, self.l4_start, self.end)
        } else {
            None
        }
    }
    #[inline]
    pub fn udp(&self) -> Option<UdpView<'a>> {
        if self.is_udp() {
            UdpView::parse_at(self.buf, self.l4_start, self.end)
        } else {
            None
        }
    }
}

/// A view of a TCP segment.
#[derive(Clone, Copy)]
pub struct TcpView<'a> {
    buf: &'a [u8],
    start: usize,
    payload_start: usize,
    end: usize,
}

impl<'a> TcpView<'a> {
    fn parse_at(buf: &'a [u8], start: usize, end: usize) -> Option<Self> {
        let tcp: &TcpHeader = header_at(buf, start)?;
        let hlen = tcp.header_len();
        if hlen < TcpHeader::MIN_LEN {
            return None;
        }
        let payload_start = start.checked_add(hlen)?;
        if payload_start > end || payload_start > buf.len() {
            return None;
        }
        Some(Self {
            buf,
            start,
            payload_start,
            end,
        })
    }

    #[inline]
    pub fn header(&self) -> &'a TcpHeader {
        header_at(self.buf, self.start).expect("validated during parse")
    }
    #[inline]
    pub fn header_offset(&self) -> usize {
        self.start
    }
    #[inline]
    pub fn src_port(&self) -> u16 {
        self.header().src_port()
    }
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.header().dst_port()
    }
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.payload_start..self.end]
    }
    #[inline]
    pub fn payload_offset(&self) -> usize {
        self.payload_start
    }

    /// True if either endpoint is the DNS port (DNS-over-TCP).
    #[inline]
    pub fn is_dns(&self) -> bool {
        self.src_port() == port::DNS || self.dst_port() == port::DNS
    }
    #[inline]
    pub fn dns(&self) -> Option<DnsView<'a>> {
        if self.is_dns() {
            DnsView::parse_at(self.buf, self.payload_start, self.end)
        } else {
            None
        }
    }
}

/// A view of a UDP datagram. `end` is clamped by the UDP length field.
#[derive(Clone, Copy)]
pub struct UdpView<'a> {
    buf: &'a [u8],
    start: usize,
    payload_start: usize,
    end: usize,
}

impl<'a> UdpView<'a> {
    fn parse_at(buf: &'a [u8], start: usize, end: usize) -> Option<Self> {
        let udp: &UdpHeader = header_at(buf, start)?;
        let payload_start = start.checked_add(UdpHeader::LEN)?;
        if payload_start > end || payload_start > buf.len() {
            return None;
        }
        // Trust the UDP length when it is sane, else fall back to the IP-derived
        // end already passed in.
        let declared = udp.length() as usize;
        let end = match start.checked_add(declared) {
            Some(e) if declared >= UdpHeader::LEN && e <= end => e,
            _ => end,
        };
        Some(Self {
            buf,
            start,
            payload_start,
            end: end.max(payload_start),
        })
    }

    #[inline]
    pub fn header(&self) -> &'a UdpHeader {
        header_at(self.buf, self.start).expect("validated during parse")
    }
    #[inline]
    pub fn header_offset(&self) -> usize {
        self.start
    }
    #[inline]
    pub fn src_port(&self) -> u16 {
        self.header().src_port()
    }
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.header().dst_port()
    }
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.payload_start..self.end]
    }
    #[inline]
    pub fn payload_offset(&self) -> usize {
        self.payload_start
    }

    /// True if either endpoint is a DHCP/BOOTP port.
    #[inline]
    pub fn is_dhcp(&self) -> bool {
        let is_bootp = |p: u16| p == port::DHCP_SERVER || p == port::DHCP_CLIENT;
        is_bootp(self.src_port()) || is_bootp(self.dst_port())
    }
    /// True if either endpoint is the DNS port.
    #[inline]
    pub fn is_dns(&self) -> bool {
        self.src_port() == port::DNS || self.dst_port() == port::DNS
    }

    #[inline]
    pub fn dhcp(&self) -> Option<DhcpView<'a>> {
        if self.is_dhcp() {
            DhcpView::parse_at(self.buf, self.payload_start, self.end)
        } else {
            None
        }
    }
    #[inline]
    pub fn dns(&self) -> Option<DnsView<'a>> {
        if self.is_dns() {
            DnsView::parse_at(self.buf, self.payload_start, self.end)
        } else {
            None
        }
    }
}

/// A view of a DHCPv4 message: the fixed header plus its options region.
#[derive(Clone, Copy)]
pub struct DhcpView<'a> {
    buf: &'a [u8],
    start: usize,
    options_start: usize,
    end: usize,
}

impl<'a> DhcpView<'a> {
    fn parse_at(buf: &'a [u8], start: usize, end: usize) -> Option<Self> {
        let _: &DhcpHeader = header_at(buf, start)?;
        let options_start = start.checked_add(DhcpHeader::LEN)?;
        Some(Self {
            buf,
            start,
            options_start: options_start.min(end),
            end,
        })
    }

    #[inline]
    pub fn header(&self) -> &'a DhcpHeader {
        header_at(self.buf, self.start).expect("validated during parse")
    }
    #[inline]
    pub fn header_offset(&self) -> usize {
        self.start
    }
    /// Raw options bytes (the TLV trailer after the magic cookie).
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        &self.buf[self.options_start..self.end]
    }
    /// Iterator over the `(code, value)` DHCP options.
    #[inline]
    pub fn options_iter(&self) -> dhcp::OptionsIter<'a> {
        dhcp::OptionsIter::new(self.options())
    }

    /// Typed access to the options region.
    #[inline]
    pub fn typed_options(&self) -> dhcp::Options<'a> {
        dhcp::Options::new(self.options())
    }

    /// The DHCP message type (option 53), if present.
    #[inline]
    pub fn message_type(&self) -> Option<dhcp::MessageType> {
        self.typed_options().message_type()
    }

    /// Interpret the message as a DHCPOFFER (`None` unless it is one).
    #[inline]
    pub fn offer(&self) -> Option<dhcp::Offer<'a>> {
        dhcp::Offer::parse(self.header(), self.options())
    }

    /// Interpret the message as a DHCPREQUEST (`None` unless it is one).
    #[inline]
    pub fn request(&self) -> Option<dhcp::Request<'a>> {
        dhcp::Request::parse(self.header(), self.options())
    }

    /// Interpret the message as the lease granted by a DHCPACK (`None` unless
    /// it is an ACK).
    #[inline]
    pub fn lease(&self) -> Option<dhcp::Lease<'a>> {
        dhcp::Lease::parse(self.header(), self.options())
    }
}

/// A view of a DNS message: the fixed header plus the question/record body.
#[derive(Clone, Copy)]
pub struct DnsView<'a> {
    buf: &'a [u8],
    start: usize,
    body_start: usize,
    end: usize,
}

impl<'a> DnsView<'a> {
    fn parse_at(buf: &'a [u8], start: usize, end: usize) -> Option<Self> {
        let _: &DnsHeader = header_at(buf, start)?;
        let body_start = start.checked_add(DnsHeader::LEN)?;
        Some(Self {
            buf,
            start,
            body_start: body_start.min(end),
            end,
        })
    }

    #[inline]
    pub fn header(&self) -> &'a DnsHeader {
        header_at(self.buf, self.start).expect("validated during parse")
    }
    #[inline]
    pub fn header_offset(&self) -> usize {
        self.start
    }
    /// Raw bytes following the header (questions and resource records, which
    /// use name compression and so are not cast in place).
    #[inline]
    pub fn body(&self) -> &'a [u8] {
        &self.buf[self.body_start..self.end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::ethernet::ethertype;
    use crate::net::wire::mut_from_prefix;

    const DNS_ID: u16 = 0x1234;

    /// Build an Ethernet/IPv4/UDP/DNS packet into `buf` and return its length.
    fn build_dns_over_udp(buf: &mut [u8]) -> usize {
        let total_ip = Ipv4Header::MIN_LEN + UdpHeader::LEN + DnsHeader::LEN;

        let (eth, rest) = mut_from_prefix::<EthernetHeader>(buf).unwrap();
        eth.set_ethertype(ethertype::IPV4);

        let (ipv4, rest) = mut_from_prefix::<Ipv4Header>(rest).unwrap();
        ipv4.set_version_ihl(4, 5);
        ipv4.protocol = ip::proto::UDP;
        ipv4.set_total_len(total_ip as u16);

        let (udp, rest) = mut_from_prefix::<UdpHeader>(rest).unwrap();
        udp.set_dst_port(port::DNS);
        udp.set_length((UdpHeader::LEN + DnsHeader::LEN) as u16);

        let (dns, _) = mut_from_prefix::<DnsHeader>(rest).unwrap();
        dns.set_id(DNS_ID);

        EthernetHeader::LEN + total_ip
    }

    #[test]
    fn descends_eth_ipv4_udp_dns() {
        // Oversized buffer so trailing bytes act as Ethernet padding.
        let mut buf = [0u8; 64];
        let len = build_dns_over_udp(&mut buf);

        let eth = parse(&buf).unwrap();
        assert!(eth.is_ipv4());

        let ipv4 = eth.ipv4().unwrap();
        assert!(ipv4.is_udp());

        let udp = ipv4.udp().unwrap();
        assert!(udp.is_dns());
        // Payload is trimmed to the DNS message, not the padded buffer.
        assert_eq!(udp.payload().len(), DnsHeader::LEN);

        let dns = udp.dns().unwrap();
        assert_eq!(dns.header().id(), DNS_ID);

        // The reported offset locates the DNS header within the original frame.
        assert_eq!(dns.header_offset(), len - DnsHeader::LEN);
    }

    #[test]
    fn non_arp_frame_has_no_arp_view() {
        let mut buf = [0u8; 64];
        build_dns_over_udp(&mut buf);
        let eth = parse(&buf).unwrap();
        assert!(eth.arp().is_none());
        assert!(eth.ipv4().unwrap().tcp().is_none());
    }
}
