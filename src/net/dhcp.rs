//! DHCPv4 / BOOTP fixed header.
//!
//! The variable-length options trailer (after [`DhcpHeader::MAGIC_COOKIE`]) is
//! not part of the fixed struct; treat the bytes following the header as the
//! options region and walk them with [`OptionsIter`].

use crate::net::wire::{Pod, U16Be, U32Be};
use std::net::Ipv4Addr;

/// The broadcast-flag bit (the top bit of the 16-bit `flags` field). When set,
/// the server must broadcast its reply instead of unicasting it.
const BROADCAST_FLAG: u16 = 0x8000;

/// Hardware type for Ethernet in the `htype` field (the same value ARP uses).
const HTYPE_ETHERNET: u8 = 1;
/// Hardware address length for Ethernet: a MAC is 6 bytes.
const HLEN_ETHERNET: u8 = 6;

/// `op` field.
pub mod op {
    pub const BOOTREQUEST: u8 = 1;
    pub const BOOTREPLY: u8 = 2;
}

/// Selected DHCP option codes.
pub mod option {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS_SERVER: u8 = 6;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAMETER_REQUEST_LIST: u8 = 55;
    /// T1: when the client should start renewing, in seconds.
    pub const RENEWAL_TIME: u8 = 58;
    /// T2: when the client should start rebinding, in seconds.
    pub const REBINDING_TIME: u8 = 59;
    pub const END: u8 = 255;
}

/// DHCP message type values (the payload of option 53).
pub mod message_type {
    pub const DISCOVER: u8 = 1;
    pub const OFFER: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const DECLINE: u8 = 4;
    pub const ACK: u8 = 5;
    pub const NAK: u8 = 6;
    pub const RELEASE: u8 = 7;
    pub const INFORM: u8 = 8;
}

/// Fixed 240-byte DHCPv4 header (236-byte BOOTP frame + 4-byte magic cookie).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DhcpHeader {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    xid: U32Be,
    secs: U16Be,
    flags: U16Be,
    ciaddr: [u8; 4],
    yiaddr: [u8; 4],
    siaddr: [u8; 4],
    giaddr: [u8; 4],
    /// Client hardware address (first `hlen` bytes are meaningful).
    pub chaddr: [u8; 16],
    /// Optional server host name, null-terminated.
    pub sname: [u8; 64],
    /// Optional boot file name, null-terminated.
    pub file: [u8; 128],
    magic_cookie: U32Be,
}

unsafe impl Pod for DhcpHeader {}

impl Default for DhcpHeader {
    fn default() -> Self {
        // All-zero is a valid bit pattern for every field of this POD header.
        unsafe { core::mem::zeroed() }
    }
}

impl DhcpHeader {
    pub const LEN: usize = 240;
    /// The DHCP magic cookie that precedes the options region.
    pub const MAGIC_COOKIE: u32 = 0x6382_5363;

    #[inline]
    pub fn xid(&self) -> u32 {
        self.xid.get()
    }
    #[inline]
    pub fn set_xid(&mut self, v: u32) {
        self.xid.set(v);
    }

    #[inline]
    pub fn secs(&self) -> u16 {
        self.secs.get()
    }
    /// The broadcast-flag bit.
    #[inline]
    pub fn broadcast(&self) -> bool {
        self.flags.get() & BROADCAST_FLAG != 0
    }
    #[inline]
    pub fn set_broadcast(&mut self, on: bool) {
        let f = if on {
            self.flags.get() | BROADCAST_FLAG
        } else {
            self.flags.get() & !BROADCAST_FLAG
        };
        self.flags.set(f);
    }

    #[inline]
    pub fn client_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.ciaddr)
    }
    /// "Your" address — the IP the server is assigning.
    #[inline]
    pub fn your_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.yiaddr)
    }
    #[inline]
    pub fn server_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.siaddr)
    }
    #[inline]
    pub fn gateway_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.giaddr)
    }

    #[inline]
    pub fn set_secs(&mut self, v: u16) {
        self.secs.set(v);
    }
    #[inline]
    pub fn set_client_ip(&mut self, addr: Ipv4Addr) {
        self.ciaddr = addr.octets();
    }
    /// Set `yiaddr`, the address being assigned to the client.
    #[inline]
    pub fn set_your_ip(&mut self, addr: Ipv4Addr) {
        self.yiaddr = addr.octets();
    }
    #[inline]
    pub fn set_server_ip(&mut self, addr: Ipv4Addr) {
        self.siaddr = addr.octets();
    }
    #[inline]
    pub fn set_gateway_ip(&mut self, addr: Ipv4Addr) {
        self.giaddr = addr.octets();
    }

    /// Set the client hardware address and `hlen` from a MAC, zero-padding the
    /// rest of `chaddr` and truncating if `mac` is longer than the field.
    pub fn set_client_hardware_addr(&mut self, mac: &[u8]) {
        let len = mac.len().min(self.chaddr.len());
        self.chaddr.fill(0);
        self.chaddr[..len].copy_from_slice(&mac[..len]);
        self.hlen = len as u8;
    }

    /// Initialise the fixed fields for an Ethernet BOOTP frame: `op`, the
    /// Ethernet hardware type/length, and the magic cookie. Call the address
    /// and `chaddr` setters afterwards.
    pub fn init_ethernet(&mut self, op: u8) {
        self.op = op;
        self.htype = HTYPE_ETHERNET;
        self.hlen = HLEN_ETHERNET;
        self.set_magic_cookie();
    }

    #[inline]
    pub fn has_magic_cookie(&self) -> bool {
        self.magic_cookie.get() == Self::MAGIC_COOKIE
    }
    #[inline]
    pub fn set_magic_cookie(&mut self) {
        self.magic_cookie.set(Self::MAGIC_COOKIE);
    }
}

/// Iterator over the `(code, value)` TLV options that follow a [`DhcpHeader`].
///
/// `PAD` options are skipped and iteration stops at `END` or when the buffer is
/// exhausted. Pass the bytes *after* the fixed header.
pub struct OptionsIter<'a> {
    buf: &'a [u8],
}

impl<'a> OptionsIter<'a> {
    #[inline]
    pub fn new(options: &'a [u8]) -> Self {
        Self { buf: options }
    }
}

impl<'a> Iterator for OptionsIter<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (&code, rest) = self.buf.split_first()?;
            match code {
                option::PAD => {
                    self.buf = rest;
                    continue;
                }
                option::END => {
                    self.buf = &[];
                    return None;
                }
                _ => {
                    let (&len, rest) = rest.split_first()?;
                    let len = len as usize;
                    if rest.len() < len {
                        self.buf = &[];
                        return None;
                    }
                    let (value, tail) = rest.split_at(len);
                    self.buf = tail;
                    return Some((code, value));
                }
            }
        }
    }
}

/// Length in bytes of an IPv4 address carried in an option value.
const IPV4_LEN: usize = 4;
/// Length in bytes of a 32-bit seconds value (lease / renewal / rebinding).
const SECONDS_LEN: usize = 4;

/// Parse an option value as a single IPv4 address (`None` unless exactly 4 bytes).
fn opt_ipv4(value: &[u8]) -> Option<Ipv4Addr> {
    let octets: [u8; IPV4_LEN] = value.try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

/// Parse an option value as a big-endian `u32` of seconds (`None` unless 4 bytes).
fn opt_seconds(value: &[u8]) -> Option<u32> {
    let bytes: [u8; SECONDS_LEN] = value.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// The DHCP message type (option 53), as a closed set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl MessageType {
    /// Map the option-53 byte to a variant.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            message_type::DISCOVER => Self::Discover,
            message_type::OFFER => Self::Offer,
            message_type::REQUEST => Self::Request,
            message_type::DECLINE => Self::Decline,
            message_type::ACK => Self::Ack,
            message_type::NAK => Self::Nak,
            message_type::RELEASE => Self::Release,
            message_type::INFORM => Self::Inform,
            _ => return None,
        })
    }

    /// The wire byte for this message type.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Discover => message_type::DISCOVER,
            Self::Offer => message_type::OFFER,
            Self::Request => message_type::REQUEST,
            Self::Decline => message_type::DECLINE,
            Self::Ack => message_type::ACK,
            Self::Nak => message_type::NAK,
            Self::Release => message_type::RELEASE,
            Self::Inform => message_type::INFORM,
        }
    }
}

/// Iterator over a concatenated list of IPv4 addresses, as carried by options
/// such as Router (3) and DNS Server (6).
#[derive(Clone, Copy)]
pub struct Ipv4ListIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for Ipv4ListIter<'a> {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() < IPV4_LEN {
            return None;
        }
        let (head, tail) = self.bytes.split_at(IPV4_LEN);
        self.bytes = tail;
        opt_ipv4(head)
    }
}

/// Typed read access over a DHCP options region (the bytes after the magic
/// cookie). Cheap to copy; every getter is a fresh scan, which is fine for the
/// handful of options a message carries.
#[derive(Clone, Copy)]
pub struct Options<'a> {
    bytes: &'a [u8],
}

impl<'a> Options<'a> {
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    #[inline]
    pub fn iter(&self) -> OptionsIter<'a> {
        OptionsIter::new(self.bytes)
    }

    /// First value for `code`, if present.
    #[inline]
    pub fn get(&self, code: u8) -> Option<&'a [u8]> {
        self.iter().find(|(c, _)| *c == code).map(|(_, v)| v)
    }

    #[inline]
    pub fn message_type(&self) -> Option<MessageType> {
        MessageType::from_u8(*self.get(option::MESSAGE_TYPE)?.first()?)
    }
    #[inline]
    pub fn server_id(&self) -> Option<Ipv4Addr> {
        opt_ipv4(self.get(option::SERVER_ID)?)
    }
    #[inline]
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        opt_ipv4(self.get(option::REQUESTED_IP)?)
    }
    #[inline]
    pub fn subnet_mask(&self) -> Option<Ipv4Addr> {
        opt_ipv4(self.get(option::SUBNET_MASK)?)
    }
    /// Lease duration in seconds (option 51).
    #[inline]
    pub fn lease_time(&self) -> Option<u32> {
        opt_seconds(self.get(option::LEASE_TIME)?)
    }
    /// Renewal (T1) time in seconds (option 58).
    #[inline]
    pub fn renewal_time(&self) -> Option<u32> {
        opt_seconds(self.get(option::RENEWAL_TIME)?)
    }
    /// Rebinding (T2) time in seconds (option 59).
    #[inline]
    pub fn rebinding_time(&self) -> Option<u32> {
        opt_seconds(self.get(option::REBINDING_TIME)?)
    }
    /// Default gateways (option 3).
    #[inline]
    pub fn routers(&self) -> Ipv4ListIter<'a> {
        Ipv4ListIter {
            bytes: self.get(option::ROUTER).unwrap_or(&[]),
        }
    }
    /// DNS servers (option 6).
    #[inline]
    pub fn dns_servers(&self) -> Ipv4ListIter<'a> {
        Ipv4ListIter {
            bytes: self.get(option::DNS_SERVER).unwrap_or(&[]),
        }
    }
}

/// A parsed DHCPOFFER: the address and parameters a server is offering.
#[derive(Clone, Copy)]
pub struct Offer<'a> {
    header: &'a DhcpHeader,
    options: Options<'a>,
}

impl<'a> Offer<'a> {
    /// Interpret `(header, options)` as an offer; `None` unless option 53 says
    /// [`MessageType::Offer`].
    pub fn parse(header: &'a DhcpHeader, options: &'a [u8]) -> Option<Self> {
        let options = Options::new(options);
        match options.message_type()? {
            MessageType::Offer => Some(Self { header, options }),
            _ => None,
        }
    }

    /// Transaction id tying this offer to the client's discover.
    #[inline]
    pub fn transaction_id(&self) -> u32 {
        self.header.xid()
    }
    /// Client hardware address the offer is for (`hlen` bytes of `chaddr`).
    #[inline]
    pub fn client_hardware_addr(&self) -> &'a [u8] {
        let len = (self.header.hlen as usize).min(self.header.chaddr.len());
        &self.header.chaddr[..len]
    }
    /// The offered address (`yiaddr`).
    #[inline]
    pub fn offered_ip(&self) -> Ipv4Addr {
        self.header.your_ip()
    }
    #[inline]
    pub fn server_id(&self) -> Option<Ipv4Addr> {
        self.options.server_id()
    }
    #[inline]
    pub fn lease_time(&self) -> Option<u32> {
        self.options.lease_time()
    }
    #[inline]
    pub fn subnet_mask(&self) -> Option<Ipv4Addr> {
        self.options.subnet_mask()
    }
    #[inline]
    pub fn routers(&self) -> Ipv4ListIter<'a> {
        self.options.routers()
    }
    #[inline]
    pub fn dns_servers(&self) -> Ipv4ListIter<'a> {
        self.options.dns_servers()
    }
    /// Raw typed options, for anything not surfaced above.
    #[inline]
    pub fn options(&self) -> Options<'a> {
        self.options
    }
}

/// A parsed DHCPREQUEST: a client committing to (or renewing) an address.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    header: &'a DhcpHeader,
    options: Options<'a>,
}

impl<'a> Request<'a> {
    /// `None` unless option 53 says [`MessageType::Request`].
    pub fn parse(header: &'a DhcpHeader, options: &'a [u8]) -> Option<Self> {
        let options = Options::new(options);
        match options.message_type()? {
            MessageType::Request => Some(Self { header, options }),
            _ => None,
        }
    }

    #[inline]
    pub fn transaction_id(&self) -> u32 {
        self.header.xid()
    }
    #[inline]
    pub fn client_hardware_addr(&self) -> &'a [u8] {
        let len = (self.header.hlen as usize).min(self.header.chaddr.len());
        &self.header.chaddr[..len]
    }
    /// The address the client wants (option 50). During a renewal the client
    /// omits this and uses `ciaddr` instead — see [`Self::client_ip`].
    #[inline]
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.options.requested_ip()
    }
    /// `ciaddr`: the client's current address, set when renewing.
    #[inline]
    pub fn client_ip(&self) -> Ipv4Addr {
        self.header.client_ip()
    }
    /// The server this request is directed at (option 54), set when selecting
    /// among multiple offers.
    #[inline]
    pub fn server_id(&self) -> Option<Ipv4Addr> {
        self.options.server_id()
    }
    #[inline]
    pub fn options(&self) -> Options<'a> {
        self.options
    }
}

/// A parsed lease, taken from a DHCPACK: the bound address and its parameters.
#[derive(Clone, Copy)]
pub struct Lease<'a> {
    header: &'a DhcpHeader,
    options: Options<'a>,
}

impl<'a> Lease<'a> {
    /// `None` unless option 53 says [`MessageType::Ack`] (the message that
    /// actually grants the lease).
    pub fn parse(header: &'a DhcpHeader, options: &'a [u8]) -> Option<Self> {
        let options = Options::new(options);
        match options.message_type()? {
            MessageType::Ack => Some(Self { header, options }),
            _ => None,
        }
    }

    #[inline]
    pub fn transaction_id(&self) -> u32 {
        self.header.xid()
    }
    #[inline]
    pub fn client_hardware_addr(&self) -> &'a [u8] {
        let len = (self.header.hlen as usize).min(self.header.chaddr.len());
        &self.header.chaddr[..len]
    }
    /// The bound address (`yiaddr`).
    #[inline]
    pub fn assigned_ip(&self) -> Ipv4Addr {
        self.header.your_ip()
    }
    #[inline]
    pub fn server_id(&self) -> Option<Ipv4Addr> {
        self.options.server_id()
    }
    /// Lease duration in seconds.
    #[inline]
    pub fn lease_time(&self) -> Option<u32> {
        self.options.lease_time()
    }
    /// Renewal time T1 in seconds.
    #[inline]
    pub fn renewal_time(&self) -> Option<u32> {
        self.options.renewal_time()
    }
    /// Rebinding time T2 in seconds.
    #[inline]
    pub fn rebinding_time(&self) -> Option<u32> {
        self.options.rebinding_time()
    }
    #[inline]
    pub fn subnet_mask(&self) -> Option<Ipv4Addr> {
        self.options.subnet_mask()
    }
    #[inline]
    pub fn routers(&self) -> Ipv4ListIter<'a> {
        self.options.routers()
    }
    #[inline]
    pub fn dns_servers(&self) -> Ipv4ListIter<'a> {
        self.options.dns_servers()
    }
    #[inline]
    pub fn options(&self) -> Options<'a> {
        self.options
    }
}

/// Writes DHCP option TLVs into the region *after* the magic cookie, tracking
/// how many bytes were used. Each writer method returns `false` (without
/// advancing) if the option wouldn't fit, so a caller can detect truncation;
/// finish with [`OptionsWriter::end`] to emit the `END` marker.
pub struct OptionsWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> OptionsWriter<'a> {
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// Bytes written so far (including a trailing `END` once emitted).
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Write one `code`/`value` option. Fails if `value` exceeds 255 bytes or
    /// the buffer is full.
    #[must_use]
    pub fn option(&mut self, code: u8, value: &[u8]) -> bool {
        let need = 2 + value.len();
        if value.len() > u8::MAX as usize || self.len + need > self.buf.len() {
            return false;
        }
        self.buf[self.len] = code;
        self.buf[self.len + 1] = value.len() as u8;
        self.buf[self.len + 2..self.len + need].copy_from_slice(value);
        self.len += need;
        true
    }

    #[must_use]
    pub fn message_type(&mut self, t: MessageType) -> bool {
        self.option(option::MESSAGE_TYPE, &[t.to_u8()])
    }
    #[must_use]
    pub fn ipv4(&mut self, code: u8, addr: Ipv4Addr) -> bool {
        self.option(code, &addr.octets())
    }
    #[must_use]
    pub fn seconds(&mut self, code: u8, secs: u32) -> bool {
        self.option(code, &secs.to_be_bytes())
    }
    #[must_use]
    pub fn ipv4_list(&mut self, code: u8, addrs: &[Ipv4Addr]) -> bool {
        let vlen = addrs.len() * IPV4_LEN;
        if vlen > u8::MAX as usize || self.len + 2 + vlen > self.buf.len() {
            return false;
        }
        self.buf[self.len] = code;
        self.buf[self.len + 1] = vlen as u8;
        let mut o = self.len + 2;
        for a in addrs {
            self.buf[o..o + IPV4_LEN].copy_from_slice(&a.octets());
            o += IPV4_LEN;
        }
        self.len += 2 + vlen;
        true
    }

    /// Emit the terminating `END` option.
    #[must_use]
    pub fn end(&mut self) -> bool {
        if self.len + 1 > self.buf.len() {
            return false;
        }
        self.buf[self.len] = option::END;
        self.len += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Length byte for a single IPv4-address option value.
    const IPV4_OPT_LEN: u8 = 4;
    /// Length byte for a 32-bit seconds option value.
    const SECONDS_OPT_LEN: u8 = 4;

    #[test]
    fn parses_ack_into_lease() {
        let header = DhcpHeader::default();
        let opts = [
            option::MESSAGE_TYPE,
            1,
            message_type::ACK,
            option::SERVER_ID,
            IPV4_OPT_LEN,
            192,
            168,
            1,
            1,
            // 0x0000_0E10 == 3600 seconds.
            option::LEASE_TIME,
            SECONDS_OPT_LEN,
            0x00,
            0x00,
            0x0e,
            0x10,
            option::SUBNET_MASK,
            IPV4_OPT_LEN,
            255,
            255,
            255,
            0,
            option::ROUTER,
            IPV4_OPT_LEN,
            192,
            168,
            1,
            254,
            option::DNS_SERVER,
            8,
            8,
            8,
            8,
            8,
            1,
            1,
            1,
            1,
            option::END,
        ];

        let lease = Lease::parse(&header, &opts).expect("ACK should parse as a lease");
        assert_eq!(lease.server_id(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(lease.lease_time(), Some(3600));
        assert_eq!(lease.subnet_mask(), Some(Ipv4Addr::new(255, 255, 255, 0)));

        let routers: Vec<_> = lease.routers().collect();
        assert_eq!(routers, vec![Ipv4Addr::new(192, 168, 1, 254)]);

        let dns: Vec<_> = lease.dns_servers().collect();
        assert_eq!(
            dns,
            vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)]
        );

        // The message-type gate rejects the wrong interpretation.
        assert!(Offer::parse(&header, &opts).is_none());
        assert!(Request::parse(&header, &opts).is_none());
    }

    #[test]
    fn parses_offer_and_request() {
        let header = DhcpHeader::default();

        let offer_opts = [
            option::MESSAGE_TYPE,
            1,
            message_type::OFFER,
            option::SERVER_ID,
            IPV4_OPT_LEN,
            10,
            0,
            0,
            1,
            option::END,
        ];
        let offer = Offer::parse(&header, &offer_opts).expect("OFFER");
        assert_eq!(offer.server_id(), Some(Ipv4Addr::new(10, 0, 0, 1)));

        let request_opts = [
            option::MESSAGE_TYPE,
            1,
            message_type::REQUEST,
            option::REQUESTED_IP,
            IPV4_OPT_LEN,
            10,
            0,
            0,
            50,
            option::SERVER_ID,
            IPV4_OPT_LEN,
            10,
            0,
            0,
            1,
            option::END,
        ];
        let request = Request::parse(&header, &request_opts).expect("REQUEST");
        assert_eq!(request.requested_ip(), Some(Ipv4Addr::new(10, 0, 0, 50)));
        assert_eq!(request.server_id(), Some(Ipv4Addr::new(10, 0, 0, 1)));
    }
}
