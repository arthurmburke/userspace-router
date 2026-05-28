//! DHCP control plane: a LAN-side server that hands out leases and a WAN-side
//! client that obtains the router's own address.
//!
//! Both produce/consume fully-formed Ethernet/IPv4/UDP frames (via
//! [`crate::router::frame`]) so the datapath only has to copy bytes onto an
//! mbuf. There is a single software-defined server-identity IP
//! ([`DhcpServerConfig::server_ip`]) used as the DHCP server-id on every LAN
//! interface.

use crate::net::dhcp::{self, DhcpHeader, MessageType, OptionsWriter, option};
use crate::net::ethernet::{BROADCAST, MacAddr};
use crate::net::view::DhcpView;
use crate::net::wire::mut_from_prefix;
use crate::router::frame::{self, UdpV4};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Server (BOOTP server) UDP port.
const SERVER_PORT: u16 = 67;
/// Client (BOOTP client) UDP port.
const CLIENT_PORT: u16 = 68;
/// Scratch size for a built DHCP payload (240-byte fixed header + options).
const PAYLOAD_MAX: usize = 512;

const UNSPECIFIED: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const BROADCAST_IP: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

/// Options the client asks the server to include.
const PARAM_REQUEST_LIST: [u8; 4] = [
    option::SUBNET_MASK,
    option::ROUTER,
    option::DNS_SERVER,
    option::LEASE_TIME,
];

/// The first six bytes of `chaddr` as a MAC.
fn client_mac(header: &DhcpHeader) -> MacAddr {
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&header.chaddr[..6]);
    mac
}

// ------------------------------------------------------------------------- //
// Server
// ------------------------------------------------------------------------- //

/// Static configuration for the LAN DHCP server.
pub struct DhcpServerConfig {
    /// The single software-defined server identity (DHCP server-id + `siaddr`).
    pub server_ip: Ipv4Addr,
    /// MAC of the LAN interface that will source replies.
    pub server_mac: MacAddr,
    /// Default gateway handed to clients (often equal to `server_ip`).
    pub gateway: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub lease_secs: u32,
    /// Inclusive address pool.
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
}

/// A simple DHCP server with a flat address pool keyed by client MAC.
pub struct DhcpServer {
    cfg: DhcpServerConfig,
    leases: HashMap<MacAddr, Ipv4Addr>,
}

impl DhcpServer {
    pub fn new(cfg: DhcpServerConfig) -> Self {
        Self {
            cfg,
            leases: HashMap::new(),
        }
    }

    /// Currently-assigned address for `mac`, if any.
    pub fn lease_of(&self, mac: &MacAddr) -> Option<Ipv4Addr> {
        self.leases.get(mac).copied()
    }

    /// Process an inbound DHCP message and, if a reply is warranted, build the
    /// response frame into `out`, returning its length.
    pub fn handle(&mut self, view: &DhcpView, out: &mut [u8]) -> Option<usize> {
        let header = view.header();
        let mac = client_mac(header);
        let xid = header.xid();
        let broadcast = header.broadcast();
        let opts = view.typed_options();

        match view.message_type()? {
            MessageType::Discover => {
                let ip = self.assign(mac)?;
                self.build_reply(MessageType::Offer, xid, ip, mac, broadcast, out)
            }
            MessageType::Request => {
                // If the client is selecting another server, stay quiet.
                if let Some(sid) = opts.server_id()
                    && sid != self.cfg.server_ip
                {
                    return None;
                }
                let requested = opts.requested_ip().unwrap_or_else(|| header.client_ip());
                let ip = self.assign(mac)?;
                if requested == ip {
                    self.build_reply(MessageType::Ack, xid, ip, mac, broadcast, out)
                } else {
                    // The client wants something we won't give it.
                    self.build_reply(MessageType::Nak, xid, UNSPECIFIED, mac, true, out)
                }
            }
            MessageType::Release | MessageType::Decline => {
                self.leases.remove(&mac);
                None
            }
            _ => None,
        }
    }

    /// Return the address bound to `mac`, allocating the next free pool address
    /// on first contact.
    fn assign(&mut self, mac: MacAddr) -> Option<Ipv4Addr> {
        if let Some(&ip) = self.leases.get(&mac) {
            return Some(ip);
        }
        let taken: std::collections::HashSet<u32> =
            self.leases.values().map(|a| u32::from(*a)).collect();
        let reserved = [u32::from(self.cfg.server_ip), u32::from(self.cfg.gateway)];

        for n in u32::from(self.cfg.pool_start)..=u32::from(self.cfg.pool_end) {
            if reserved.contains(&n) || taken.contains(&n) {
                continue;
            }
            let ip = Ipv4Addr::from(n);
            self.leases.insert(mac, ip);
            return Some(ip);
        }
        None // pool exhausted
    }

    fn build_reply(
        &self,
        kind: MessageType,
        xid: u32,
        yiaddr: Ipv4Addr,
        client: MacAddr,
        broadcast: bool,
        out: &mut [u8],
    ) -> Option<usize> {
        let mut payload = [0u8; PAYLOAD_MAX];
        let plen = self.build_payload(kind, xid, yiaddr, client, &mut payload)?;

        // A client without an address generally can't receive unicast; honour
        // the broadcast flag and always broadcast a NAK.
        let (dst_ip, dst_mac) = if broadcast || kind == MessageType::Nak {
            (BROADCAST_IP, BROADCAST)
        } else {
            (yiaddr, client)
        };

        let params = UdpV4 {
            src_mac: self.cfg.server_mac,
            dst_mac,
            src_ip: self.cfg.server_ip,
            dst_ip,
            src_port: SERVER_PORT,
            dst_port: CLIENT_PORT,
            ttl: frame::DEFAULT_TTL,
        };
        frame::build_udp_ipv4(out, &params, &payload[..plen])
    }

    fn build_payload(
        &self,
        kind: MessageType,
        xid: u32,
        yiaddr: Ipv4Addr,
        client: MacAddr,
        buf: &mut [u8],
    ) -> Option<usize> {
        {
            let (h, _) = mut_from_prefix::<DhcpHeader>(buf)?;
            h.init_ethernet(dhcp::op::BOOTREPLY);
            h.set_xid(xid);
            h.set_your_ip(yiaddr);
            h.set_server_ip(self.cfg.server_ip);
            h.set_client_hardware_addr(&client);
        }

        let mut w = OptionsWriter::new(&mut buf[DhcpHeader::LEN..]);
        // Boolean `&&` consumes each `#[must_use]` result and short-circuits on
        // the first option that doesn't fit.
        let ok = w.message_type(kind)
            && w.ipv4(option::SERVER_ID, self.cfg.server_ip)
            && (kind == MessageType::Nak
                || (w.seconds(option::LEASE_TIME, self.cfg.lease_secs)
                    && w.ipv4(option::SUBNET_MASK, self.cfg.subnet_mask)
                    && w.ipv4(option::ROUTER, self.cfg.gateway)
                    && (self.cfg.dns.is_empty()
                        || w.ipv4_list(option::DNS_SERVER, &self.cfg.dns))))
            && w.end();
        if !ok {
            return None;
        }
        Some(DhcpHeader::LEN + w.len())
    }
}

// ------------------------------------------------------------------------- //
// Client
// ------------------------------------------------------------------------- //

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientState {
    Init,
    Selecting,
    Requesting,
    Bound,
}

/// The configuration the client learned from the server's ACK.
#[derive(Clone, Copy, Debug)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub subnet_mask: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    pub lease_secs: Option<u32>,
}

/// A minimal DHCP client driving the DISCOVER → OFFER → REQUEST → ACK exchange.
pub struct DhcpClient {
    mac: MacAddr,
    xid: u32,
    state: ClientState,
    offered_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
    lease: Option<DhcpLease>,
}

impl DhcpClient {
    pub fn new(mac: MacAddr, xid: u32) -> Self {
        Self {
            mac,
            xid,
            state: ClientState::Init,
            offered_ip: None,
            server_id: None,
            lease: None,
        }
    }

    pub fn state(&self) -> ClientState {
        self.state
    }
    pub fn lease(&self) -> Option<&DhcpLease> {
        self.lease.as_ref()
    }
    pub fn bound_ip(&self) -> Option<Ipv4Addr> {
        self.lease.as_ref().map(|l| l.ip)
    }

    /// Produce the next outbound message (DISCOVER in `Init`, REQUEST in
    /// `Requesting`), advancing the protocol where appropriate. Returns the
    /// frame length written to `out`, or `None` if there's nothing to send.
    pub fn poll(&mut self, out: &mut [u8]) -> Option<usize> {
        match self.state {
            ClientState::Init => {
                let n = self.build(MessageType::Discover, out)?;
                self.state = ClientState::Selecting;
                Some(n)
            }
            ClientState::Requesting => self.build(MessageType::Request, out),
            ClientState::Selecting | ClientState::Bound => None,
        }
    }

    /// Feed a received DHCP message, advancing the state machine.
    pub fn on_receive(&mut self, view: &DhcpView) {
        let header = view.header();
        if header.xid() != self.xid {
            return; // not our transaction
        }
        let opts = view.typed_options();
        match view.message_type() {
            Some(MessageType::Offer) if self.state == ClientState::Selecting => {
                self.offered_ip = Some(header.your_ip());
                self.server_id = opts.server_id();
                self.state = ClientState::Requesting;
            }
            Some(MessageType::Ack) if self.state == ClientState::Requesting => {
                self.lease = Some(DhcpLease {
                    ip: header.your_ip(),
                    subnet_mask: opts.subnet_mask(),
                    gateway: opts.routers().next(),
                    server_id: opts.server_id(),
                    lease_secs: opts.lease_time(),
                });
                self.state = ClientState::Bound;
            }
            Some(MessageType::Nak) => {
                self.offered_ip = None;
                self.server_id = None;
                self.state = ClientState::Init;
            }
            _ => {}
        }
    }

    fn build(&self, kind: MessageType, out: &mut [u8]) -> Option<usize> {
        let mut payload = [0u8; PAYLOAD_MAX];
        let plen = {
            {
                let (h, _) = mut_from_prefix::<DhcpHeader>(&mut payload)?;
                h.init_ethernet(dhcp::op::BOOTREQUEST);
                h.set_xid(self.xid);
                h.set_broadcast(true);
                h.set_client_hardware_addr(&self.mac);
            }
            let mut w = OptionsWriter::new(&mut payload[DhcpHeader::LEN..]);
            let ok = w.message_type(kind)
                && (kind != MessageType::Request
                    || ((self.offered_ip.is_none()
                        || w.ipv4(option::REQUESTED_IP, self.offered_ip.unwrap()))
                        && (self.server_id.is_none()
                            || w.ipv4(option::SERVER_ID, self.server_id.unwrap()))))
                && w.option(option::PARAMETER_REQUEST_LIST, &PARAM_REQUEST_LIST)
                && w.end();
            if !ok {
                return None;
            }
            DhcpHeader::LEN + w.len()
        };

        // Client has no address yet: source 0.0.0.0:68 → 255.255.255.255:67.
        let params = UdpV4 {
            src_mac: self.mac,
            dst_mac: BROADCAST,
            src_ip: UNSPECIFIED,
            dst_ip: BROADCAST_IP,
            src_port: CLIENT_PORT,
            dst_port: SERVER_PORT,
            ttl: frame::DEFAULT_TTL,
        };
        frame::build_udp_ipv4(out, &params, &payload[..plen])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::view;

    /// Walk a frame down to its DHCP view and run `f` on it. (A helper can't
    /// return the borrowing view, so we pass a closure.)
    fn with_dhcp<R>(frame: &[u8], f: impl FnOnce(&DhcpView) -> R) -> R {
        let eth = view::parse(frame).expect("eth");
        let ip = eth.ipv4().expect("ipv4");
        let udp = ip.udp().expect("udp");
        let dhcp = udp.dhcp().expect("dhcp");
        f(&dhcp)
    }

    #[test]
    fn full_dora_between_client_and_server() {
        let client_mac = [0x02, 0, 0, 0, 0, 0x10];
        let server_mac = [0x02, 0, 0, 0, 0, 0x01];
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);

        let mut client = DhcpClient::new(client_mac, 0xABCD_1234);
        let mut server = DhcpServer::new(DhcpServerConfig {
            server_ip,
            server_mac,
            gateway: server_ip,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            dns: vec![Ipv4Addr::new(1, 1, 1, 1)],
            lease_secs: 3600,
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 110),
        });

        let mut out = [0u8; 600];
        let mut reply = [0u8; 600];

        // DISCOVER -> OFFER
        let n = client.poll(&mut out).unwrap();
        assert_eq!(client.state(), ClientState::Selecting);
        let on = with_dhcp(&out[..n], |v| server.handle(v, &mut reply)).unwrap();
        with_dhcp(&reply[..on], |v| client.on_receive(v));
        assert_eq!(client.state(), ClientState::Requesting);

        // REQUEST -> ACK
        let n = client.poll(&mut out).unwrap();
        let an = with_dhcp(&out[..n], |v| server.handle(v, &mut reply)).unwrap();
        with_dhcp(&reply[..an], |v| client.on_receive(v));
        assert_eq!(client.state(), ClientState::Bound);

        let lease = client.lease().unwrap();
        assert!(lease.ip >= Ipv4Addr::new(192, 168, 1, 100));
        assert!(lease.ip <= Ipv4Addr::new(192, 168, 1, 110));
        assert_eq!(lease.gateway, Some(server_ip));
        assert_eq!(lease.server_id, Some(server_ip));
        assert_eq!(lease.lease_secs, Some(3600));
        assert_eq!(lease.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        // The server recorded the binding for this MAC.
        assert_eq!(server.lease_of(&client_mac), Some(lease.ip));
    }

    #[test]
    fn distinct_clients_get_distinct_addresses() {
        let server_ip = Ipv4Addr::new(10, 0, 0, 1);
        let mut server = DhcpServer::new(DhcpServerConfig {
            server_ip,
            server_mac: [0x02, 0, 0, 0, 0, 1],
            gateway: server_ip,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            dns: vec![],
            lease_secs: 600,
            pool_start: Ipv4Addr::new(10, 0, 0, 10),
            pool_end: Ipv4Addr::new(10, 0, 0, 12),
        });

        let mut out = [0u8; 600];
        let mut reply = [0u8; 600];
        let mut offered = Vec::new();
        for last in 0x20u8..0x23 {
            let mut c = DhcpClient::new([0x02, 0, 0, 0, 0, last], last as u32);
            let n = c.poll(&mut out).unwrap();
            let on = with_dhcp(&out[..n], |v| server.handle(v, &mut reply)).unwrap();
            with_dhcp(&reply[..on], |v| c.on_receive(v));
            offered.push(c.offered_ip.unwrap());
        }
        offered.sort();
        offered.dedup();
        assert_eq!(offered.len(), 3, "each client should get a unique address");
    }
}
