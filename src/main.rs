//! quicktcp router runtime.
//!
//! Single-core skeleton that brings the control plane online: the WAN port runs
//! a DHCP client to obtain the router's address; each LAN port answers ARP for
//! the software-defined service IP and serves DHCP leases. The NAT datapath
//! (and multi-core worker model) layer on top of this later.
//!
//! NOTE: this is the DPDK-gated glue — build/run it in the container:
//! `cargo run --features dpdk -- -l 0 -n 4 --vdev ...`

fn main() {
    #[cfg(not(feature = "dpdk"))]
    eprintln!("build with `--features dpdk` to run the router");

    #[cfg(feature = "dpdk")]
    runtime::run();
}

#[cfg(feature = "dpdk")]
mod runtime {
    use quicktcp::dpdk::ffi;
    use quicktcp::dpdk::mbuf::Mbuf;
    use quicktcp::dpdk::port::{self, PortConfig};
    use quicktcp::net::ethernet::MacAddr;
    use quicktcp::router::conf::{InterfaceRole, RouterConfig};
    use quicktcp::router::{
        arp,
        dhcp::{DhcpClient, DhcpServer, DhcpServerConfig},
    };
    use std::ffi::CString;
    use std::io::Read;
    use std::net::Ipv4Addr;
    use std::path::Path;

    /// RX/TX burst size.
    const BURST: usize = 32;
    /// Per-port RX/TX descriptor ring size.
    const RING: u16 = 1024;
    /// Number of mbufs in the pool (a Mersenne prime, per DPDK convention).
    const NUM_MBUFS: u32 = 8191;
    /// Per-core mbuf cache size.
    const MBUF_CACHE: u32 = 256;
    /// mbuf data room: default 2048 payload + 128 headroom.
    const MBUF_DATA_ROOM: u16 = 2048 + 128;
    /// Max Ethernet frame we build into the scratch buffer.
    const FRAME_MAX: usize = 1518;

    /// Software-defined DHCP server identity / LAN gateway.
    const LEASE_SECS: u32 = 86_400;
    /// Transaction id seed for the WAN client ("quic" in ASCII).
    const WAN_XID: u32 = 0x7175_6963;

    pub fn run() {
        // Deserialize router configuration file a router config file
        let config_file_path =
            Path::new(&std::env::var("CONFIG_FILE").unwrap_or_else(|_| "router.conf".to_string()))
                .to_path_buf();

        let mut config_file =
            std::fs::File::open(&config_file_path).expect("config file not found");
        let mut data = Vec::new();
        let len = config_file
            .read_to_end(&mut data)
            .expect("failed to read router configuration");

        let config: RouterConfig = toml::from_slice(&data[..len]).expect("failed to parse config");
        let server_ip = config.lan.ip;
        let subnet_mask = config.lan.mask;
        let pool_start = config.dhcp.pool_start;
        let pool_end = config.dhcp.pool_end;

        eal_init();

        let ports = port::all_ports();
        assert!(
            ports.len() >= 2,
            "need at least one WAN + one LAN port (found {})",
            ports.len()
        );
        // Find the WAN port based on the config.
        let wan_port_name = config
            .interfaces
            .iter()
            .find(|i| i.role == InterfaceRole::Wan)
            .map(|i| i.name.clone())
            .unwrap_or_else(|| ports[0].to_string());

        let mut wan = 0;

        unsafe {
            let c_str = CString::new(wan_port_name.clone()).unwrap();
            let ret = ffi::rte_eth_dev_get_port_by_name(c_str.as_ptr(), &mut wan);
            assert_eq!(
                ret, 0,
                "failed to find WAN port with name '{}'",
                wan_port_name
            );
        }

        let lan_port_names = config
            .interfaces
            .iter()
            .filter(|i| i.role == InterfaceRole::Lan)
            .map(|i| i.name.clone())
            .collect::<Vec<_>>();

        let mut lan_ports = vec![0; lan_port_names.len()];
        for (i, lan_port_name) in lan_port_names.into_iter().enumerate() {
            unsafe {
                let c_str = CString::new(lan_port_name.clone()).unwrap();
                let ret = ffi::rte_eth_dev_get_port_by_name(c_str.as_ptr(), &mut lan_ports[i]);
                assert_eq!(
                    ret, 0,
                    "failed to find LAN port with name '{}'",
                    lan_port_name
                );
            }
        }

        let pool = create_pool();
        for &p in &ports {
            port::init_port(&PortConfig {
                port_id: p,
                nb_rx_queues: 1,
                nb_tx_queues: 1,
                rx_ring_size: RING,
                tx_ring_size: RING,
                mempool: pool,
            })
            .expect("port init");
        }

        // WAN DHCP client.
        let wan_mac = mac_of(wan);
        let mut client = DhcpClient::new(wan_mac, WAN_XID);

        // One DHCP server per LAN port, each sourcing replies from that port's
        // own MAC but sharing the single service IP. (For a bridged LAN you'd
        // share one lease pool instead of one-per-port.)
        let mut lan: Vec<(u16, MacAddr, DhcpServer)> = lan_ports
            .iter()
            .map(|&p| {
                let mac = mac_of(p);
                let server = DhcpServer::new(DhcpServerConfig {
                    server_ip,
                    server_mac: mac,
                    gateway: server_ip,
                    subnet_mask: subnet_mask.netmask(),
                    // advertise ourselves as the DNS server in addition to the upstream
                    // configured ones; this way clients get DNS resolution as soon as they have a lease.
                    dns: std::iter::once(server_ip)
                        .chain(config.dns.servers.clone())
                        .collect(),
                    lease_secs: LEASE_SECS,
                    pool_start,
                    pool_end,
                });
                (p, mac, server)
            })
            .collect();

        let mut scratch = [0u8; FRAME_MAX];

        // Kick off the WAN client (sends DISCOVER).
        if let Some(n) = client.poll(&mut scratch) {
            tx(wan, pool, &scratch[..n]);
        }

        let mut last_bound: Option<Ipv4Addr> = None;
        loop {
            // ---- WAN: drive the DHCP client ----
            for raw in rx_burst(wan) {
                // SAFETY: `raw` is a valid mbuf handed over by rx_burst.
                let Some(m) = (unsafe { Mbuf::from_raw(raw) }) else {
                    continue;
                };
                if let Some(dhcp) = m
                    .ethernet()
                    .and_then(|e| e.ipv4())
                    .and_then(|i| i.udp())
                    .and_then(|u| u.dhcp())
                {
                    client.on_receive(&dhcp);
                }
                // m dropped here -> mbuf freed.
            }
            // Advance the client (sends REQUEST after an OFFER).
            if client.bound_ip().is_none() {
                if let Some(n) = client.poll(&mut scratch) {
                    tx(wan, pool, &scratch[..n]);
                }
            } else if client.bound_ip() != last_bound {
                last_bound = client.bound_ip();
                println!("WAN address acquired: {}", last_bound.unwrap());
            }

            // ---- LAN: ARP + DHCP server ----
            for (p, mac, server) in lan.iter_mut() {
                for raw in rx_burst(*p) {
                    let Some(m) = (unsafe { Mbuf::from_raw(raw) }) else {
                        continue;
                    };
                    let data = m.data();

                    // ARP request for the service IP?
                    if let Some(n) = arp::respond(*mac, &[server_ip], data, &mut scratch) {
                        tx(*p, pool, &scratch[..n]);
                        continue;
                    }
                    // DHCP request?
                    if let Some(dhcp) = quicktcp::net::view::parse(data)
                        .and_then(|e| e.ipv4())
                        .and_then(|i| i.udp())
                        .and_then(|u| u.dhcp())
                        && let Some(n) = server.handle(&dhcp, &mut scratch)
                    {
                        tx(*p, pool, &scratch[..n]);
                    }
                }
            }
        }
    }

    /// Initialise EAL from this process's argv.
    fn eal_init() {
        let args: Vec<CString> = std::env::args()
            .map(|a| CString::new(a).expect("arg contained a NUL"))
            .collect();
        let mut argv: Vec<*mut core::ffi::c_char> =
            args.iter().map(|a| a.as_ptr() as *mut _).collect();
        // SAFETY: argc/argv are a valid vector outliving the call.
        let rc = unsafe { ffi::rte_eal_init(argv.len() as core::ffi::c_int, argv.as_mut_ptr()) };
        assert!(rc >= 0, "rte_eal_init failed: {rc}");
    }

    fn create_pool() -> *mut ffi::rte_mempool {
        let name = CString::new("mbuf_pool").unwrap();
        // SAFETY: valid name; standard pktmbuf pool parameters.
        let pool = unsafe {
            ffi::rte_pktmbuf_pool_create(
                name.as_ptr(),
                NUM_MBUFS,
                MBUF_CACHE,
                0,
                MBUF_DATA_ROOM,
                ffi::rte_socket_id() as core::ffi::c_int,
            )
        };
        assert!(!pool.is_null(), "rte_pktmbuf_pool_create failed");
        pool
    }

    fn mac_of(port: u16) -> MacAddr {
        // SAFETY: zeroed addr struct is filled by the call; port is valid.
        let mut addr: ffi::rte_ether_addr = unsafe { core::mem::zeroed() };
        unsafe { ffi::rte_eth_macaddr_get(port, &mut addr) };
        addr.addr_bytes
    }

    /// Receive a burst, returning the raw mbuf pointers (wrap each in `Mbuf`).
    fn rx_burst(port: u16) -> impl Iterator<Item = *mut ffi::rte_mbuf> {
        let mut bufs = [core::ptr::null_mut(); BURST];
        // SAFETY: `bufs` has room for `BURST` pointers.
        let n = unsafe { ffi::rte_eth_rx_burst(port, 0, bufs.as_mut_ptr(), BURST as u16) } as usize;
        bufs.into_iter().take(n)
    }

    /// Allocate an mbuf, copy `frame` into it, and transmit on `port` queue 0.
    fn tx(port: u16, pool: *mut ffi::rte_mempool, frame: &[u8]) {
        // SAFETY: `pool` is a live mbuf pool; `append`'d bytes are written
        // before transmit; on failure we reclaim the mbuf so it isn't leaked.
        unsafe {
            let Some(mut m) = Mbuf::alloc(pool) else {
                return;
            };
            let Some(dst) = m.append(frame.len() as u16) else {
                return; // no tailroom
            };
            dst.copy_from_slice(frame);

            let mut raw = m.into_raw();
            let sent = ffi::rte_eth_tx_burst(port, 0, &mut raw, 1);
            if sent == 0 {
                // Not transmitted: take ownership back so Drop frees it.
                let _ = Mbuf::from_raw(raw);
            }
        }
    }
}
