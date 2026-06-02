//! userspace_router router runtime.
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
    use userspace_router::dpdk::lcore::LcoreIter;
    use userspace_router::dpdk::mbuf::Mbuf;
    use userspace_router::dpdk::mempool::{MemPool, SharedMemPool};
    use userspace_router::dpdk::port::{self, Port, PortConfig};
    use userspace_router::dpdk::{self, ffi};
    use userspace_router::router::app::{self, AppCtx, LanPortCtx, PortCtx, WanPortCtx, launch_worker};
    use userspace_router::router::conf::{InterfaceRole, RouterConfig};
    use userspace_router::router::dhcp::{DhcpClient, DhcpServer, DhcpServerConfig, SharedDhcpClient};
    use userspace_router::router::fdb::SharedFdb;
    use userspace_router::router::leases::SharedLeases;
    use userspace_router::router::neighbor::SharedNeighbor;
    use userspace_router::router::pool::SharedAddressPool;
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::io::Read;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::sync::Arc;

    /// Per-port RX/TX descriptor ring size.
    const RING: u16 = 1024;
    /// Number of mbufs in the pool (a Mersenne prime, per DPDK convention).
    const NUM_MBUFS: u32 = 8191;
    /// Per-core mbuf cache size.
    const MBUF_CACHE: u32 = 256;
    /// mbuf data room: default 2048 payload + 128 headroom.
    const MBUF_DATA_ROOM: u16 = 2048 + 128;

    /// LAN DHCP lease length handed out by the server.
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

        // Find the WAN port based on the config.
        let wan_port_name = config
            .interfaces
            .iter()
            .find(|i| i.role == InterfaceRole::Wan)
            .map(|i| i.name.clone())
            .expect("WAN port not configured");

        let wan_id = get_port_id(&wan_port_name);

        let lan_port_names = config
            .interfaces
            .iter()
            .filter(|i| i.role == InterfaceRole::Lan)
            .map(|i| i.name.clone())
            .collect::<Vec<_>>();

        let lan_ids = lan_port_names
            .iter()
            .map(|name| get_port_id(name.as_str()))
            .collect::<Vec<_>>();

        assert!(
            lan_ids.iter().all(|&id| id != wan_id),
            "WAN port must be distinct from LAN ports"
        );

        assert!(!lan_ids.is_empty(), "at least one LAN port required");

        let port_ids = std::iter::once(wan_id)
            .chain(lan_ids.iter().copied())
            .collect::<Vec<_>>();

        // SAFETY: we're still single-core at this point, so there's no concurrency to worry about yet.
        let main_lcore = unsafe { ffi::rte_get_main_lcore() };

        // Filter to only enabled lcores and worker lcores
        let lcores = LcoreIter::new()
            .filter(|lcore| unsafe { ffi::rte_lcore_is_enabled(lcore.id) } != 0)
            .collect::<Vec<_>>();

        let nb_lcores = lcores.len() as u16;

        let mut socket_pools: BTreeMap<i32, SharedMemPool> = BTreeMap::new();

        let mut ports: BTreeMap<u16, Port> = BTreeMap::new();

        let mut load: BTreeMap<u32, usize> = lcores.iter().map(|lcore| (lcore.id, 0)).collect();

        // One mempool per NUMA socket touched by any port. DPDK's per-lcore
        // cache inside each pool already gives us per-core hot stashes, so we
        // don't need (or want) per-core pools — only per-socket placement.
        for &p in &port_ids {
            // Virtio etc. return -1 (SOCKET_ID_ANY); normalise to socket 0.
            let socket = unsafe { ffi::rte_eth_dev_socket_id(p) }.max(0);
            let pool = socket_pools
                .entry(socket)
                .or_insert_with(|| {
                    SharedMemPool::from(
                        MemPool::create(
                            &format!("MEMPOOL{}", socket),
                            NUM_MBUFS,
                            MBUF_CACHE,
                            MBUF_DATA_ROOM,
                            socket,
                        )
                        .expect("failed to create mempool"),
                    )
                })
                .clone();

            let port_setup = port::init_port(&PortConfig {
                port_id: p,
                nb_rx_queues: nb_lcores,
                nb_tx_queues: nb_lcores,
                rx_ring_size: RING,
                tx_ring_size: RING,
                mempool: pool.clone(),
            })
            .expect("port init");

            // Filter to lcores dedicated to this worker
            let mut dedicated_lcores = lcores
                .iter()
                .filter(|lcore| lcore.socket as i32 == socket)
                .map(|lcore| lcore.id)
                .collect::<Vec<_>>();

            // If there are no lcores that share a NUMA socket with this port, we choose
            // the lcore with the least load as the lcore assigned to this port
            if dedicated_lcores.is_empty() {
                let (lcore, lcore_load) = load
                    .iter_mut()
                    .min_by_key(|(_, l)| **l)
                    .expect("map is non-empty");
                *lcore_load += 1;
                dedicated_lcores.push(*lcore);
            }

            let port_info = dpdk::port::info(p).expect("failed to get port info");

            let port = Port::new(port_setup, port_info, pool, &dedicated_lcores);
            ports.insert(p, port);
        }

        // WAN DHCP client.
        let wan_port = ports.remove(&wan_id).expect("WAN port could not be found");
        let wan_mac = wan_port.info().ether_addr;
        let dhcp_client = SharedDhcpClient::from(DhcpClient::new(wan_mac, WAN_XID));
        // Shared neighbor table for the WAN segment (cloneable handle so each
        // future worker can hold its own reference to the same state). The
        // address starts unspecified; it's updated when the WAN DHCP lease
        // binds, below.
        let wan_neighbor: SharedNeighbor<Mbuf> =
            SharedNeighbor::new(wan_mac, Ipv4Addr::UNSPECIFIED);
        let wan_ctx = PortCtx::Wan(WanPortCtx::new(wan_port, wan_neighbor, dhcp_client));

        let address_pool = SharedAddressPool::new(pool_start, pool_end);
        // Reserve the server IP for ourselves so it doesn't get leased out. It may not be
        // in the pool but that's okay this is just a safety precaution.
        address_pool.reserve(server_ip);

        // One shared lease table across every LAN port: this is a bridged LAN
        // (one broadcast domain), so a client roaming between physical ports
        // must keep its lease. Each per-port `DhcpServer` clones this handle
        // and reads/writes the same bindings.
        let leases = SharedLeases::new();

        // One DHCP server per LAN port, each sourcing replies from that port's
        // own MAC but sharing the single service IP, address pool, and lease
        // table.
        //
        // `SharedNeighbor` is `Clone` so additional workers serving the same
        // LAN segment can hold their own handle to the same cache + pending
        // queue; today the runtime is single-core, but the wiring is forward-
        // compatible.
        let software_defined_addr = userspace_router::net::util::software_defined_mac(server_ip);
        let lan_neighbor = SharedNeighbor::<Mbuf>::new(software_defined_addr, server_ip);

        let lan: Vec<PortCtx> = ports
            .into_values()
            .map(|port| {
                let server = DhcpServer::new(
                    DhcpServerConfig {
                        server_ip,
                        server_mac: software_defined_addr,
                        gateway: server_ip,
                        subnet_mask: subnet_mask.netmask(),
                        // advertise ourselves as the DNS server in addition to the upstream
                        // configured ones; this way clients get DNS resolution as soon as they have a lease.
                        dns: std::iter::once(server_ip)
                            .chain(config.dns.servers.clone())
                            .collect(),
                        lease_secs: LEASE_SECS,
                    },
                    address_pool.clone(),
                    leases.clone(),
                );
                PortCtx::Lan(LanPortCtx::new(port, lan_neighbor.clone(), server))
            })
            .collect();

        let port_ctx = std::iter::once(wan_ctx)
            .chain(lan.into_iter())
            .collect::<Vec<_>>();

        // FDB table for forwarding within the LAN segment
        let fdb = SharedFdb::<Mbuf>::new(128);

        let ctx = Arc::new(AppCtx::new(server_ip, software_defined_addr, fdb, port_ctx));

        // Handle CTRL-C gracefully so we can stop ports and run rte_eal_cleanup
        // instead of being killed by the default signal handler mid-burst.
        app::setup_sigint_handler();

        for lcore in &lcores {
            if lcore.id != main_lcore {
                // SAFETY: every worker holds its own `Arc<AppCtx>`; all interior
                // state shared with the main thread is behind locks or atomics
                // (`SharedNeighbor`, `SharedFdb`, `SharedDhcpClient`, the per-TX
                // queue spinlocks on `Port`, `WanPortCtx::bound`), and the
                // per-lcore RX-queue assignment guarantees no two lcores poll
                // the same hardware queue.
                let ctx_clone = Arc::clone(&ctx);
                if let Err(rc) = launch_worker(lcore.id, ctx_clone) {
                    eprintln!(
                        "[WARN]: rte_eal_remote_launch(lcore={}) failed: {rc}; running without it",
                        lcore.id
                    );
                }
            }
        }

        // The main lcore is itself a worker. It returns once SHUTDOWN is set.
        ctx.run(main_lcore);

        // Wait for every other lcore to exit its poll loop before tearing the
        // EAL down — workers may still be holding `Mbuf`s that must drop back
        // into their mempool before `rte_eal_cleanup` runs.
        for lcore in &lcores {
            if lcore.id != main_lcore {
                // SAFETY: `rte_eal_wait_lcore` blocks until the worker returns.
                unsafe { ffi::rte_eal_wait_lcore(lcore.id) };
            }
        }

        // Stop and close every port before cleanup so the NIC stops DMA'ing
        // into mbufs we're about to free. Errors here are non-fatal — we still
        // want to attempt cleanup.
        for &p in &port_ids {
            // SAFETY: ports were configured + started in this same process;
            // both calls are no-ops if the port is already stopped/closed.
            let rc = unsafe { ffi::rte_eth_dev_stop(p) };
            if rc < 0 {
                eprintln!("[WARN]: rte_eth_dev_stop(port={p}) failed: {rc}");
            }
            let rc = unsafe { ffi::rte_eth_dev_close(p) };
            if rc < 0 {
                eprintln!("[WARN]: rte_eth_dev_close(port={p}) failed: {rc}");
            }
        }

        // Drop everything that still references EAL-owned memory (ports' mbuf
        // pool handles, then the `socket_pools` map itself) BEFORE
        // `rte_eal_cleanup`. Otherwise the last `SharedMemPool` clone would
        // drop *after* cleanup and call `rte_mempool_free` on freed memory.
        drop(ctx);
        drop(socket_pools);

        if unsafe { ffi::rte_eal_cleanup() } != 0 {
            eprintln!("rte_eal_cleanup failed");
        }
    }

    fn get_port_id(name: &str) -> u16 {
        let mut port_id = 0;
        unsafe {
            let c_str = CString::new(name.to_string()).unwrap();
            let ret = ffi::rte_eth_dev_get_port_by_name(c_str.as_ptr(), &mut port_id);
            assert_eq!(ret, 0, "failed to find port with name '{}'", name);
        }
        port_id
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
}
