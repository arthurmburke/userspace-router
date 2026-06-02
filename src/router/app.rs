//! Global contexts that are shared across all worker threads. This includes the neighbor cache, FDB,
//! DHCP client + server and ports.

use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering},
    },
    time::Instant,
};

use crate::{
    dpdk::{mbuf::Mbuf, port::Port},
    net::{ethernet::MacAddr, util::format_mac},
    router::{
        dhcp::{DhcpServer, SharedDhcpClient},
        fdb::SharedFdb,
        neighbor::{SharedNeighbor, Tick},
    },
};

/// Max Ethernet frame we build into per-iteration scratch buffers.
const FRAME_MAX: usize = 1518;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    /// `signal(2)` — install a process-wide handler. We use it to flip
    /// [`SHUTDOWN`] on SIGINT so every worker drops out of its poll loop and
    /// the main thread can run a clean `rte_eal_*` teardown instead of being
    /// killed by the default handler mid-burst.
    ///
    /// # SAFETY
    /// Must only be called from the main thread before any worker threads are
    /// spawned: `signal` itself is process-wide, but the handler we install
    /// touches `SHUTDOWN` from arbitrary signal-delivery contexts.
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
}

extern "C" fn handle_sigint(_: i32) {
    // `Release` so the workers' `Acquire` load in `run()` synchronises with
    // anything the main thread had published before the signal arrived. Not
    // strictly necessary for a single flag, but cheap and unambiguous.
    SHUTDOWN.store(true, Ordering::Release);
}

const SIGINT: i32 = 2;

pub fn setup_sigint_handler() {
    // SAFETY: see [`signal`].
    unsafe {
        signal(SIGINT, handle_sigint);
    }
}

/// Whether a shutdown has been requested (by SIGINT or otherwise). Visible to
/// the main runtime so it can decide whether to drain workers or bail.
pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::Acquire)
}

unsafe extern "C" fn run(arg: *mut std::os::raw::c_void) -> std::os::raw::c_int {
    // SAFETY: `arg` is the `Box::into_raw` pointer from `launch_worker`; this
    // reclaims ownership so the `WorkerCtx` (and its `Arc<AppCtx>`) is dropped
    // when the worker exits.
    let ctx = unsafe { Box::from_raw(arg as *mut WorkerCtx) };
    ctx.run();
    0
}

/// Launches a worker on the provided `lcore`.
pub fn launch_worker(lcore: u32, app: Arc<AppCtx>) {
    let ctx = Box::new(WorkerCtx { lcore, app });
    let ctx_ptr = Box::into_raw(ctx) as *mut std::os::raw::c_void;
    // SAFETY: `ctx_ptr` is a valid `Box`'d `WorkerCtx`; `rte_eal_remote_launch`
    // takes ownership for the lifetime of the worker.
    unsafe {
        crate::dpdk::ffi::rte_eal_remote_launch(Some(run), ctx_ptr, lcore);
    }
}

pub struct WorkerCtx {
    lcore: u32,
    app: Arc<AppCtx>,
}

impl WorkerCtx {
    pub fn new(lcore: u32, app: Arc<AppCtx>) -> Self {
        Self { lcore, app }
    }

    pub fn run(&self) {
        self.app.run(self.lcore);
    }
}

pub struct WanPortCtx {
    port: Port,
    neighbors: SharedNeighbor<Mbuf>,
    dhcp: SharedDhcpClient,
    /// Latched once the WAN DHCP lease binds
    bound: AtomicU32,
}

impl WanPortCtx {
    pub fn new(port: Port, neighbors: SharedNeighbor<Mbuf>, dhcp: SharedDhcpClient) -> Self {
        Self {
            port,
            neighbors,
            dhcp,
            bound: AtomicU32::new(0), // 0 indicates not bound (e.g. UNSPECIFIED)
        }
    }
}

pub struct LanPortCtx {
    port: Port,
    neighbors: SharedNeighbor<Mbuf>,
    dhcp: DhcpServer,
}

impl LanPortCtx {
    pub fn new(port: Port, neighbors: SharedNeighbor<Mbuf>, dhcp: DhcpServer) -> Self {
        Self {
            port,
            neighbors,
            dhcp,
        }
    }
}

pub enum PortCtx {
    Wan(WanPortCtx),
    Lan(LanPortCtx),
}

pub struct AppCtx {
    server_ip: Ipv4Addr,
    server_mac: MacAddr,
    fdb: SharedFdb<Mbuf>,
    ports: Vec<PortCtx>,
    /// Process-wide reference time. Captured once in `new` and shared by every
    /// worker so [`Tick`] values are consistent across cores — the neighbor
    /// table's retransmit / aging logic depends on a single monotonic origin.
    start: Instant,
}

impl AppCtx {
    pub fn new(
        server_ip: Ipv4Addr,
        server_mac: MacAddr,
        fdb: SharedFdb<Mbuf>,
        ports: Vec<PortCtx>,
    ) -> Self {
        Self {
            server_ip,
            server_mac,
            fdb,
            ports,
            start: Instant::now(),
        }
    }

    pub fn run(&self, lcore: u32) {
        while !SHUTDOWN.load(Ordering::Acquire) {
            // One time source per iteration: drives ARP request stamps,
            // retransmit decisions, and cache aging.
            let now = Tick::ms(self.start.elapsed().as_millis() as u64);

            for port in &self.ports {
                self.drive(now, lcore, port);
            }
        }
    }

    /// Drive a single rx/tx cycle for a port. This may be a WAN or LAN port.
    fn drive(&self, now: Tick, lcore: u32, port: &PortCtx) {
        match port {
            PortCtx::Wan(ctx) => self.drive_wan(now, lcore, ctx),
            PortCtx::Lan(ctx) => self.drive_lan(now, lcore, ctx),
        }
    }

    fn drive_wan(&self, now: Tick, lcore: u32, wan: &WanPortCtx) {
        let mut scratch: [u8; 1518] = [0u8; FRAME_MAX];
        for m in wan.port.receive(lcore) {
            if let Some(eth) = m.ethernet() {
                // Update FDB, forwarding any packets that may have been pending to the correct destination.
                if let Some(packets) = self.fdb.insert(eth.header().src, wan.port.port_id()) {
                    for q in packets {
                        if !wan.port.transmit_mbuf(lcore, q) {
                            eprintln!(
                                "[ERROR]: failed to send packet to address {}",
                                format_mac(&eth.header().src)
                            );
                        }
                    }
                }

                if let Some(arp_pkt) = eth.arp() {
                    if !arp_pkt.sender_ip().is_unspecified()
                        && let Some((mac_resolved, drained)) =
                            wan.neighbors.on_arp(arp_pkt.sender_ip(), arp_pkt.sha, now)
                    {
                        for mut q in drained {
                            super::worker::set_ethernet(
                                &mut q,
                                wan.port.info().ether_addr,
                                mac_resolved,
                            );
                            if !wan.port.transmit_mbuf(lcore, q) {
                                eprintln!(
                                    "[ERROR]: failed to send packet to address {}",
                                    format_mac(&mac_resolved)
                                );
                            }
                        }
                    }

                    if !arp_pkt.target_ip().is_unspecified()
                        && let Some((mac_resolved, drained)) =
                            wan.neighbors.on_arp(arp_pkt.target_ip(), arp_pkt.tha, now)
                    {
                        for mut q in drained {
                            super::worker::set_ethernet(
                                &mut q,
                                wan.port.info().ether_addr,
                                mac_resolved,
                            );
                            if !wan.port.transmit_mbuf(lcore, q) {
                                eprintln!(
                                    "[ERROR]: failed to send packet to address {}",
                                    format_mac(&mac_resolved)
                                );
                            }
                        }
                    }
                }
            }

            if let Some(dhcp) = m
                .ethernet()
                .and_then(|e| e.ipv4())
                .and_then(|i| i.udp())
                .and_then(|u| u.dhcp())
            {
                wan.dhcp.on_receive(&dhcp);
            }
        }

        if let Some(wan_ip) = wan.dhcp.bound_ip() {
            let wip32 = u32::from(wan_ip);

            // Only act on the bind transition. Without this every iteration
            // would re-set the neighbor IP and re-emit the bind log line.
            let old = wan.bound.swap(wip32, Ordering::AcqRel);

            if old != wip32 {
                wan.neighbors.set_our_ip(wan_ip);
                eprintln!("[INFO]: WAN address assigned: {wan_ip}");
            }
        } else if let Some(n) = wan.dhcp.poll(&mut scratch)
            && !wan.port.transmit_frame(lcore, &scratch[..n])
        {
            eprintln!("[ERROR]: failed to drive one iteration of WAN DHCP client");
        }
    }

    fn drive_lan(&self, now: Tick, lcore: u32, lan: &LanPortCtx) {
        let mut scratch: [u8; 1518] = [0u8; FRAME_MAX];

        for m in lan.port.receive(lcore) {
            let data = m.data();

            // Learn from any ARP traffic on this LAN.
            if let Some(eth) = crate::net::view::parse(data) {
                // Handle ARP packets.
                if let Some(arp) = eth.arp() {
                    // Reserve the sender's address in the DHCP pool.
                    // Every ARP frame is a "this address is in use" claim
                    // — covers statically-assigned hosts, prior leases we
                    // missed, and gratuitous ARPs. `reserve` is a no-op if
                    // the address isn't currently free, so calling it for
                    // every observed sender is safe and cheap.
                    lan.dhcp.reserve(arp.sender_ip());

                    // Check if this sender had a different IP in our ARP table before. If it did, release
                    // that IP back to the pool.
                    if let Some(old_ip) = lan.neighbors.reverse_lookup(arp.sha)
                        && old_ip != arp.sender_ip()
                        && lan.dhcp.start() <= old_ip
                        && old_ip <= lan.dhcp.end()
                    {
                        lan.dhcp.release(old_ip);
                    }

                    // Learn from any ARP traffic on the LAN segment (request *or*
                    // reply — the sender mapping is always informative).
                    if let Some(arp_pkt) = eth.arp() {
                        if let Some((mac_resolved, drained)) =
                            lan.neighbors.on_arp(arp_pkt.sender_ip(), arp_pkt.sha, now)
                        {
                            for mut q in drained {
                                super::worker::set_ethernet(
                                    &mut q,
                                    lan.port.info().ether_addr,
                                    mac_resolved,
                                );
                                lan.port.transmit_mbuf(lcore, q);
                            }
                        }

                        if !arp_pkt.target_ip().is_unspecified()
                            && let Some((mac_resolved, drained)) =
                                lan.neighbors.on_arp(arp_pkt.target_ip(), arp_pkt.tha, now)
                        {
                            for mut q in drained {
                                super::worker::set_ethernet(
                                    &mut q,
                                    lan.port.info().ether_addr,
                                    mac_resolved,
                                );
                                lan.port.transmit_mbuf(lcore, q);
                            }
                        }

                        let tip = arp.target_ip();
                        if tip != self.server_ip && arp.is_request() && eth.header().is_broadcast()
                        {
                            // Flood the request to every *other* LAN port so
                            // the bridged segment behaves like one broadcast
                            // domain. Comparing port IDs (not the filtered
                            // iterator's enumeration index) is what actually
                            // identifies "the port we received this on".
                            let src_port = lan.port.port_id();
                            for ctx in self.ports.iter().filter_map(|p| match p {
                                PortCtx::Lan(ctx) => Some(ctx),
                                _ => None,
                            }) {
                                if ctx.port.port_id() != src_port
                                    && !ctx.port.transmit_frame(lcore, data)
                                {
                                    eprintln!(
                                        "[ERROR]: failed to forward ARP request for {} to LAN port {}",
                                        tip,
                                        ctx.port.port_id()
                                    );
                                }
                            }
                        } else if tip == self.server_ip && arp.is_request() {
                            // We are `target`; reply to the requester (its MAC + IP from the request).
                            if let Some(n) = crate::net::arp::build_reply(
                                &mut scratch,
                                self.server_mac,
                                self.server_ip,
                                arp.sha,
                                arp.sender_ip(),
                            ) {
                                lan.port.transmit_frame(lcore, &scratch[..n]);
                            }
                        }
                    }
                }

                if let Some(dhcp) = eth.ipv4().and_then(|i| i.udp()).and_then(|u| u.dhcp()) {
                    if let Some(n) = lan.dhcp.handle(&dhcp, &mut scratch) {
                        if !lan.port.transmit_frame(lcore, &scratch[..n]) {
                            eprintln!(
                                "[ERROR]: failed to drive one iteration of LAN DHCP server on port {}",
                                lan.port.port_id()
                            );
                        }
                    }
                }
            }
        }
    }
}
