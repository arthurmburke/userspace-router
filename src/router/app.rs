//! Global contexts that are shared across all worker threads. This includes the neighbor cache, FDB,
//! DHCP client + server and ports.

use std::{
    net::Ipv4Addr,
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Instant,
};

/// Sentinel `signal(2)` returns when handler installation failed
/// (`SIG_ERR == (sighandler_t) -1`).
const SIG_ERR: usize = usize::MAX;

use crate::{
    dpdk::{mbuf::Mbuf, port::Port},
    net::{ethernet::MacAddr, util::format_mac},
    router::{
        conntrack::SharedConnTrack,
        dhcp::{DhcpServer, SharedDhcpClient},
        fdb::SharedFdb,
        nat::SharedNat,
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

/// Signal numbers we install [`handle_sigint`] for. Both should trigger the
/// same cleanup path — Ctrl-C, container stop, systemd `Restart`, etc.
const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

/// Install our shutdown handler for SIGINT and SIGTERM. Returns the number of
/// handlers that failed to install (0 on success).
///
/// SAFETY: must run on the main thread before any worker is spawned.
pub fn setup_sigint_handler() -> usize {
    let mut failed = 0;
    for sig in [SIGINT, SIGTERM] {
        // SAFETY: see [`signal`].
        let prev = unsafe { signal(sig, handle_sigint) };
        if prev == SIG_ERR {
            eprintln!("[WARN]: signal({sig}) failed; default handler will kill us mid-burst");
            failed += 1;
        }
    }
    failed
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
    // Unwinding past an `extern "C"` boundary is undefined behaviour, so catch
    // any panic in the worker, log it, request shutdown, and return non-zero.
    // The main thread will see SHUTDOWN and unwind its own loop cleanly.
    let lcore = ctx.lcore;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| ctx.run()));
    match result {
        Ok(()) => 0,
        Err(_) => {
            eprintln!("[ERROR]: worker on lcore {lcore} panicked; requesting shutdown");
            SHUTDOWN.store(true, Ordering::Release);
            1
        }
    }
}

/// Launches a worker on the provided `lcore`. Returns `Ok(())` on success or
/// the raw `rte_eal_remote_launch` error code on failure (e.g. `-EBUSY` if the
/// lcore is already running). On failure the `WorkerCtx` is reclaimed so its
/// `Arc<AppCtx>` doesn't leak.
pub fn launch_worker(lcore: u32, app: Arc<AppCtx>) -> Result<(), i32> {
    let ctx = Box::new(WorkerCtx { lcore, app });
    let ctx_ptr = Box::into_raw(ctx) as *mut std::os::raw::c_void;
    // SAFETY: `ctx_ptr` is a valid `Box`'d `WorkerCtx`; on success
    // `rte_eal_remote_launch` takes ownership for the lifetime of the worker.
    let rc = unsafe { crate::dpdk::ffi::rte_eal_remote_launch(Some(run), ctx_ptr, lcore) };
    if rc != 0 {
        // SAFETY: launch failed, so the box was never handed off — reclaim it
        // here to drop the `Arc<AppCtx>` ref and free the heap allocation.
        drop(unsafe { Box::from_raw(ctx_ptr as *mut WorkerCtx) });
        Err(rc)
    } else {
        Ok(())
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
    /// Latched once the WAN DHCP lease binds. Stored as `u32::from(ip)` so we
    /// can detect lease changes (rebind to a different IP) atomically. `0`
    /// means "not yet bound".
    bound: AtomicU32,
    /// WAN next-hop (upstream gateway) IP learned from the DHCP lease. The
    /// egress path resolves this against [`Self::neighbors`] to find the
    /// gateway MAC. `0` means "not yet known".
    gateway: AtomicU32,
}

impl WanPortCtx {
    pub fn new(port: Port, neighbors: SharedNeighbor<Mbuf>, dhcp: SharedDhcpClient) -> Self {
        Self {
            port,
            neighbors,
            dhcp,
            bound: AtomicU32::new(0),
            gateway: AtomicU32::new(0),
        }
    }

    /// Currently-known WAN gateway IP, or `None` until the DHCP lease binds.
    pub fn gateway_ip(&self) -> Option<Ipv4Addr> {
        match self.gateway.load(Ordering::Acquire) {
            0 => None,
            n => Some(Ipv4Addr::from(n)),
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
    /// The IP address the router responds to on the LAN. This is mostly cosmetic
    /// (e.g. for ARP replies and DHCP options), but it also needs to be consistent
    /// across workers so the FDB learns a single MAC → port mapping for the router
    /// rather than one per worker.
    server_ip: Ipv4Addr,
    /// The software defined MAC address that the router responds to on the LAN.
    /// This is mostly cosmetic (e.g. for ARP replies and DHCP options),
    /// but it also needs to be consistent across workers so the FDB learns a
    /// single MAC → port mapping for the router rather than one per worker.
    server_mac: MacAddr,
    /// Per-shard FDB sahred across workers. Every port learns into the same FDB.
    /// On an FDB hit, the frame is forwarded to the port the MAC was learned on (zero-copy).
    /// On an FDB miss, the frame is flooded to all ports except the ingress port.
    fdb: SharedFdb,
    /// Per-shard NAT table shared across workers. `wan_ip` inside is updated
    /// from the WAN DHCP lease at bind transition; until that happens the
    /// egress path no-ops (translate returns `None` and we drop the packet).
    nat: SharedNat,
    /// Stateful TCP firewall. WAN-side packets are dropped unless they match a
    /// flow we previously saw originate from inside (and only TCP flows are
    /// tracked — UDP/ICMP/etc. ingress is refused outright).
    conntrack: SharedConnTrack,
    ports: Vec<PortCtx>,
    /// Process-wide reference time. Captured once in `new` and shared by every
    /// worker so [`Tick`] values are consistent across cores — the neighbor
    /// table's retransmit / aging logic depends on a single monotonic origin.
    start: Instant,
    /// The lcore designated to run neighbor-table sweeps. Only one worker should
    /// retransmit ARP / age the cache; otherwise every worker would race to do
    /// the same work each iteration.
    sweeper_lcore: u32,
    /// Throttle the sweep to at most once per [`SWEEP_INTERVAL_MS`]. Storing the
    /// last-sweep tick lets the sweeper skip work the rest of the time.
    last_sweep_ms: AtomicU32,
}

/// Minimum gap between neighbor-table sweeps on the sweeper lcore.
const SWEEP_INTERVAL_MS: u64 = 250;

impl AppCtx {
    pub fn new(
        server_ip: Ipv4Addr,
        server_mac: MacAddr,
        fdb: SharedFdb,
        nat: SharedNat,
        conntrack: SharedConnTrack,
        ports: Vec<PortCtx>,
        sweeper_lcore: u32,
    ) -> Self {
        Self {
            server_ip,
            server_mac,
            fdb,
            nat,
            conntrack,
            ports,
            start: Instant::now(),
            sweeper_lcore,
            last_sweep_ms: AtomicU32::new(0),
        }
    }

    pub fn run(&self, lcore: u32) {
        let is_sweeper = lcore == self.sweeper_lcore;
        while !SHUTDOWN.load(Ordering::Acquire) {
            // One time source per iteration: drives ARP request stamps,
            // retransmit decisions, and cache aging.
            let now = Tick::ms(self.start.elapsed().as_millis() as u64);

            for port in &self.ports {
                self.drive(now, lcore, port);
            }

            // The sweeper lcore drives retransmits + aging on every port's
            // neighbor table. Throttled so we don't grab the write lock every
            // poll iteration just to discover no time has passed.
            if is_sweeper {
                self.maybe_sweep(now, lcore);
            }
        }
    }

    /// Run a neighbor-table sweep on every port if at least `SWEEP_INTERVAL_MS`
    /// has elapsed since the previous sweep. Drops any packets that the
    /// neighbor table hands back (target never replied to `MAX_REQUEST_ATTEMPTS`
    /// ARP retries).
    fn maybe_sweep(&self, now: Tick, lcore: u32) {
        let last = self.last_sweep_ms.load(Ordering::Relaxed) as u64;
        // `Tick(0)` is "fresh"; treat last==0 as "never swept" so the first
        // sweep happens immediately rather than after the interval elapses.
        if last != 0 && now.0.saturating_sub(last) < SWEEP_INTERVAL_MS {
            return;
        }
        self.last_sweep_ms
            .store(now.0.min(u32::MAX as u64) as u32, Ordering::Relaxed);
        for port in &self.ports {
            match port {
                PortCtx::Wan(wan) => {
                    let _dropped = wan.neighbors.sweep(now, |frame| {
                        // Fire-and-forget ARP retransmit; per-queue TX lock is
                        // held only briefly.
                        wan.port.transmit_frame(lcore, frame);
                    });
                }
                PortCtx::Lan(lan) => {
                    let _dropped = lan.neighbors.sweep(now, |frame| {
                        lan.port.transmit_frame(lcore, frame);
                    });
                }
            }
        }

        // Same cadence as the neighbor sweep — both want to age out idle
        // state; both are write-locked but short.
        self.conntrack.sweep(now);
    }

    /// Drive a single rx/tx cycle for a port. This may be a WAN or LAN port.
    fn drive(&self, now: Tick, lcore: u32, port: &PortCtx) {
        match port {
            PortCtx::Wan(ctx) => self.drive_wan(now, lcore, ctx),
            PortCtx::Lan(ctx) => self.drive_lan(now, lcore, ctx),
        }
    }

    fn drive_wan(&self, now: Tick, lcore: u32, wan: &WanPortCtx) {
        let mut scratch: [u8; FRAME_MAX] = [0u8; FRAME_MAX];
        for m in wan.port.receive(lcore) {
            // ---- Phase 1: classify ----------------------------------------
            let class = {
                let data = m.data();
                let Some(eth) = crate::net::view::parse(data) else {
                    continue;
                };
                let h = eth.header();
                WanClass {
                    src_mac: h.src,
                    is_arp: eth.is_arp(),
                    is_ipv4: eth.is_ipv4(),
                }
            };

            // ---- Phase 2: learn -------------------------------------------
            // Symmetric with the LAN side: record the sender MAC behind this
            // port. The WAN side rarely sees a flood of distinct MACs (the
            // gateway is the only sender on a typical link), so this is
            // mostly a no-op once steady-state.
            self.fdb.insert(class.src_mac, wan.port.port_id());

            // ---- Phase 3: handle ------------------------------------------
            if class.is_arp {
                self.handle_wan_arp(now, lcore, wan, &m);
                continue;
            }

            // Feed any DHCP message to the WAN client state machine. DHCP is
            // the control plane for our own WAN address — it isn't NAT'd.
            let is_dhcp = m
                .ethernet()
                .and_then(|e| e.ipv4())
                .and_then(|i| i.udp())
                .and_then(|u| u.dhcp())
                .is_some();
            if is_dhcp {
                if let Some(dhcp) = m
                    .ethernet()
                    .and_then(|e| e.ipv4())
                    .and_then(|i| i.udp())
                    .and_then(|u| u.dhcp())
                {
                    wan.dhcp.on_receive(&dhcp);
                }
                continue;
            }

            // Anything else IPv4: try reverse NAT and forward into the LAN.
            if class.is_ipv4 {
                self.wan_ingress_nat(now, lcore, wan, m);
            }
            // Non-ARP/non-IPv4 (IPv6, etc.) drops as `m` goes out of scope.
        }

        if let Some(wan_ip) = wan.dhcp.bound_ip() {
            let wip32 = u32::from(wan_ip);

            // Only act on the bind transition. Without this every iteration
            // would re-set the neighbor IP / NAT WAN IP and re-emit logs.
            let old = wan.bound.swap(wip32, Ordering::AcqRel);

            if old != wip32 {
                wan.neighbors.set_our_ip(wan_ip);
                self.nat.set_wan_ip(wan_ip);
                eprintln!("[INFO]: WAN address assigned: {wan_ip}");

                // Pull the gateway out of the lease (if the upstream included a
                // Router option) and seed an ARP resolve so the egress path
                // doesn't take the cache-miss hit on the first translated
                // packet. `resolve` with a dummy packet would queue it; we just
                // want the ARP probe, so build it directly.
                if let Some(gw) = wan.dhcp.lease().and_then(|l| l.gateway) {
                    wan.gateway.store(u32::from(gw), Ordering::Release);
                    eprintln!("[INFO]: WAN gateway: {gw}");
                    let mut arp = [0u8; crate::net::arp::FRAME_LEN];
                    if crate::net::arp::build_request(
                        &mut arp,
                        wan.port.info().ether_addr,
                        wan_ip,
                        gw,
                    )
                    .is_some()
                    {
                        wan.port.transmit_frame(lcore, &arp);
                    }
                }
            }
        } else if let Some(n) = wan.dhcp.poll(&mut scratch)
            && !wan.port.transmit_frame(lcore, &scratch[..n])
        {
            eprintln!("[ERROR]: failed to drive one iteration of WAN DHCP client");
        }
    }

    fn drive_lan(&self, now: Tick, lcore: u32, lan: &LanPortCtx) {
        let mut scratch: [u8; FRAME_MAX] = [0u8; FRAME_MAX];

        for m in lan.port.receive(lcore) {
            // ---- Phase 1: classify ----------------------------------------
            // Pull out just enough header info to route the frame, then drop
            // the view so we're free to move `m` into ownership-taking paths
            // (FDB resolve, neighbor.resolve) below.
            let class = {
                let data = m.data();
                let Some(eth) = crate::net::view::parse(data) else {
                    continue;
                };
                let h = eth.header();
                LanClass {
                    src_mac: h.src,
                    dst_mac: h.dst,
                    is_broadcast: h.is_broadcast(),
                    is_arp: eth.is_arp(),
                    is_ipv4: eth.is_ipv4(),
                }
            };

            // ---- Phase 2: learn the sender --------------------------------
            // Record `src_mac → this port` so subsequent unicast frames to
            // this MAC skip the flood. The lookup is read-only — unknown
            // unicast just floods, so we don't need a per-MAC pending queue.
            self.fdb.insert(class.src_mac, lan.port.port_id());

            // ---- Phase 3: route -------------------------------------------
            if class.is_arp {
                self.handle_lan_arp(now, lcore, lan, &m, &mut scratch);
            } else if class.is_ipv4 {
                self.handle_lan_ipv4(now, lcore, lan, m, &class, &mut scratch);
            }
            // Anything else (IPv6, VLAN, LLDP, ...) drops on the floor when
            // `m` goes out of scope.
        }
    }

    /// ARP handling on a LAN port: reserve/release in the DHCP pool, learn the
    /// sender mapping, then either flood (foreign request) or reply (request
    /// for the router IP).
    fn handle_lan_arp(
        &self,
        now: Tick,
        lcore: u32,
        lan: &LanPortCtx,
        m: &Mbuf,
        scratch: &mut [u8],
    ) {
        let data = m.data();
        let Some(eth) = crate::net::view::parse(data) else {
            return;
        };
        let Some(arp) = eth.arp() else {
            return;
        };

        // Every ARP is a "this address is in use" claim — reserve the sender
        // in the DHCP pool so we never lease that IP out to someone else.
        lan.dhcp.reserve(arp.sender_ip());

        // If this MAC previously held a different IP from our pool, release
        // the stale one so it can be re-leased.
        if let Some(old_ip) = lan.neighbors.reverse_lookup(arp.sha)
            && old_ip != arp.sender_ip()
            && lan.dhcp.start() <= old_ip
            && old_ip <= lan.dhcp.end()
        {
            lan.dhcp.release(old_ip);
        }

        // Learn the sender mapping; drain anything that was waiting on it.
        if let Some((mac_resolved, drained)) =
            lan.neighbors.on_arp(arp.sender_ip(), arp.sha, now)
        {
            for mut q in drained {
                super::worker::set_ethernet(&mut q, lan.port.info().ether_addr, mac_resolved);
                lan.port.transmit_mbuf(lcore, q);
            }
        }

        // Replies also teach us about the target.
        if !arp.target_ip().is_unspecified()
            && let Some((mac_resolved, drained)) =
                lan.neighbors.on_arp(arp.target_ip(), arp.tha, now)
        {
            for mut q in drained {
                super::worker::set_ethernet(&mut q, lan.port.info().ether_addr, mac_resolved);
                lan.port.transmit_mbuf(lcore, q);
            }
        }

        let tip = arp.target_ip();
        if tip != self.server_ip && arp.is_request() && eth.header().is_broadcast() {
            // Flood the request to every *other* LAN port so the bridged
            // segment behaves like one broadcast domain.
            let src_port = lan.port.port_id();
            for ctx in self.lan_ports() {
                if ctx.port.port_id() != src_port && !ctx.port.transmit_frame(lcore, data) {
                    eprintln!(
                        "[ERROR]: failed to forward ARP request for {} to LAN port {}",
                        tip,
                        ctx.port.port_id()
                    );
                }
            }
        } else if tip == self.server_ip && arp.is_request() {
            // We are `target`; reply to the requester directly.
            if let Some(n) = crate::net::arp::build_reply(
                scratch,
                self.server_mac,
                self.server_ip,
                arp.sha,
                arp.sender_ip(),
            ) {
                lan.port.transmit_frame(lcore, &scratch[..n]);
            }
        }
    }

    /// IPv4 handling on a LAN port. Takes ownership of `m` because some of the
    /// routing paths (FDB resolve, NAT egress queue) consume the mbuf.
    fn handle_lan_ipv4(
        &self,
        now: Tick,
        lcore: u32,
        lan: &LanPortCtx,
        m: Mbuf,
        class: &LanClass,
        scratch: &mut [u8],
    ) {
        // DHCP first: every DHCP message is unicast or broadcast IPv4/UDP that
        // the LAN server must handle, regardless of dst MAC.
        let is_dhcp = m
            .ethernet()
            .and_then(|e| e.ipv4())
            .and_then(|i| i.udp())
            .and_then(|u| u.dhcp())
            .is_some();
        if is_dhcp {
            // Re-parse so the view's borrow lifetime is local to this block.
            if let Some(dhcp) = m
                .ethernet()
                .and_then(|e| e.ipv4())
                .and_then(|i| i.udp())
                .and_then(|u| u.dhcp())
                && let Some(n) = lan.dhcp.handle(&dhcp, scratch)
                && !lan.port.transmit_frame(lcore, &scratch[..n])
            {
                eprintln!(
                    "[ERROR]: failed to drive one iteration of LAN DHCP server on port {}",
                    lan.port.port_id()
                );
            }
            return;
        }

        // Packets addressed to the router MAC are bound for the upstream
        // (LAN -> WAN) NAT egress path.
        if class.dst_mac == self.server_mac {
            self.lan_egress_nat(now, lcore, m);
            return;
        }

        // Broadcast / multicast (non-ARP): flood across the bridge to every
        // other LAN port. We pay a copy per port since each `transmit_frame`
        // allocates from that port's mempool.
        if class.is_broadcast {
            let src_port = lan.port.port_id();
            let data = m.data();
            for ctx in self.lan_ports() {
                if ctx.port.port_id() != src_port {
                    ctx.port.transmit_frame(lcore, data);
                }
            }
            return;
        }

        // Unicast: FDB hit -> forward to that port. Miss -> queue and flood
        // (unknown-unicast flood is what teaches every other LAN port about
        // the destination; the queue holds a copy in case we see the dst MAC
        // later via an unrelated frame). Skip looping the frame back onto the
        // ingress port — a host shouldn't see its own outbound traffic.
        self.transmit_to_mac_or_flood_except(lcore, class.dst_mac, m, Some(lan.port.port_id()));
    }

    /// LAN→WAN egress NAT path. **TCP only** — this router is a TCP-only NAT,
    /// matching the ingress firewall policy. Non-TCP egress (UDP/ICMP/...) is
    /// dropped at the boundary so the NAT port pool and conntrack table only
    /// hold useful state.
    ///
    /// Steps: parse 5-tuple + flags → update conntrack → translate (rewrites
    /// IP src + L4 src port + checksums) → resolve WAN gateway MAC → transmit.
    ///
    /// Drops `m` silently if:
    /// - there's no WAN port (config quirk),
    /// - DHCP hasn't bound yet (`nat.wan_ip == 0.0.0.0`) — the binding would
    ///   point at an unroutable source,
    /// - we don't yet know the gateway IP (DHCP didn't include a Router option),
    /// - the packet isn't IPv4 TCP,
    /// - the NAT port pool is exhausted,
    /// - or the neighbor pending queue for the gateway is full.
    ///
    /// On a neighbor cache miss the packet is queued in the WAN neighbor table
    /// and drained later by `drive_wan`'s `on_arp` branch; an ARP request
    /// frame is emitted alongside (on the first miss for the gateway).
    fn lan_egress_nat(&self, now: Tick, lcore: u32, mut m: Mbuf) {
        let Some(wan) = self.wan_port() else { return };
        let Some(gateway_ip) = wan.gateway_ip() else { return };
        if self.nat.wan_ip().is_unspecified() {
            return;
        }

        // Parse the pre-NAT TCP 5-tuple + flags. `None` here means "not TCP"
        // (UDP, ICMP, malformed, ...) — drop it; we don't translate non-TCP.
        let Some((int_ip, int_port, ext_ip, ext_port, flags)) =
            parse_tcp_tuple(m.data())
        else {
            return;
        };

        // Update conntrack with the *pre-NAT* internal endpoint. This is the
        // state the ingress side will look up via the same 5-tuple (the
        // internal endpoint stays the internal endpoint; only the external
        // address swaps sides for return traffic).
        self.conntrack
            .observe_egress(int_ip, int_port, ext_ip, ext_port, flags, now);

        // Now rewrite IP src + L4 src port + checksums in place.
        if self.nat.translate_egress(m.data_mut()).is_none() {
            return;
        }

        // Stamp the L2 source now (the destination gets filled in by the
        // resolve hit or the on_arp drain — whichever path the packet takes).
        let wan_mac = wan.port.info().ether_addr;

        let mut req_buf = [0u8; crate::net::arp::FRAME_LEN];
        use crate::router::neighbor::Action;
        match wan
            .neighbors
            .resolve(gateway_ip, m, &mut req_buf, now)
        {
            Action::Forward { mac, packet: mut p } => {
                super::worker::set_ethernet(&mut p, wan_mac, mac);
                if !wan.port.transmit_mbuf(lcore, p) {
                    eprintln!(
                        "[ERROR]: WAN tx_burst rejected NAT egress to {}",
                        format_mac(&mac)
                    );
                }
            }
            Action::Queued { request_len } => {
                // First miss for this target also synthesises an ARP request.
                if let Some(n) = request_len {
                    wan.port.transmit_frame(lcore, &req_buf[..n]);
                }
                // packet is queued in the neighbor table; it drains via
                // drive_wan's on_arp branch once the gateway replies.
            }
            Action::Drop { packet: _ } => {
                // Pending queue overflow for the gateway — drop.
            }
        }
    }

    /// Iterator over every LAN [`LanPortCtx`] this app owns.
    fn lan_ports(&self) -> impl Iterator<Item = &LanPortCtx> {
        self.ports.iter().filter_map(|p| match p {
            PortCtx::Lan(ctx) => Some(ctx),
            _ => None,
        })
    }

    /// Look up the LAN port with `port_id`, if any. Used by FDB-resolved
    /// forwarding to find the egress port from a hit.
    fn lan_port_by_id(&self, port_id: u16) -> Option<&LanPortCtx> {
        self.lan_ports().find(|p| p.port.port_id() == port_id)
    }

    /// The single WAN [`WanPortCtx`] this app owns, if any. Today the runtime
    /// enforces exactly one in `main.rs`; if that ever changes, callers will
    /// need to pick by routing-table lookup instead of "the WAN port".
    fn wan_port(&self) -> Option<&WanPortCtx> {
        self.ports.iter().find_map(|p| match p {
            PortCtx::Wan(ctx) => Some(ctx),
            _ => None,
        })
    }

    /// ARP handling on the WAN port: learn the sender (and target, in a
    /// reply) and drain any packets that were waiting on that resolution.
    /// Drained packets are NAT-translated egress traffic queued by
    /// `lan_egress_nat`; on drain we stamp the L2 header and transmit.
    fn handle_wan_arp(&self, now: Tick, lcore: u32, wan: &WanPortCtx, m: &Mbuf) {
        let Some(eth) = m.ethernet() else { return };
        let Some(arp_pkt) = eth.arp() else { return };

        if !arp_pkt.sender_ip().is_unspecified()
            && let Some((mac_resolved, drained)) =
                wan.neighbors.on_arp(arp_pkt.sender_ip(), arp_pkt.sha, now)
        {
            for mut q in drained {
                super::worker::set_ethernet(&mut q, wan.port.info().ether_addr, mac_resolved);
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
                super::worker::set_ethernet(&mut q, wan.port.info().ether_addr, mac_resolved);
                if !wan.port.transmit_mbuf(lcore, q) {
                    eprintln!(
                        "[ERROR]: failed to send packet to address {}",
                        format_mac(&mac_resolved)
                    );
                }
            }
        }
    }

    /// WAN→LAN ingress NAT path. **TCP only, and only flows we initiated**:
    /// every inbound packet must (a) be TCP and (b) match a conntrack entry
    /// previously opened by outbound LAN traffic. Everything else is dropped
    /// at the WAN boundary.
    ///
    /// Order matters: we parse the pre-NAT 5-tuple from the inbound packet
    /// (source = external peer; destination is our WAN IP + the NAT-allocated
    /// external port), call `translate_ingress` to get the internal endpoint,
    /// then check conntrack with the canonical (int, ext) key. If conntrack
    /// admits the packet we forward; otherwise we drop — yes, the frame's
    /// already been mutated by translate, but we're dropping it anyway.
    ///
    /// Drops `m` silently if:
    /// - the packet isn't IPv4 TCP (UDP/ICMP/IPv6/... are refused outright),
    /// - the NAT table has no binding for the destination port,
    /// - conntrack has no flow matching the 5-tuple (unsolicited probe / scan),
    /// - we have no LAN ports configured,
    /// - the LAN neighbor pending queue for the internal IP is full.
    fn wan_ingress_nat(&self, now: Tick, lcore: u32, _wan: &WanPortCtx, mut m: Mbuf) {
        // Phase 1: TCP filter + capture the external peer endpoint.
        // We need the pre-NAT src (peer) for the conntrack key; the pre-NAT
        // dst is our WAN IP (we don't need it explicitly). Flags advance the
        // conntrack state machine on the inbound side.
        let Some((ext_ip, ext_port, _our_wan_ip, _our_ext_port, flags)) =
            parse_tcp_tuple(m.data())
        else {
            return;
        };

        // Phase 2: reverse-NAT in place. After this the packet's dst is the
        // internal endpoint we want to deliver to.
        let Some(ingress) = self.nat.translate_ingress(m.data_mut()) else {
            return;
        };

        // Phase 3: conntrack check. Same canonical key as observe_egress —
        // internal endpoint stays internal regardless of direction.
        if !self
            .conntrack
            .check_ingress(ingress.dst_ip, ingress.dst_port, ext_ip, ext_port, flags, now)
        {
            // Unsolicited inbound TCP — drop. The frame is mutated; that's
            // fine, we're discarding it.
            return;
        }

        // Phase 4: figure out which LAN port to send on. Every LAN port shares
        // the same broadcast domain + neighbor table, so we just need *any*
        // LAN context to read from + the FDB tells us the egress port (if it
        // knows). If the FDB doesn't know yet, fall back to flooding so the
        // packet reaches its host.
        let Some(any_lan) = self.lan_ports().next() else {
            return;
        };
        let lan_src_mac = any_lan.port.info().ether_addr;

        // Phase 5: resolve internal-IP -> MAC and forward.
        let mut req_buf = [0u8; crate::net::arp::FRAME_LEN];
        use crate::router::neighbor::Action;
        match any_lan
            .neighbors
            .resolve(ingress.dst_ip, m, &mut req_buf, now)
        {
            Action::Forward { mac, packet: mut p } => {
                super::worker::set_ethernet(&mut p, lan_src_mac, mac);
                // FDB lookup picks the egress LAN port. On miss, flood:
                // we already paid the cost of cloning a transmit_frame copy
                // per port; the alternative would be dropping a packet whose
                // destination we just resolved, which is worse. No port to
                // exclude — the packet came from the WAN.
                self.transmit_to_mac_or_flood_except(lcore, mac, p, None);
            }
            Action::Queued { request_len } => {
                // First miss for this host also synthesises an ARP request.
                // Flood it across LAN ports because the host could be on any
                // of them.
                if let Some(n) = request_len {
                    for ctx in self.lan_ports() {
                        ctx.port.transmit_frame(lcore, &req_buf[..n]);
                    }
                }
                // packet is queued in the LAN neighbor table; it drains via
                // drive_lan's on_arp branch once the host replies.
            }
            Action::Drop { packet: _ } => {
                // Pending queue overflow for this internal IP — drop.
            }
        }
    }

    /// Send `packet` to `mac` on the LAN side. On an FDB hit we transmit
    /// zero-copy on the learned port; on a miss we queue the packet in the
    /// FDB *and* flood a copy across every LAN port so the destination still
    /// receives it (unknown-unicast flood is what teaches bridges).
    ///
    /// `except_port` is the LAN port the packet came in on, when this helper
    /// is used for intra-LAN forwarding (so we don't echo the frame back to
    /// the sender). `None` from the WAN-ingress path means "flood every LAN
    /// port" since the packet came from off-bridge.
    fn transmit_to_mac_or_flood_except(
        &self,
        lcore: u32,
        mac: MacAddr,
        packet: Mbuf,
        except_port: Option<u16>,
    ) {
        // FDB lookup is read-only (no queueing on miss), so we can keep
        // ownership of `packet` until we know which path to take.
        match self.fdb.lookup(mac) {
            Some(port) if Some(port) != except_port => {
                if let Some(out) = self.lan_port_by_id(port) {
                    out.port.transmit_mbuf(lcore, packet);
                }
                // else: stale FDB entry pointing at a port we no longer own;
                // drop with `packet`.
            }
            Some(_) => {
                // FDB says this MAC is on the ingress port itself — don't
                // echo back to the sender. Drop.
            }
            None => {
                // Unknown unicast: flood across every LAN port except the
                // source. `transmit_frame` allocates a copy per port, which
                // is the unavoidable cost of flooding.
                let data = packet.data();
                for ctx in self.lan_ports() {
                    if Some(ctx.port.port_id()) != except_port {
                        ctx.port.transmit_frame(lcore, data);
                    }
                }
                // `packet` drops here, returning to its mempool.
            }
        }
    }
}

/// Read the IPv4 + TCP 5-tuple (src_ip, src_port, dst_ip, dst_port) and the
/// TCP flag byte from `frame`. Returns `None` if the frame isn't a parseable
/// IPv4 + TCP packet — i.e. drop-on-egress + drop-on-ingress for a TCP-only
/// router.
fn parse_tcp_tuple(frame: &[u8]) -> Option<(Ipv4Addr, u16, Ipv4Addr, u16, u8)> {
    let eth = crate::net::view::parse(frame)?;
    let ip = eth.ipv4()?;
    let tcp = ip.tcp()?;
    Some((
        ip.header().src(),
        tcp.src_port(),
        ip.header().dst(),
        tcp.dst_port(),
        tcp.header().flags,
    ))
}

/// Classification of a frame received on a LAN port. The fields are owned
/// (no borrow into the mbuf) so the caller can drop the `EthernetView` it
/// extracted them from and then move the mbuf elsewhere.
struct LanClass {
    src_mac: MacAddr,
    dst_mac: MacAddr,
    is_broadcast: bool,
    is_arp: bool,
    is_ipv4: bool,
}

/// Classification of a frame received on the WAN port. Smaller than [`LanClass`]
/// because the WAN side has fewer routing branches — every frame is destined
/// for us (the link's only IP) or for ARP/DHCP.
struct WanClass {
    src_mac: MacAddr,
    is_arp: bool,
    is_ipv4: bool,
}
