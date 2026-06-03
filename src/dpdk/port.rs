//! NIC port configuration for DPDK.
//!
//! Handles port initialization: device configuration, RX/TX queue setup,
//! and port start. Configures hardware offloads (checksum, RSS) and
//! ring buffer sizes

use crate::core::spinlock::SpinLock;
use crate::dpdk::ffi;
use crate::dpdk::mbuf::Mbuf;
use crate::dpdk::mempool::SharedMemPool;
use crate::net::ethernet::MacAddr;
use std::collections::HashMap;

pub struct PortConfig {
    pub port_id: u16,
    /// Number of RX queues to ask for. Clamped to `[1, info.max_rx_queues]`.
    /// Set this to the number of lcores that will poll this port: each lcore
    /// gets its own queue, and when the NIC supports RSS we'll enable it so
    /// inbound flows fan out across the queues (Toeplitz over IPv4 +
    /// TCP/UDP 4-tuples, intersected with what the device advertises).
    pub nb_rx_queues: u16,
    /// Number of TX queues. Same clamp; set per lcore that will TX on this port.
    pub nb_tx_queues: u16,
    pub rx_ring_size: u16,
    pub tx_ring_size: u16,
    pub mempool: SharedMemPool,
}

/// What `init_port` actually configured on the device after clamping the
/// caller's request against the NIC's reported capabilities.
#[derive(Debug, Clone, Copy)]
pub struct PortSetup {
    pub port_id: u16,
    pub rx_queues: u16,
    pub tx_queues: u16,
    /// True when RSS was enabled across the RX queues. False means all RX
    /// traffic lands on queue 0 (virtio without RSS, single-queue request,
    /// or the device offers no usable hash types).
    pub rss_enabled: bool,
}

#[derive(Debug)]
pub enum PortError {
    Configure(i32),
    RxQueueSetup { queue: u16, err: i32 },
    TxQueueSetup { queue: u16, err: i32 },
    Start(i32),
    Promiscuous(i32),
    Info(i32),
}

impl std::fmt::Display for PortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortError::Configure(e) => write!(f, "port configure failed: {e}"),
            PortError::RxQueueSetup { queue, err } => {
                write!(f, "RX queue {queue} setup failed: {err}")
            }
            PortError::TxQueueSetup { queue, err } => {
                write!(f, "TX queue {queue} setup failed: {err}")
            }
            PortError::Start(e) => write!(f, "port start failed: {e}"),
            PortError::Promiscuous(e) => write!(f, "promiscuous enable failed: {e}"),
            PortError::Info(e) => write!(f, "rte_eth_dev_info_get failed: {e}"),
        }
    }
}

/// Initialise a DPDK Ethernet port using the device's reported capabilities:
///
/// - probe via `rte_eth_dev_info_get`,
/// - clamp the requested RX/TX queue counts to `info.max_*_queues`,
/// - if the NIC supports RSS *and* we have more than one RX queue, enable
///   RSS over the IPv4 + TCP/UDP hash types the device advertises (so each
///   lcore polling its own queue sees a disjoint slice of the inbound flows),
/// - allocate descriptor rings on the port's own NUMA socket,
/// - start the port and enable promiscuous mode.
///
/// Returns a [`PortSetup`] describing what was actually configured. The
/// caller should drive its per-port polling using the returned `rx_queues` /
/// `tx_queues`, not what it asked for — those numbers may have been clamped.
pub fn init_port(config: &PortConfig) -> Result<PortSetup, PortError> {
    // Probe so we know the device's queue and RSS limits.
    let info = info(config.port_id)?;

    // Clamp queue counts to what the device supports (and to at least 1).
    let nb_rx = config.nb_rx_queues.clamp(1, info.max_rx_queues.max(1));
    let nb_tx = config.nb_tx_queues.clamp(1, info.max_tx_queues.max(1));

    // RSS is only meaningful when we actually have multiple RX queues *and*
    // the device advertises at least one hash type and a redirection table.
    let rss_enabled = nb_rx > 1 && info.rss_usable();

    // Build the `rte_eth_conf`. Zeroed = defaults; we only override the bits
    // we care about (the RX mq_mode and the RSS hash type set).
    // SAFETY: rte_eth_conf is a POD that DPDK expects memset(0) to be valid.
    let mut eth_conf: ffi::rte_eth_conf = unsafe { core::mem::zeroed() };
    if rss_enabled {
        eth_conf.rxmode.mq_mode = caps::MQ_MODE_RSS as _;
        // Null `rss_key` => the device's built-in default key (Toeplitz, 40
        // bytes on most NICs). We intersect the desired hash types with what
        // the device advertises so `rte_eth_dev_configure` doesn't reject the
        // request for asking for an unsupported flow type.
        eth_conf.rx_adv_conf.rss_conf.rss_key = core::ptr::null_mut();
        let desired = caps::RSS_IPV4 | caps::RSS_TCP_IPV4 | caps::RSS_UDP_IPV4;
        eth_conf.rx_adv_conf.rss_conf.rss_hf = desired & info.flow_type_rss_offloads;
    }

    // SAFETY: `eth_conf` is fully initialised; queue counts are within the
    // device's advertised maxima.
    let ret = unsafe { ffi::rte_eth_dev_configure(config.port_id, nb_rx, nb_tx, &eth_conf) };
    if ret < 0 {
        return Err(PortError::Configure(ret));
    }

    // Allocate descriptor rings on the *port's* socket so DMA stays local,
    // not the calling lcore's. `rte_eth_dev_socket_id` returns -1 for a
    // device with no NUMA affinity (typical for virtio); clamp to socket 0.
    let socket_id = {
        let s = unsafe { ffi::rte_eth_dev_socket_id(config.port_id) };
        if s < 0 { 0u32 } else { s as u32 }
    };

    for q in 0..nb_rx {
        // SAFETY: queue index < nb_rx <= info.max_rx_queues; mempool is live.
        let ret = unsafe {
            ffi::rte_eth_rx_queue_setup(
                config.port_id,
                q,
                config.rx_ring_size,
                socket_id,
                core::ptr::null(),
                config.mempool.raw_ptr(),
            )
        };
        if ret < 0 {
            return Err(PortError::RxQueueSetup { queue: q, err: ret });
        }
    }

    for q in 0..nb_tx {
        // SAFETY: queue index < nb_tx <= info.max_tx_queues.
        let ret = unsafe {
            ffi::rte_eth_tx_queue_setup(
                config.port_id,
                q,
                config.tx_ring_size,
                socket_id,
                core::ptr::null(),
            )
        };
        if ret < 0 {
            return Err(PortError::TxQueueSetup { queue: q, err: ret });
        }
    }

    // SAFETY: device has been configured + queues set up.
    let ret = unsafe { ffi::rte_eth_dev_start(config.port_id) };
    if ret < 0 {
        return Err(PortError::Start(ret));
    }

    // Promiscuous mode — our stack must see all packets destined for our IP,
    // not just those matching the NIC's MAC filter.
    let ret = unsafe { ffi::rte_eth_promiscuous_enable(config.port_id) };
    if ret < 0 {
        return Err(PortError::Promiscuous(ret));
    }

    Ok(PortSetup {
        port_id: config.port_id,
        rx_queues: nb_rx,
        tx_queues: nb_tx,
        rss_enabled,
    })
}

/// Offload-capability bits, mirroring DPDK's stable `RTE_ETH_*_OFFLOAD_*` ABI
/// values (defined here rather than relying on bindgen capturing the
/// `RTE_BIT64(...)` macros). Bit positions are stable across DPDK 20.11+.
mod caps {
    /// `RTE_ETH_TX_OFFLOAD_IPV4_CKSUM` — NIC computes the IPv4 header checksum.
    pub const TX_IPV4_CKSUM: u64 = 1 << 1;
    /// `RTE_ETH_TX_OFFLOAD_UDP_CKSUM` — NIC computes the UDP checksum.
    pub const TX_UDP_CKSUM: u64 = 1 << 2;
    /// `RTE_ETH_TX_OFFLOAD_TCP_CKSUM` — NIC computes the TCP checksum.
    pub const TX_TCP_CKSUM: u64 = 1 << 3;
    /// `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` — NIC accepts multi-segment (chained) mbufs.
    pub const TX_MULTI_SEGS: u64 = 1 << 15;

    /// `RTE_ETH_RX_OFFLOAD_IPV4_CKSUM` — NIC verifies the IPv4 header checksum.
    pub const RX_IPV4_CKSUM: u64 = 1 << 1;
    /// `RTE_ETH_RX_OFFLOAD_UDP_CKSUM` — NIC verifies the UDP checksum.
    pub const RX_UDP_CKSUM: u64 = 1 << 2;
    /// `RTE_ETH_RX_OFFLOAD_TCP_CKSUM` — NIC verifies the TCP checksum.
    pub const RX_TCP_CKSUM: u64 = 1 << 3;

    /// `enum rte_eth_rx_mq_mode::RTE_ETH_MQ_RX_RSS` — distribute RX traffic
    /// across queues using a hash over the flow type set in `rss_conf.rss_hf`.
    pub const MQ_MODE_RSS: u32 = 1;

    /// `RTE_ETH_RSS_IPV4` — hash on IPv4 src/dst.
    pub const RSS_IPV4: u64 = 1 << 2;
    /// `RTE_ETH_RSS_NONFRAG_IPV4_TCP` — hash the IPv4 + TCP 4-tuple.
    pub const RSS_TCP_IPV4: u64 = 1 << 4;
    /// `RTE_ETH_RSS_NONFRAG_IPV4_UDP` — hash the IPv4 + UDP 4-tuple.
    pub const RSS_UDP_IPV4: u64 = 1 << 5;
}

/// A snapshot of one port's capabilities, taken via `rte_eth_dev_info_get`.
///
/// These are exactly the facts the router design branches on: queue counts
/// decide whether each worker can own an independent WAN TX queue; the RSS
/// fields decide whether RSS-aligned steering is even possible (it generally
/// is not on virtio); the checksum-offload bits decide whether NAT can lean on
/// the NIC or must update checksums in software.
#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port_id: u16,
    pub driver_name: String,
    pub socket_id: i32,
    pub ether_addr: MacAddr,
    pub max_rx_queues: u16,
    pub max_tx_queues: u16,
    pub max_rx_pktlen: u32,
    pub max_mac_addrs: u32,
    pub rx_offload_capa: u64,
    pub tx_offload_capa: u64,
    /// RSS redirection-table size (0 ⇒ no usable RSS).
    pub reta_size: u16,
    /// RSS hash-key size in bytes (0 ⇒ key not configurable).
    pub hash_key_size: u8,
    /// Bitmask of supported RSS hash types (`RTE_ETH_RSS_*`).
    pub flow_type_rss_offloads: u64,
}

impl PortInfo {
    /// Whether RSS is usable: a redirection table *and* at least one hash type.
    /// When false (the expected case on virtio) we fall back to the software
    /// port-range demux instead of RSS-aligned steering.
    #[inline]
    pub fn rss_usable(&self) -> bool {
        self.reta_size > 0 && self.flow_type_rss_offloads != 0
    }

    /// Whether each worker can own an independent WAN TX queue (the fast path),
    /// given `workers` worker cores.
    #[inline]
    pub fn supports_per_core_tx(&self, workers: u16) -> bool {
        self.max_tx_queues >= workers
    }

    /// Whether the NIC can compute IPv4 + L4 checksums on TX, letting NAT skip
    /// software checksum work.
    #[inline]
    pub fn tx_checksum_offload(&self) -> bool {
        let want = caps::TX_IPV4_CKSUM | caps::TX_UDP_CKSUM | caps::TX_TCP_CKSUM;
        self.tx_offload_capa & want == want
    }

    #[inline]
    pub fn rx_checksum_offload(&self) -> bool {
        let want = caps::RX_IPV4_CKSUM | caps::RX_UDP_CKSUM | caps::RX_TCP_CKSUM;
        self.rx_offload_capa & want == want
    }
}

impl std::fmt::Display for PortInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "port {} ({})", self.port_id, self.driver_name)?;
        writeln!(f, "  socket_id        : {}", self.socket_id)?;
        writeln!(
            f,
            "  queues           : {} rx / {} tx (max)",
            self.max_rx_queues, self.max_tx_queues
        )?;
        writeln!(f, "  max_rx_pktlen    : {}", self.max_rx_pktlen)?;
        writeln!(f, "  max_mac_addrs    : {}", self.max_mac_addrs)?;
        writeln!(
            f,
            "  rss              : {} (reta={}, key={} bytes, types=0x{:016x})",
            if self.rss_usable() {
                "usable"
            } else {
                "unusable"
            },
            self.reta_size,
            self.hash_key_size,
            self.flow_type_rss_offloads
        )?;
        writeln!(
            f,
            "  tx cksum offload : ipv4={} udp={} tcp={} multiseg={}",
            self.tx_offload_capa & caps::TX_IPV4_CKSUM != 0,
            self.tx_offload_capa & caps::TX_UDP_CKSUM != 0,
            self.tx_offload_capa & caps::TX_TCP_CKSUM != 0,
            self.tx_offload_capa & caps::TX_MULTI_SEGS != 0,
        )?;
        write!(
            f,
            "  rx cksum offload : ipv4={} udp={} tcp={}",
            self.rx_offload_capa & caps::RX_IPV4_CKSUM != 0,
            self.rx_offload_capa & caps::RX_UDP_CKSUM != 0,
            self.rx_offload_capa & caps::RX_TCP_CKSUM != 0,
        )
    }
}

/// All currently-valid Ethernet port ids (the `RTE_ETH_FOREACH_DEV` idiom,
/// which isn't a callable function, reimplemented over `rte_eth_find_next`).
pub fn all_ports() -> Vec<u16> {
    let mut ports = Vec::new();
    // SAFETY: `rte_eth_find_next` is always safe to call; it returns
    // `RTE_MAX_ETHPORTS` when there are no further valid ports.
    let mut p = unsafe { ffi::rte_eth_find_next(0) };
    while (p as u32) < ffi::RTE_MAX_ETHPORTS {
        ports.push(p);
        p = unsafe { ffi::rte_eth_find_next(p + 1) };
    }
    ports
}

/// Probe one port's capabilities.
pub fn info(port_id: u16) -> Result<PortInfo, PortError> {
    // # SAFETY: a zeroed `rte_eth_dev_info` is the documented input (the C API
    // memset(0)s it); `rte_eth_dev_info_get` fills it in.
    let mut dev: ffi::rte_eth_dev_info = unsafe { core::mem::zeroed() };
    let rc = unsafe { ffi::rte_eth_dev_info_get(port_id, &mut dev) };
    if rc != 0 {
        return Err(PortError::Info(rc));
    }

    let driver_name = if dev.driver_name.is_null() {
        String::new()
    } else {
        // SAFETY: non-null and NUL-terminated, owned by the driver (static).
        unsafe { core::ffi::CStr::from_ptr(dev.driver_name) }
            .to_string_lossy()
            .into_owned()
    };

    // # SAFETY: always safe; returns -1 if the port has no NUMA affinity.
    let socket_id = unsafe { ffi::rte_eth_dev_socket_id(port_id) }.max(0);

    // # SAFETY: always safe, the port should always have an ethernet address
    let mut addr: ffi::rte_ether_addr = unsafe { core::mem::zeroed() };
    unsafe { ffi::rte_eth_macaddr_get(port_id, &mut addr) };

    Ok(PortInfo {
        port_id,
        driver_name,
        socket_id,
        ether_addr: addr.addr_bytes,
        max_rx_queues: dev.max_rx_queues,
        max_tx_queues: dev.max_tx_queues,
        max_rx_pktlen: dev.max_rx_pktlen,
        max_mac_addrs: dev.max_mac_addrs,
        rx_offload_capa: dev.rx_offload_capa,
        tx_offload_capa: dev.tx_offload_capa,
        reta_size: dev.reta_size,
        hash_key_size: dev.hash_key_size,
        flow_type_rss_offloads: dev.flow_type_rss_offloads,
    })
}

/// Max number of packets handed out per [`Port::receive`] call.
pub const BURST: usize = 32;

/// A configured DPDK port together with the per-lcore queue assignment that
/// routes [`Port::receive`] / [`Port::transmit_frame`] / [`Port::transmit_mbuf`]
/// onto the right queue (or a software-side fallback when there isn't one).
///
/// **RX**
/// - If RSS was enabled (`setup.rss_enabled`), lcore *i* polls queue *i*, up
///   to `setup.rx_queues`. Excess lcores get an empty iterator from
///   `receive` — they would otherwise race against another lcore on the same
///   queue, which DPDK doesn't allow.
/// - If RSS isn't available, exactly one lcore is the **RX owner** of hw
///   queue 0 (the only queue carrying anything). All other lcores' `receive`
///   returns empty, and the runtime is expected to fan packets out from the
///   owner via its own steering structures (e.g. `SharedFdb` + SPSC rings).
///   This is what "software-defined steering" means here: queue ownership is
///   a runtime decision, not a NIC feature.
///
/// **TX**
/// - Each lcore is mapped to a TX queue. When the device exposes at least as
///   many TX queues as lcores assigned to the port, every lcore gets its own
///   queue and the per-queue spinlock is uncontended. When TX queues are
///   oversubscribed, sharers serialize briefly on the spinlock.
/// - `rte_pktmbuf_alloc` is internally thread-safe (per-lcore caches inside
///   the mempool), so multiple lcores can transmit concurrently.
pub struct Port {
    info: PortInfo,
    setup: PortSetup,
    /// Pool to alloc TX mbufs from. EAL owns the allocation; it lives for the
    /// program lifetime.
    mempool: SharedMemPool,
    rx: RxPlan,
    tx: TxPlan,
}

// SAFETY: `mempool` is an EAL-owned static reachable for the program lifetime;
// `rte_pktmbuf_alloc` is internally thread-safe. Per-queue TX is serialised by
// the per-queue spinlocks in `TxPlan`, and per-queue RX is ensured by the
// per-lcore queue assignment (no two lcores share an RX queue).
unsafe impl Send for Port {}
unsafe impl Sync for Port {}

enum RxPlan {
    /// RSS-enabled: each assigned lcore owns its own queue.
    Rss(HashMap<u32, u16>),
    /// No RSS: exactly one lcore polls hw queue 0; others must receive
    /// packets out-of-band (from SPSC rings filled by the owner).
    SingleOwner(u32),
}

struct TxPlan {
    /// `lcore_id -> queue_idx`. Lcores not in the map fall through to queue 0.
    lcore_to_queue: HashMap<u32, u16>,
    /// One spinlock per TX queue. Uncontended whenever `tx_queues >= lcores`.
    locks: Vec<SpinLock<()>>,
}

impl Port {
    /// Build the per-lcore plan over a port that has already been
    /// [`init_port`]'d. `lcores` is the set of lcores that will own RX/TX on
    /// this port (typically the workers on the port's NUMA socket).
    pub fn new(setup: PortSetup, info: PortInfo, mempool: SharedMemPool, lcores: &[u32]) -> Self {
        assert!(!lcores.is_empty(), "Port::new requires at least one lcore");

        let rx = if setup.rss_enabled {
            // lcore i -> queue i, up to setup.rx_queues. Excess lcores aren't
            // assigned a queue (sharing one would race DPDK).
            let mut map = HashMap::new();
            for (i, &lc) in lcores.iter().take(setup.rx_queues as usize).enumerate() {
                map.insert(lc, i as u16);
            }
            RxPlan::Rss(map)
        } else {
            // Software steering: one owner polls hw queue 0; the runtime
            // dispatches to other lcores out-of-band. We choose the owner
            // at random from the available lcores.
            let i = rand::random_range(0..lcores.len());
            let lcore = lcores[i];

            RxPlan::SingleOwner(lcore)
        };

        let n_tx = setup.tx_queues.max(1) as usize;
        let mut lcore_to_queue = HashMap::new();
        for (i, &lc) in lcores.iter().enumerate() {
            lcore_to_queue.insert(lc, (i % n_tx) as u16);
        }
        let locks: Vec<SpinLock<()>> = (0..n_tx).map(|_| SpinLock::new(())).collect();
        let tx = TxPlan {
            lcore_to_queue,
            locks,
        };

        Self {
            info,
            setup,
            mempool,
            rx,
            tx,
        }
    }

    #[inline]
    pub fn port_id(&self) -> u16 {
        self.info.port_id
    }
    #[inline]
    pub fn info(&self) -> &PortInfo {
        &self.info
    }
    #[inline]
    pub fn setup(&self) -> &PortSetup {
        &self.setup
    }
    /// The mempool TX mbufs are drawn from — placed on the port's NUMA socket.
    #[inline]
    pub fn mempool(&self) -> &SharedMemPool {
        &self.mempool
    }

    /// Whether `lcore` is responsible for polling a hardware RX queue on this
    /// port. `false` for non-owners in the no-RSS fallback and for excess
    /// lcores in the RSS case.
    pub fn is_rx_owner(&self, lcore: u32) -> bool {
        match &self.rx {
            RxPlan::Rss(map) => map.contains_key(&lcore),
            RxPlan::SingleOwner(o) => lcore == *o,
        }
    }

    /// Allocate an mbuf from this port's mempool. Useful for callers that want
    /// to build a packet directly and then pass it to [`Self::transmit_mbuf`].
    #[inline]
    pub fn alloc(&self) -> Option<Mbuf> {
        self.mempool.alloc()
    }

    /// Receive a burst on behalf of `lcore`. Returns an empty iterator if
    /// `lcore` isn't assigned an RX queue on this port (non-owner with no
    /// RSS, or excess lcore with RSS).
    pub fn receive(&self, lcore: u32) -> impl Iterator<Item = Mbuf> {
        let q = match &self.rx {
            RxPlan::Rss(map) => map.get(&lcore).copied(),
            RxPlan::SingleOwner(owner) => (lcore == *owner).then_some(0u16),
        };
        let mut bufs = [core::ptr::null_mut(); BURST];
        let n = match q {
            Some(q) => unsafe {
                // SAFETY: `bufs` has room for `BURST` pointers.
                ffi::rte_eth_rx_burst(self.info.port_id, q, bufs.as_mut_ptr(), BURST as u16)
            },
            // Non-owner on this port (no-RSS fallback or an excess lcore under
            // RSS). Stay quiet — every poll on every non-owner would print.
            None => 0,
        } as usize;
        bufs.into_iter()
            .take(n)
            .filter_map(|p| unsafe { Mbuf::from_raw(p) })
    }

    /// Allocate an mbuf, copy `frame` into it, and transmit on `lcore`'s
    /// queue. Returns `true` if the NIC accepted the packet; on any failure
    /// the mbuf is reclaimed so it isn't leaked.
    pub fn transmit_frame(&self, lcore: u32, frame: &[u8]) -> bool {
        let Some(mut m) = self.alloc() else {
            eprintln!(
                "[ERROR]: failed to allocate mbuf from pool on lcore {lcore} port {}",
                self.port_id()
            );
            return false;
        };
        // SAFETY: bytes written before the slice is dropped.
        let Some(dst) = (unsafe { m.append(frame.len() as u16) }) else {
            eprintln!("[ERROR]: failed to allocate headroom in mbuf");
            return false; // no tailroom
        };
        dst.copy_from_slice(frame);
        self.transmit_mbuf(lcore, m)
    }

    /// Transmit an already-built mbuf zero-copy on `lcore`'s queue. On TX
    /// failure the mbuf is reclaimed via [`Mbuf::from_raw`] so it isn't leaked.
    pub fn transmit_mbuf(&self, lcore: u32, m: Mbuf) -> bool {
        let q = self.tx.lcore_to_queue.get(&lcore).copied().unwrap_or(0);
        let port_id = self.info.port_id;
        let mut raw = m.into_raw();
        // Serialise on the per-queue spinlock. Uncontended when every lcore
        // got its own queue (the common case); briefly contended when TX
        // queues were oversubscribed.
        let sent = self.tx.locks[q as usize]
            .with(|_| unsafe { ffi::rte_eth_tx_burst(port_id, q, &mut raw, 1) });
        if sent == 0 {
            // SAFETY: the NIC rejected the packet; take ownership back so
            // `Drop` frees it.
            let _ = unsafe { Mbuf::from_raw(raw) };
            false
        } else {
            true
        }
    }
}

/// Probe and print every port — call after `rte_eal_init`.
pub fn log_all_ports() {
    let ports = all_ports();
    if ports.is_empty() {
        println!("no DPDK ethernet ports found");
        return;
    }
    for p in ports {
        match info(p) {
            Ok(i) => println!("{i}"),
            Err(e) => println!("port {p}: {e}"),
        }
    }
}
