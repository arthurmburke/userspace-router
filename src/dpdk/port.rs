//! NIC port configuration for DPDK.
//!
//! Handles port initialization: device configuration, RX/TX queue setup,
//! and port start. Configures hardware offloads (checksum, RSS) and
//! ring buffer sizes

use crate::dpdk::ffi;

pub struct PortConfig {
    pub port_id: u16,
    pub nb_rx_queues: u16,
    pub nb_tx_queues: u16,
    pub rx_ring_size: u16,
    pub tx_ring_size: u16,
    pub mempool: *mut ffi::rte_mempool,
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

/// Initialize a DPDK Ethernet port.
///
/// Configures the port with the specified number of RX/TX queues,
/// sets up each queue with the given ring sizes, and starts the port
/// in promiscuous mode (required for our custom TCP stack to receive
/// all packets destined for our IP).
pub fn init_port(config: &PortConfig) -> Result<(), PortError> {
    unsafe {
        // Configure port (null eth_conf uses defaults)
        let ret = ffi::rte_eth_dev_configure(
            config.port_id,
            config.nb_rx_queues,
            config.nb_tx_queues,
            std::ptr::null(),
        );
        if ret < 0 {
            return Err(PortError::Configure(ret));
        }

        let socket_id = ffi::rte_socket_id();

        // Setup RX queues
        for q in 0..config.nb_rx_queues {
            let ret = ffi::rte_eth_rx_queue_setup(
                config.port_id,
                q,
                config.rx_ring_size,
                socket_id,
                std::ptr::null(),
                config.mempool,
            );
            if ret < 0 {
                return Err(PortError::RxQueueSetup { queue: q, err: ret });
            }
        }

        // Setup TX queues
        for q in 0..config.nb_tx_queues {
            let ret = ffi::rte_eth_tx_queue_setup(
                config.port_id,
                q,
                config.tx_ring_size,
                socket_id,
                std::ptr::null(),
            );
            if ret < 0 {
                return Err(PortError::TxQueueSetup { queue: q, err: ret });
            }
        }

        // Start port
        let ret = ffi::rte_eth_dev_start(config.port_id);
        if ret < 0 {
            return Err(PortError::Start(ret));
        }

        // Enable promiscuous mode — our custom TCP stack must see all
        // packets destined for our IP, not just those matching the
        // NIC's MAC filter.
        let ret = ffi::rte_eth_promiscuous_enable(config.port_id);
        if ret < 0 {
            return Err(PortError::Promiscuous(ret));
        }
    }

    Ok(())
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
    // SAFETY: a zeroed `rte_eth_dev_info` is the documented input (the C API
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

    // SAFETY: always safe; returns -1 if the port has no NUMA affinity.
    let socket_id = unsafe { ffi::rte_eth_dev_socket_id(port_id) };

    Ok(PortInfo {
        port_id,
        driver_name,
        socket_id,
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
