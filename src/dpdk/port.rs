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