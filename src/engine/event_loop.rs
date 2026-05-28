// Busy-poll RX/TX loop pinned to an isolated lcore.

pub fn run() {
    // TODO: rte_eth_rx_burst → parse → TCP state machine → rte_eth_tx_burst.
}
