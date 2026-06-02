//! Utility structs and functions for enumerating lcores using DPDK.
//! This is useful for pairing lcores with ports and queues.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Lcore {
    pub id: u32,
    pub socket: u32,
}

pub struct LcoreIter {
    curr: u32,
}

impl LcoreIter {
    pub fn new() -> Self {
        // Sentinel: `rte_get_next_lcore(i, ...)` returns the next enabled lcore
        // strictly greater than `i`, so seeding `curr` with `u32::MAX` (i.e. the
        // C `-1`) yields the first enabled lcore on the first call.
        Self { curr: u32::MAX }
    }
}

impl Default for LcoreIter {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for LcoreIter {
    type Item = Lcore;

    fn next(&mut self) -> Option<Self::Item> {
        let nxt = unsafe {
            super::ffi::rte_get_next_lcore(
                self.curr, // start
                0,         // include main
                0,         // no wrap
            )
        };
        // Exhausted: `rte_get_next_lcore` returns `RTE_MAX_LCORE` when there are
        // no further enabled lcores.
        if nxt >= super::ffi::RTE_MAX_LCORE {
            // Latch so subsequent calls also return None.
            self.curr = super::ffi::RTE_MAX_LCORE;
            return None;
        }

        self.curr = nxt;
        Some(Lcore {
            id: nxt,
            socket: unsafe { super::ffi::rte_lcore_to_socket_id(nxt) },
        })
    }
}
