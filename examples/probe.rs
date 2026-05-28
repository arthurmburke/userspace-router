//! Probe DPDK port capabilities.
//!
//! Run inside the container with EAL args for your setup, e.g.:
//!
//! ```text
//! cargo run --example probe --features dpdk -- -l 0 -n 4 \
//!     --vdev net_virtio_user0,path=/dev/vhost-net,queues=4,mac=...
//! ```
//!
//! Everything after the EAL args is ignored; we only want `rte_eth_dev_info`.

fn main() {
    #[cfg(not(feature = "dpdk"))]
    eprintln!("build/run with `--features dpdk` to probe DPDK ports");

    #[cfg(feature = "dpdk")]
    run();
}

#[cfg(feature = "dpdk")]
fn run() {
    use quicktcp::dpdk::{ffi, port};
    use std::ffi::CString;

    // Forward this process's argv straight to EAL.
    let args: Vec<CString> = std::env::args()
        .map(|a| CString::new(a).expect("arg contained a NUL"))
        .collect();
    let mut argv: Vec<*mut core::ffi::c_char> = args.iter().map(|a| a.as_ptr() as *mut _).collect();
    let argc = argv.len() as core::ffi::c_int;

    // SAFETY: argc/argv describe a valid, NUL-terminated argument vector that
    // outlives this call (`args` owns the backing `CString`s).
    let consumed = unsafe { ffi::rte_eal_init(argc, argv.as_mut_ptr()) };
    if consumed < 0 {
        panic!("rte_eal_init failed: {consumed}");
    }

    port::log_all_ports();

    // SAFETY: no DPDK resources are in use after this point.
    unsafe { ffi::rte_eal_cleanup() };
}
