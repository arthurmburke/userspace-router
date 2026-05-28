# quicktcp

Highly optimized TCP implementation using DPDK, with raw C FFI bindings generated from the installed DPDK headers via `bindgen`.

## Layout

```
src/
  lib.rs            crate root; re-exports modules below
  dpdk/             raw DPDK access
    ffi.rs          bindgen-generated bindings (include!d from OUT_DIR)
    mbuf.rs         rte_mbuf helpers
    port.rs         ethdev configuration / queues / start-stop
  engine/
    event_loop.rs   busy-poll RX/TX on an isolated lcore
  mem/
    pool.rs         rte_mempool wrappers
    ring.rs         rte_ring wrappers
  net/              header parsing / state machine
    ethernet.rs ip.rs tcp.rs arp.rs checksum.rs
  protocol/         app-layer (placeholder mirrored from reference)
wrapper.h           top-level include passed to bindgen
build.rs            pkg-config(libdpdk) + bindgen + cc for static-fn shims
```

## Building

DPDK only runs on Linux. A devcontainer is provided.

```bash
# host (macOS), no DPDK — checks Rust only, skips bindgen/linking
cargo check

# inside the Linux container, with real DPDK
cargo build --release --features dpdk
```

Use the crate from a downstream binary by adding it as a path/git dependency with `features = ["dpdk"]` and calling `quicktcp::dpdk::ffi::rte_eal_init(...)` from your `main`.

The `dpdk` feature gates the bindgen+pkg-config+cc work in `build.rs` and the `include!` in `src/dpdk/ffi.rs`, so `cargo check` on a host without DPDK still type-checks the Rust side.

Requirements on the build host:
- `libdpdk-dev` (Ubuntu 24.04 ships DPDK 23.11)
- `clang` / `libclang-dev` (for bindgen)
- `pkg-config`

## Running

Running a DPDK app requires hugepages, a supported NIC bound to `vfio-pci` (or `uio_pci_generic`), and root or equivalent capabilities. The devcontainer can build but cannot meaningfully run DPDK on a macOS host — use a Linux machine or VM with a real or SR-IOV NIC for runtime testing.

