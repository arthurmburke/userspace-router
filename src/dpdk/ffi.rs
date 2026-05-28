#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(improper_ctypes)]
// bindgen 0.71 doesn't wrap raw-pointer ops inside its generated `unsafe fn`
// bodies in `unsafe {}` blocks, which Rust 2024 warns about.
#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "dpdk")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
