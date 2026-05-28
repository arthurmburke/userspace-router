pub mod dpdk;
pub mod engine;
pub mod mem;
pub mod net;
pub mod protocol;
pub mod core;

static HEAP_SIZE: usize = {
    match option_env!("HEAP_SIZE") {
        Some(s) => parse!(s, usize).unwrap_or_else(|_| {
            eprintln!("Invalid HEAP_SIZE '{}', defaulting to 1 GiB", s);
            1024 * 1024 * 1024 // 1 GiB default heap size
        }),
        _ => 1024 * 1024 * 1024, // 1 GiB default heap size
    }
};

// One GiB global arena, shared by all threads. The `#[global_allocator]` attribute
// is applied in `src/lib.rs` so it can be overridden in tests.
#[global_allocator]
static ALLOCATOR: Arena<HEAP_SIZE> = Arena::new();