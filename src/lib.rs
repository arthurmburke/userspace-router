use crate::mem::alloc::Arena;

pub mod core;
pub mod dpdk;
pub mod mem;
pub mod net;
pub mod router;

include!("generated.rs");

// One GiB global arena, shared by all threads. The `#[global_allocator]` attribute
// is applied in `src/lib.rs` so it can be overridden in tests.
#[global_allocator]
static ALLOCATOR: Arena<{ HEAP_SIZE }> = Arena::new();
