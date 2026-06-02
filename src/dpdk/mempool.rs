//! A zero-copy wrapper around a DPDK mempool. The mempool is a pool of fixed-size buffers (mbufs) that can be used for packet I/O.
//! This module provides a safe Rust interface to the mempool, allowing us to allocate and free mbufs without dealing with raw pointers or unsafe code directly in the rest of the codebase. The

use std::{ptr::NonNull, sync::Arc};

use crate::{core::spinlock::SpinLock, dpdk::mbuf::Mbuf};

/// A wrapper around a DPDK allocated mempool. The mempool is responsible for managing the lifecycle of mbufs, and this struct ensures that the mempool is properly freed when it goes out of scope.
pub struct MemPool {
    pool: NonNull<super::ffi::rte_mempool>,
}

impl MemPool {
    pub fn create(
        name: &str,
        num_mbufs: u32,
        cache_size: u32,
        mbuf_size: u16,
        socket: i32,
    ) -> Option<Self> {
        let c_name =
            std::ffi::CString::new(name).expect("Mempool name must not contain null bytes");
        let pool = unsafe {
            super::ffi::rte_pktmbuf_pool_create(
                c_name.as_ptr(),
                num_mbufs,
                cache_size, // cache size (0 for no per-core caching)
                0,          // priv size (0 for none)
                mbuf_size,
                socket as core::ffi::c_int,
            )
        };
        if pool.is_null() {
            None
        } else {
            Some(Self {
                pool: unsafe { NonNull::new_unchecked(pool) },
            })
        }
    }

    /// Wrap a mbuf from this mempool.
    ///
    /// # SAFETY `pool` must be a valid, live `rte_mempool` created for mbufs (e.g. via `rte_pktmbuf_pool_create`).
    #[inline]
    pub unsafe fn from_raw(pool: *mut super::ffi::rte_mempool) -> Self {
        Self {
            pool: NonNull::new(pool).expect("Pool pointer must not be null"),
        }
    }

    /// Allocate a fresh mbuf from `pool`.
    ///
    /// # Safety
    /// `pool` must be a valid, live `rte_mempool` created for mbufs (e.g. via
    /// `rte_pktmbuf_pool_create`).
    #[inline]
    pub unsafe fn alloc(&mut self) -> Option<super::mbuf::Mbuf> {
        let ptr = self.pool.as_ptr();
        unsafe { Mbuf::alloc(ptr) }
    }
}

impl Drop for MemPool {
    fn drop(&mut self) {
        unsafe {
            super::ffi::rte_mempool_free(self.pool.as_ptr());
        }
    }
}

/// # SAFETY: Mempool is not thread-safe, so it must not be sent across threads. However, it can be safely shared between threads as long as they don't access it concurrently (e.g. by only using it on a single thread or by synchronizing access with a mutex).
unsafe impl Send for MemPool {}

/// A mempool that is designed to be shared among cores.
#[derive(Clone)]
pub struct SharedMemPool {
    inner: Arc<SpinLock<MemPool>>,
}

impl From<MemPool> for SharedMemPool {
    fn from(value: MemPool) -> Self {
        Self {
            inner: Arc::new(SpinLock::new(value)),
        }
    }
}

impl SharedMemPool {
    pub fn alloc(&self) -> Option<super::mbuf::Mbuf> {
        self.inner.with(|inner| unsafe { inner.alloc() })
    }

    /// # SAFETY only call this function on initializing a port. For all other cases when allocating Mbuf's,
    /// use the `alloc` function. The returned pointer is not thread-safe and lifetime is not guaranteed.
    pub unsafe fn raw_ptr(&self) -> *mut super::ffi::rte_mempool {
        let mut lock = self.inner.lock();
        lock.as_mut().pool.as_ptr()
    }
}
