//! A zero copy wrapper around DPDK's mbuf structure.
//!
//! This type does NOT implement Clone — mbufs are unique resources
//! that must be explicitly freed back to their mempool.
//!
//! The Drop implementation guarantees that every mbuf is returned to its
//! mempool on every code path. This prevents the class of bug where a C
//! programmer adds an early return and forgets the `goto out_free`.
//! The `unsafe` at the FFI boundary is still manual and still your
//! responsibility — Rust doesn't make DPDK safe; it makes the wrapper
//! harder to misuse.
//!
//! The byte slices returned by [`Mbuf::data`] / [`Mbuf::data_mut`] borrow
//! directly into the mbuf's data region. Reinterpret them in place with the
//! header views in [`crate::net`] — e.g.
//! `net::wire::mut_from_prefix::<EthernetHeader>(mbuf.data_mut())` — to read
//! and edit packet fields without copying.

use crate::dpdk::ffi;
use crate::net::view::EthernetView;
use crate::net::wire::{self, Pod};
use core::ptr::NonNull;
use core::slice;

pub struct Mbuf {
    raw: NonNull<ffi::rte_mbuf>,
}

impl Mbuf {
    /// Allocate a fresh mbuf from `pool`.
    ///
    /// # Safety
    /// `pool` must be a valid, live `rte_mempool` created for mbufs (e.g. via
    /// `rte_pktmbuf_pool_create`).
    #[inline]
    pub unsafe fn alloc(pool: *mut ffi::rte_mempool) -> Option<Self> {
        let m = unsafe { ffi::rte_pktmbuf_alloc(pool) };
        NonNull::new(m).map(|raw| Self { raw })
    }

    /// Take ownership of a raw mbuf pointer (e.g. one returned by
    /// `rte_eth_rx_burst`). Returns `None` if `ptr` is null.
    ///
    /// # Safety
    /// `ptr` must point to a valid mbuf that the caller is handing over; after
    /// this call the `Mbuf` is responsible for freeing it.
    #[inline]
    pub unsafe fn from_raw(ptr: *mut ffi::rte_mbuf) -> Option<Self> {
        NonNull::new(ptr).map(|raw| Self { raw })
    }

    /// Relinquish ownership, returning the raw pointer without freeing it.
    ///
    /// Use this when handing the buffer to a function that consumes it, such as
    /// `rte_eth_tx_burst` (the NIC frees it after transmit).
    #[inline]
    pub fn into_raw(self) -> *mut ffi::rte_mbuf {
        let ptr = self.raw.as_ptr();
        core::mem::forget(self);
        ptr
    }

    #[inline]
    pub fn as_ptr(&self) -> *const ffi::rte_mbuf {
        self.raw.as_ptr()
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::rte_mbuf {
        self.raw.as_ptr()
    }

    /// Length of the data in this segment, in bytes.
    #[inline]
    pub fn data_len(&self) -> usize {
        unsafe { (*self.raw.as_ptr()).data_len as usize }
    }

    /// Total length of the packet across all segments, in bytes.
    #[inline]
    pub fn pkt_len(&self) -> usize {
        unsafe { (*self.raw.as_ptr()).pkt_len as usize }
    }

    /// Pointer to the first byte of packet data: `buf_addr + data_off`.
    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        unsafe {
            let m = self.raw.as_ptr();
            ((*m).buf_addr as *mut u8).add((*m).data_off as usize)
        }
    }

    /// Immutable view of this segment's data.
    #[inline]
    pub fn data(&self) -> &[u8] {
        // SAFETY: data_ptr/data_len describe an initialised region owned by the
        // mbuf and valid for `&self`'s lifetime.
        unsafe { slice::from_raw_parts(self.data_ptr(), self.data_len()) }
    }

    /// Mutable view of this segment's data. Edits land in the packet buffer.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `data`, and `&mut self` guarantees exclusive access.
        unsafe { slice::from_raw_parts_mut(self.data_ptr(), self.data_len()) }
    }

    /// Interpret the packet as an Ethernet frame — the entry point for the
    /// layered views in [`crate::net::view`]. From the returned view you can
    /// descend: `eth.ipv4()?.udp()?.dns()`, `eth.arp()`, etc. Returns `None`
    /// if there aren't enough bytes for an Ethernet header.
    #[inline]
    pub fn ethernet(&self) -> Option<EthernetView<'_>> {
        EthernetView::parse(self.data())
    }

    /// Borrow a header of type `T` at byte `offset` for in-place editing.
    ///
    /// Pair it with a view's `header_offset()` to mutate a layer you located
    /// via [`Self::ethernet`] — read the offset first (it's a `usize`, so the
    /// immutable view's borrow ends), then take the mutable reference:
    ///
    /// ```ignore
    /// let off = mbuf.ethernet()?.ipv4()?.header_offset();
    /// let ip: &mut Ipv4Header = mbuf.header_at_mut(off)?;
    /// ip.set_ttl(ip.ttl().saturating_sub(1));
    /// ```
    #[inline]
    pub fn header_at_mut<T: Pod>(&mut self, offset: usize) -> Option<&mut T> {
        self.data_mut()
            .get_mut(offset..)
            .and_then(wire::mut_from::<T>)
    }

    /// Append `len` bytes to the tail of the (last segment of the) packet and
    /// return a mutable slice over them, or `None` if there isn't enough
    /// tailroom. Useful when building a packet to transmit.
    ///
    /// # Safety
    /// The returned bytes are uninitialised; write them before reading.
    #[inline]
    pub unsafe fn append(&mut self, len: u16) -> Option<&mut [u8]> {
        let tail = unsafe { ffi::rte_pktmbuf_append(self.raw.as_ptr(), len) };
        if tail.is_null() {
            None
        } else {
            Some(unsafe { slice::from_raw_parts_mut(tail, len as usize) })
        }
    }
}

impl Drop for Mbuf {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: we own this mbuf and only drop once; after this the pointer
        // is never used again.
        unsafe { ffi::rte_pktmbuf_free(self.raw.as_ptr()) };
    }
}

// An mbuf is a plain owned resource; it can move between threads. It is not
// `Sync` because concurrent access to the underlying buffer is unsynchronised.
unsafe impl Send for Mbuf {}
