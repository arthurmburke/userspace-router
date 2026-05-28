//! Wire-format primitives shared by every header in this module.
//!
//! Two ideas do all the work here:
//!
//! 1. [`U16Be`] / [`U32Be`] store integers in **network byte order** as raw
//!    byte arrays. Because they are `[u8; N]` under the hood they have an
//!    alignment of 1, so a header built from them never gains padding and can
//!    sit at *any* offset inside a packet buffer. You can only read the host
//!    value through [`U16Be::get`], which makes accidental native-endian access
//!    impossible.
//!
//! 2. [`Pod`] marks a header as "plain bytes, valid for any bit pattern,
//!    alignment 1". Anything `Pod` can be reinterpreted in place from a byte
//!    slice via [`ref_from`] / [`mut_from`] with no copy — the returned
//!    reference borrows straight into the underlying buffer (e.g. an mbuf's
//!    data region), so writes through it mutate the packet directly.

use core::mem::{align_of, size_of};

/// Number of bytes in a 32-bit word. Several headers (IPv4 IHL, TCP data
/// offset) express their length as a count of these words.
pub const WORD_BYTES: usize = 4;

/// The alignment every [`Pod`] must have. It is 1 so that a header can be read
/// from *any* byte offset within a packet buffer without violating alignment.
const POD_ALIGN: usize = 1;

/// A `u16` stored in network (big-endian) byte order.
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct U16Be([u8; 2]);

impl U16Be {
    #[inline]
    pub const fn new(host: u16) -> Self {
        Self(host.to_be_bytes())
    }
    /// The value in host byte order.
    #[inline]
    pub const fn get(self) -> u16 {
        u16::from_be_bytes(self.0)
    }
    #[inline]
    pub fn set(&mut self, host: u16) {
        self.0 = host.to_be_bytes();
    }
}

impl From<u16> for U16Be {
    #[inline]
    fn from(v: u16) -> Self {
        Self::new(v)
    }
}
impl From<U16Be> for u16 {
    #[inline]
    fn from(v: U16Be) -> Self {
        v.get()
    }
}
impl core::fmt::Debug for U16Be {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.get())
    }
}

/// A `u32` stored in network (big-endian) byte order.
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct U32Be([u8; 4]);

impl U32Be {
    #[inline]
    pub const fn new(host: u32) -> Self {
        Self(host.to_be_bytes())
    }
    #[inline]
    pub const fn get(self) -> u32 {
        u32::from_be_bytes(self.0)
    }
    #[inline]
    pub fn set(&mut self, host: u32) {
        self.0 = host.to_be_bytes();
    }
}

impl From<u32> for U32Be {
    #[inline]
    fn from(v: u32) -> Self {
        Self::new(v)
    }
}
impl From<U32Be> for u32 {
    #[inline]
    fn from(v: U32Be) -> Self {
        v.get()
    }
}
impl core::fmt::Debug for U32Be {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.get())
    }
}

/// Marker for header types that can be reinterpreted directly from packet bytes.
///
/// # Safety
///
/// Implementors must:
/// - be `#[repr(C)]` or `#[repr(transparent)]`,
/// - contain only fields that are themselves valid for any bit pattern
///   (`u8`, `[u8; N]`, [`U16Be`], [`U32Be`], or other `Pod`s), and
/// - have `align_of::<Self>() == 1`, so that any byte offset is a valid
///   location for the type.
///
/// All three hold for the header structs in this module, which is what makes
/// the zero-copy casts below sound.
pub unsafe trait Pod: Sized {}

/// Reinterpret the start of `buf` as `&T`. Returns `None` if `buf` is shorter
/// than `T`.
#[inline]
pub fn ref_from<T: Pod>(buf: &[u8]) -> Option<&T> {
    ref_from_prefix(buf).map(|(hdr, _)| hdr)
}

/// Reinterpret the start of `buf` as `&mut T`. Returns `None` if `buf` is
/// shorter than `T`. Writes through the result mutate `buf` in place.
#[inline]
pub fn mut_from<T: Pod>(buf: &mut [u8]) -> Option<&mut T> {
    mut_from_prefix(buf).map(|(hdr, _)| hdr)
}

/// Like [`ref_from`] but also returns the bytes that follow the header, which
/// is convenient for peeling successive layers (eth -> ip -> tcp -> payload).
#[inline]
pub fn ref_from_prefix<T: Pod>(buf: &[u8]) -> Option<(&T, &[u8])> {
    debug_assert_eq!(
        align_of::<T>(),
        POD_ALIGN,
        "Pod types must have alignment 1"
    );
    if buf.len() < size_of::<T>() {
        return None;
    }
    let (head, tail) = buf.split_at(size_of::<T>());
    // SAFETY: `head` is exactly `size_of::<T>()` bytes, `T: Pod` is valid for
    // any bit pattern, and alignment 1 means `head.as_ptr()` is always aligned.
    Some((unsafe { &*(head.as_ptr() as *const T) }, tail))
}

/// Mutable counterpart of [`ref_from_prefix`].
#[inline]
pub fn mut_from_prefix<T: Pod>(buf: &mut [u8]) -> Option<(&mut T, &mut [u8])> {
    debug_assert_eq!(
        align_of::<T>(),
        POD_ALIGN,
        "Pod types must have alignment 1"
    );
    if buf.len() < size_of::<T>() {
        return None;
    }
    let (head, tail) = buf.split_at_mut(size_of::<T>());
    // SAFETY: see `ref_from_prefix`; `head` is uniquely borrowed for `'a`.
    Some((unsafe { &mut *(head.as_mut_ptr() as *mut T) }, tail))
}
