//! IPv4 header.

use crate::net::wire::{Pod, U16Be, U32Be, WORD_BYTES};
use std::net::Ipv4Addr;

/// Bit shift to extract the 4-bit version from the combined version/IHL byte.
const VERSION_SHIFT: u8 = 4;
/// Mask for the IHL nibble in the combined version/IHL byte.
const IHL_MASK: u8 = 0x0f;
/// Don't Fragment flag within the 16-bit flags/fragment-offset field.
const FLAG_DONT_FRAGMENT: u16 = 0x4000;
/// More Fragments flag within the 16-bit flags/fragment-offset field.
const FLAG_MORE_FRAGMENTS: u16 = 0x2000;
/// Mask for the 13-bit fragment offset within the flags/fragment field.
const FRAGMENT_OFFSET_MASK: u16 = 0x1fff;

/// IP protocol numbers (the `protocol` field).
pub mod proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
}

/// Fixed 20-byte IPv4 header. Options (when `ihl > 5`) follow it.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Ipv4Header {
    /// High nibble: version. Low nibble: IHL (header length in 32-bit words).
    version_ihl: u8,
    /// High 6 bits DSCP, low 2 bits ECN.
    pub dscp_ecn: u8,
    total_len: U16Be,
    pub identification: U16Be,
    flags_fragment: U16Be,
    pub ttl: u8,
    pub protocol: u8,
    checksum: U16Be,
    src: [u8; 4],
    dst: [u8; 4],
}

unsafe impl Pod for Ipv4Header {}

impl Ipv4Header {
    /// Length of the fixed header, without options.
    pub const MIN_LEN: usize = 20;

    #[inline]
    pub fn version(&self) -> u8 {
        self.version_ihl >> VERSION_SHIFT
    }
    /// Internet Header Length, in 32-bit words.
    #[inline]
    pub fn ihl(&self) -> u8 {
        self.version_ihl & IHL_MASK
    }
    /// Total header length in bytes (`ihl * WORD_BYTES`); where the L4 payload
    /// begins.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.ihl() as usize * WORD_BYTES
    }
    #[inline]
    pub fn set_version_ihl(&mut self, version: u8, ihl: u8) {
        self.version_ihl = (version << VERSION_SHIFT) | (ihl & IHL_MASK);
    }

    #[inline]
    pub fn total_len(&self) -> u16 {
        self.total_len.get()
    }
    #[inline]
    pub fn set_total_len(&mut self, v: u16) {
        self.total_len.set(v);
    }

    #[inline]
    pub fn dont_fragment(&self) -> bool {
        self.flags_fragment.get() & FLAG_DONT_FRAGMENT != 0
    }
    #[inline]
    pub fn more_fragments(&self) -> bool {
        self.flags_fragment.get() & FLAG_MORE_FRAGMENTS != 0
    }
    /// Fragment offset in 8-byte units.
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        self.flags_fragment.get() & FRAGMENT_OFFSET_MASK
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        self.checksum.get()
    }
    #[inline]
    pub fn set_checksum(&mut self, v: u16) {
        self.checksum.set(v);
    }

    #[inline]
    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.src)
    }
    #[inline]
    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.dst)
    }
    #[inline]
    pub fn set_src(&mut self, addr: Ipv4Addr) {
        self.src = addr.octets();
    }
    #[inline]
    pub fn set_dst(&mut self, addr: Ipv4Addr) {
        self.dst = addr.octets();
    }

    /// Pseudo-header words used by TCP/UDP checksum computation.
    #[inline]
    pub fn src_words(&self) -> U32Be {
        U32Be::new(u32::from_be_bytes(self.src))
    }
    #[inline]
    pub fn dst_words(&self) -> U32Be {
        U32Be::new(u32::from_be_bytes(self.dst))
    }
}
