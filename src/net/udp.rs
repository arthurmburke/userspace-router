//! UDP header.

use crate::net::wire::{Pod, U16Be};

/// Fixed 8-byte UDP header.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct UdpHeader {
    src_port: U16Be,
    dst_port: U16Be,
    length: U16Be,
    checksum: U16Be,
}

unsafe impl Pod for UdpHeader {}

impl UdpHeader {
    pub const LEN: usize = 8;

    #[inline]
    pub fn src_port(&self) -> u16 {
        self.src_port.get()
    }
    #[inline]
    pub fn set_src_port(&mut self, v: u16) {
        self.src_port.set(v);
    }
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.dst_port.get()
    }
    #[inline]
    pub fn set_dst_port(&mut self, v: u16) {
        self.dst_port.set(v);
    }

    /// Length of the UDP header plus payload, in bytes.
    #[inline]
    pub fn length(&self) -> u16 {
        self.length.get()
    }
    #[inline]
    pub fn set_length(&mut self, v: u16) {
        self.length.set(v);
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        self.checksum.get()
    }
    #[inline]
    pub fn set_checksum(&mut self, v: u16) {
        self.checksum.set(v);
    }
}
