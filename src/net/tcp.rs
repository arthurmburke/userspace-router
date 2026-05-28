//! TCP header.

use crate::net::wire::{Pod, U16Be, U32Be, WORD_BYTES};

/// Bit shift for the 4-bit data offset in the high nibble of byte 12.
const DATA_OFFSET_SHIFT: u8 = 4;
/// Mask for the low nibble of byte 12 (reserved bits + the NS flag), preserved
/// when rewriting the data offset.
const DATA_OFFSET_LOW_NIBBLE_MASK: u8 = 0x0f;

/// TCP control flags (the low byte at offset 13).
pub mod flag {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// Fixed 20-byte TCP header. Options (when `data_offset > 5`) follow it.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TcpHeader {
    src_port: U16Be,
    dst_port: U16Be,
    seq: U32Be,
    ack: U32Be,
    /// High nibble: data offset (header length in 32-bit words).
    /// Low nibble: reserved bits + the NS flag (bit 0).
    data_offset_reserved: u8,
    pub flags: u8,
    window: U16Be,
    checksum: U16Be,
    urgent_ptr: U16Be,
}

unsafe impl Pod for TcpHeader {}

impl TcpHeader {
    pub const MIN_LEN: usize = 20;

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

    #[inline]
    pub fn seq(&self) -> u32 {
        self.seq.get()
    }
    #[inline]
    pub fn set_seq(&mut self, v: u32) {
        self.seq.set(v);
    }
    #[inline]
    pub fn ack(&self) -> u32 {
        self.ack.get()
    }
    #[inline]
    pub fn set_ack(&mut self, v: u32) {
        self.ack.set(v);
    }

    /// Data offset in 32-bit words.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        self.data_offset_reserved >> DATA_OFFSET_SHIFT
    }
    /// Header length in bytes (`data_offset * WORD_BYTES`); where the payload
    /// begins.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.data_offset() as usize * WORD_BYTES
    }
    #[inline]
    pub fn set_data_offset(&mut self, words: u8) {
        // Keep the reserved/NS bits in the low nibble intact.
        self.data_offset_reserved = (words << DATA_OFFSET_SHIFT)
            | (self.data_offset_reserved & DATA_OFFSET_LOW_NIBBLE_MASK);
    }

    #[inline]
    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
    #[inline]
    pub fn set_flag(&mut self, flag: u8, on: bool) {
        if on {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }

    #[inline]
    pub fn window(&self) -> u16 {
        self.window.get()
    }
    #[inline]
    pub fn set_window(&mut self, v: u16) {
        self.window.set(v);
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
    pub fn urgent_ptr(&self) -> u16 {
        self.urgent_ptr.get()
    }
}
