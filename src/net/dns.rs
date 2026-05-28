//! DNS message header.
//!
//! Only the fixed 12-byte header is a struct; questions and resource records
//! are variable-length and use name compression, so they are parsed from the
//! bytes that follow rather than cast in place.

use crate::net::wire::{Pod, U16Be};

// Layout of the 16-bit flags field:
//   QR(1) | Opcode(4) | AA(1) | TC(1) | RD(1) | RA(1) | Z(3) | RCODE(4)
/// QR bit set => message is a response.
const FLAG_QR_RESPONSE: u16 = 0x8000;
/// Bit shift to the 4-bit opcode field.
const OPCODE_SHIFT: u32 = 11;
/// Mask for the opcode once shifted to the low bits.
const OPCODE_MASK: u16 = 0x0f;
/// Authoritative Answer bit.
const FLAG_AUTHORITATIVE: u16 = 0x0400;
/// TrunCation bit.
const FLAG_TRUNCATED: u16 = 0x0200;
/// Recursion Desired bit.
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
/// Recursion Available bit.
const FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
/// Mask for the 4-bit response code in the low bits.
const RCODE_MASK: u16 = 0x000f;

/// QR bit: query vs. response.
pub mod qr {
    pub const QUERY: u8 = 0;
    pub const RESPONSE: u8 = 1;
}

/// OPCODE values.
pub mod opcode {
    pub const QUERY: u8 = 0;
    pub const IQUERY: u8 = 1;
    pub const STATUS: u8 = 2;
    pub const NOTIFY: u8 = 4;
    pub const UPDATE: u8 = 5;
}

/// RCODE values (response code).
pub mod rcode {
    pub const NO_ERROR: u8 = 0;
    pub const FORMAT_ERROR: u8 = 1;
    pub const SERVER_FAILURE: u8 = 2;
    pub const NAME_ERROR: u8 = 3;
    pub const NOT_IMPLEMENTED: u8 = 4;
    pub const REFUSED: u8 = 5;
}

/// Common record types (used in questions and answers).
pub mod record_type {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
}

/// Fixed 12-byte DNS header.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct DnsHeader {
    id: U16Be,
    /// Packed flags: QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4).
    flags: U16Be,
    qdcount: U16Be,
    ancount: U16Be,
    nscount: U16Be,
    arcount: U16Be,
}

unsafe impl Pod for DnsHeader {}

impl DnsHeader {
    pub const LEN: usize = 12;

    #[inline]
    pub fn id(&self) -> u16 {
        self.id.get()
    }
    #[inline]
    pub fn set_id(&mut self, v: u16) {
        self.id.set(v);
    }

    /// `false` for a query, `true` for a response.
    #[inline]
    pub fn is_response(&self) -> bool {
        self.flags.get() & FLAG_QR_RESPONSE != 0
    }
    #[inline]
    pub fn opcode(&self) -> u8 {
        ((self.flags.get() >> OPCODE_SHIFT) & OPCODE_MASK) as u8
    }
    /// Authoritative answer.
    #[inline]
    pub fn authoritative(&self) -> bool {
        self.flags.get() & FLAG_AUTHORITATIVE != 0
    }
    /// Truncation.
    #[inline]
    pub fn truncated(&self) -> bool {
        self.flags.get() & FLAG_TRUNCATED != 0
    }
    /// Recursion desired.
    #[inline]
    pub fn recursion_desired(&self) -> bool {
        self.flags.get() & FLAG_RECURSION_DESIRED != 0
    }
    /// Recursion available.
    #[inline]
    pub fn recursion_available(&self) -> bool {
        self.flags.get() & FLAG_RECURSION_AVAILABLE != 0
    }
    #[inline]
    pub fn rcode(&self) -> u8 {
        (self.flags.get() & RCODE_MASK) as u8
    }
    #[inline]
    pub fn set_flags(&mut self, v: u16) {
        self.flags.set(v);
    }
    #[inline]
    pub fn flags(&self) -> u16 {
        self.flags.get()
    }

    /// Number of entries in the question section.
    #[inline]
    pub fn question_count(&self) -> u16 {
        self.qdcount.get()
    }
    /// Number of resource records in the answer section.
    #[inline]
    pub fn answer_count(&self) -> u16 {
        self.ancount.get()
    }
    /// Number of name-server resource records in the authority section.
    #[inline]
    pub fn authority_count(&self) -> u16 {
        self.nscount.get()
    }
    /// Number of resource records in the additional section.
    #[inline]
    pub fn additional_count(&self) -> u16 {
        self.arcount.get()
    }

    #[inline]
    pub fn set_question_count(&mut self, v: u16) {
        self.qdcount.set(v);
    }
    #[inline]
    pub fn set_answer_count(&mut self, v: u16) {
        self.ancount.set(v);
    }
}
