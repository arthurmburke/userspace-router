//! Ethernet II framing.

use crate::net::wire::{Pod, U16Be};

/// A 48-bit MAC address.
pub type MacAddr = [u8; 6];

pub fn display_mac(mac: &MacAddr) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// All-ones destination MAC: the Ethernet broadcast address.
pub const BROADCAST: MacAddr = [0xff; 6];

/// The I/G (individual/group) bit, i.e. the least-significant bit of a MAC's
/// first octet. When set, the address is a group (multicast) address.
const MULTICAST_BIT: u8 = 0x01;

/// Common EtherType values (host byte order).
pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const IPV6: u16 = 0x86dd;
    pub const VLAN: u16 = 0x8100;
}

/// Ethernet II header: `dst | src | ethertype`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct EthernetHeader {
    pub dst: MacAddr,
    pub src: MacAddr,
    ethertype: U16Be,
}

unsafe impl Pod for EthernetHeader {}

impl EthernetHeader {
    pub const LEN: usize = 14;

    #[inline]
    pub fn ethertype(&self) -> u16 {
        self.ethertype.get()
    }
    #[inline]
    pub fn set_ethertype(&mut self, v: u16) {
        self.ethertype.set(v);
    }

    #[inline]
    pub fn is_broadcast(&self) -> bool {
        self.dst == BROADCAST
    }
    #[inline]
    pub fn is_multicast(&self) -> bool {
        // Index 0 = first transmitted octet, which carries the I/G bit.
        self.dst[0] & MULTICAST_BIT != 0
    }
}

/// Bit position of the 3-bit Priority Code Point within the 16-bit TCI.
const TCI_PCP_SHIFT: u32 = 13;
/// Mask for the Priority Code Point after it has been shifted to the low bits.
const TCI_PCP_MASK: u8 = 0x07;
/// Drop-Eligible Indicator bit within the TCI.
const TCI_DEI_BIT: u16 = 0x1000;
/// Mask for the 12-bit VLAN identifier within the TCI.
const TCI_VID_MASK: u16 = 0x0fff;

/// 802.1Q VLAN tag, sitting between `src` and the (inner) ethertype when the
/// outer ethertype is [`ethertype::VLAN`].
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VlanTag {
    tci: U16Be,
    inner_ethertype: U16Be,
}

unsafe impl Pod for VlanTag {}

impl VlanTag {
    pub const LEN: usize = 4;

    /// Priority code point (3 bits).
    #[inline]
    pub fn pcp(&self) -> u8 {
        (self.tci.get() >> TCI_PCP_SHIFT) as u8 & TCI_PCP_MASK
    }
    /// Drop-eligible indicator (1 bit).
    #[inline]
    pub fn dei(&self) -> bool {
        self.tci.get() & TCI_DEI_BIT != 0
    }
    /// VLAN identifier (12 bits).
    #[inline]
    pub fn vid(&self) -> u16 {
        self.tci.get() & TCI_VID_MASK
    }
    #[inline]
    pub fn set_vid(&mut self, vid: u16) {
        // Preserve the PCP/DEI bits (everything outside the VID mask).
        let tci = (self.tci.get() & !TCI_VID_MASK) | (vid & TCI_VID_MASK);
        self.tci.set(tci);
    }
    #[inline]
    pub fn inner_ethertype(&self) -> u16 {
        self.inner_ethertype.get()
    }
}
