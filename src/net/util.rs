use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

use crate::net::ethernet::MacAddr;

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Netmask(Ipv4Addr);

impl Netmask {
    pub fn new(netmask: Ipv4Addr) -> Option<Self> {
        netmask_to_prefix(netmask)?;
        Some(Self(netmask))
    }

    pub fn prefix(&self) -> u8 {
        netmask_to_prefix(self.0).unwrap()
    }

    pub fn netmask(&self) -> Ipv4Addr {
        self.0
    }

    pub fn network(&self, ip: Ipv4Addr) -> Ipv4Addr {
        let mask = u32::from(self.0);
        Ipv4Addr::from(u32::from(ip) & mask)
    }
}

impl Serialize for Netmask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let prefix = netmask_to_prefix(self.0)
            .ok_or_else(|| serde::ser::Error::custom(format!("invalid netmask: {}", self.0)))?;
        prefix.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Netmask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let netmask = Ipv4Addr::deserialize(deserializer)?;
        // Check that the netmask is valid (i.e. contiguous ones followed by zeros).
        if netmask_to_prefix(netmask).is_none() {
            return Err(serde::de::Error::custom(format!(
                "invalid netmask: {}",
                netmask
            )));
        }

        Ok(Netmask(netmask))
    }
}

pub fn prefix_to_netmask(prefix: u8) -> Option<Ipv4Addr> {
    if prefix > 32 {
        return None;
    }

    let mask: u32 = if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix)
    };

    Some(std::net::Ipv4Addr::from(mask))
}

pub fn netmask_to_prefix(netmask: Ipv4Addr) -> Option<u8> {
    let mask = u32::from(netmask);
    if mask.count_ones() + mask.trailing_zeros() != 32 {
        return None;
    }
    Some(mask.count_ones() as u8)
}

/// Generate a software defined locally administed MAC address from an IP address, for use in ARP replies when we don't have a real MAC to reply with.
pub fn software_defined_mac(ip: Ipv4Addr) -> MacAddr {
    let mut hasher = Sha256::new();
    hasher.update(ip.to_string().as_bytes());

    let hash = hasher.finalize();

    let mut mac = [0u8; 6];
    mac.copy_from_slice(&hash[..6]);

    // Set locally administered bit (bit 1)
    mac[0] |= 0x02;

    // Clear multicast bit (bit 0)
    mac[0] &= 0xFE;

    mac
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
