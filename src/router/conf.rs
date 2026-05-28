//! Structures for router configuration. Router configuration allows the
//! user to configure specific ports by interface name to a role (WAN OR LAN)
//! and assign an IP address to the router on that interface.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::net::util::Netmask;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RouterConfig {
    pub interfaces: Vec<InterfaceConfig>,
    pub lan: LanConfig,
    pub dhcp: DhcpConfig,
    pub dns: Dns,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InterfaceConfig {
    pub name: String,
    pub role: InterfaceRole,
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceRole {
    Wan,
    Lan,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LanConfig {
    pub ip: Ipv4Addr,
    pub mask: Netmask,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DhcpConfig {
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Alias {
    pub ip: Ipv4Addr,
    pub fqdn: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Dns {
    pub servers: Vec<Ipv4Addr>,
    pub search_domains: Vec<String>,
    pub aliases: Vec<Alias>,
}
