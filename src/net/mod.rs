//! Zero-copy packet header views.
//!
//! Every header here is a `#[repr(C)]` struct of network-order fields with
//! alignment 1 (see [`wire`]). To parse a packet you reinterpret the mbuf's
//! data slice in place — no allocation, no copy. Mutating a view mutates the
//! packet bytes directly:
//!
//! ```ignore
//! use quicktcp::net::{wire, ethernet::EthernetHeader, ip::Ipv4Header};
//!
//! let buf: &mut [u8] = mbuf.data_mut();
//! let (eth, rest) = wire::mut_from_prefix::<EthernetHeader>(buf)?;
//! if eth.ethertype() == ethernet::ethertype::IPV4 {
//!     let (ip, _payload) = wire::mut_from_prefix::<Ipv4Header>(rest)?;
//!     ip.set_ttl(ip.ttl() - 1); // edits the mbuf in place
//! }
//! ```

pub mod wire;

pub mod arp;
pub mod checksum;
pub mod dhcp;
pub mod dns;
pub mod ethernet;
pub mod ip;
pub mod tcp;
pub mod udp;
pub mod util;
pub mod view;
