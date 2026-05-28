//! Internet checksum (RFC 1071) plus the IPv4 and UDP checksums that packet
//! building and NAT rewriting need. Prefer NIC offload on the datapath; this is
//! the software path (packet construction, verification, and incremental NAT
//! fixups).

use crate::net::ip::proto;

/// Protocol number occupies the low byte of a 16-bit pseudo-header word.
const UDP_PROTO_WORD: u32 = proto::UDP as u32;

/// Fold a 32-bit accumulator of 16-bit one's-complement sums down to 16 bits.
fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// Add `data` (as big-endian 16-bit words) into a running one's-complement sum.
/// A trailing odd byte is padded with a zero low byte. Chain this across a
/// pseudo-header and payload, then call [`finish`].
pub fn accumulate(mut acc: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc = acc.wrapping_add(u16::from_be_bytes([c[0], c[1]]) as u32);
    }
    if let [last] = chunks.remainder() {
        acc = acc.wrapping_add(u16::from_be_bytes([*last, 0]) as u32);
    }
    acc
}

/// Final checksum from an accumulator: fold the carries, then one's-complement.
pub fn finish(acc: u32) -> u16 {
    !fold(acc)
}

/// Internet checksum over a single contiguous buffer.
pub fn checksum(data: &[u8]) -> u16 {
    finish(accumulate(0, data))
}

/// IPv4 header checksum. `header` is the header bytes with the checksum field
/// already zeroed; the returned value goes into that field. Verifying instead?
/// Run [`checksum`] over the whole header (checksum included) and expect 0.
pub fn ipv4_header(header: &[u8]) -> u16 {
    checksum(header)
}

/// UDP-over-IPv4 checksum: pseudo-header (`src`, `dst`, proto, length) plus the
/// UDP header and payload. `udp` is the UDP header+payload with its checksum
/// field zeroed. A computed zero is transmitted as `0xFFFF` per RFC 768.
pub fn udp_ipv4(src: [u8; 4], dst: [u8; 4], udp: &[u8]) -> u16 {
    let mut acc = 0u32;
    acc = accumulate(acc, &src);
    acc = accumulate(acc, &dst);
    acc = acc.wrapping_add(UDP_PROTO_WORD);
    acc = acc.wrapping_add(udp.len() as u32); // UDP length appears twice (here + header)
    acc = accumulate(acc, udp);
    match finish(acc) {
        0 => 0xffff,
        v => v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_checksum_verifies_to_zero() {
        // A 20-byte IPv4 header with the checksum field (bytes 10..12) zeroed.
        let mut hdr = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let c = ipv4_header(&hdr);
        hdr[10..12].copy_from_slice(&c.to_be_bytes());
        // Header including the checksum now sums to zero.
        assert_eq!(checksum(&hdr), 0);
    }

    #[test]
    fn udp_checksum_round_trips() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        // UDP header (ports 68->67, len 12, cksum 0) + 4 payload bytes.
        let mut udp = [
            0x00, 68, 0x00, 67, 0x00, 12, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
        ];
        let c = udp_ipv4(src, dst, &udp);
        udp[6..8].copy_from_slice(&c.to_be_bytes());
        // Recomputing over the segment with the checksum in place verifies.
        let mut acc = 0u32;
        acc = accumulate(acc, &src);
        acc = accumulate(acc, &dst);
        acc = acc.wrapping_add(UDP_PROTO_WORD);
        acc = acc.wrapping_add(udp.len() as u32);
        acc = accumulate(acc, &udp);
        assert_eq!(finish(acc), 0);
    }
}
