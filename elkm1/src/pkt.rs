// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lowest protocol layer: framing and unframing packets.

use bytes::{Buf as _, BufMut, BytesMut};
use pretty_hex::PrettyHex as _;

const RP_HEADER: [u8; 2] = [0x10, 0x02];
const RP_FOOTER: [u8; 2] = [0x10, 0x03];

/// A valid packet in either supported protocol, or bytes representing an invalid packet.
///
/// It's guaranteed that any decoded sequence of packets encodes into exactly the same bytes,
/// or vice versa.
#[derive(Clone, Debug, PartialEq)]
pub enum Packet {
    Ascii(AsciiPacket),
    Rp(RpPacket),
    Invalid(InvalidPacket),
}

impl Packet {
    /// Attempts to decode and remove a packet from the start of `src`.
    ///
    /// 1.  If `src` starts with a full, valid packet, returns `Some(Packet::Ascii(_))` or
    ///     `Some(Packet::Rp(_))`.
    /// 2.  If `src` contains a prefix of a valid packet, returns `None`.
    /// 3.  Otherwise, returns `Some(Packet::Invalid(_))` or `None`. Attempts to resynchronize
    ///     after garbage data, but details may change from version to version. May be confused by
    ///     line noise that corrupts ASCII packets' length and CRLF or RP packets' `DTE STX` and
    ///     `DTE EXT`.
    pub fn decode(src: &mut BytesMut) -> Option<Self> {
        if src.len() < 2 {
            return None; // not a complete packet
        }
        if src.starts_with(&RP_HEADER) {
            RpPacket::decode(src)
                .transpose()
                .map(|o| o.map(Packet::Rp).unwrap_or_else(Packet::Invalid))
        } else if let Ok(len) = AsciiPacket::dehex_byte(src[0], src[1]) {
            let len = 4 + usize::from(len); // include the checksum and CRLF.
            let raw = src.get(0..len)?;
            let pkt = AsciiPacket::decode(raw)
                .map(Packet::Ascii)
                .unwrap_or_else(|e| {
                    Packet::Invalid(InvalidPacket {
                        raw: raw.to_owned(),
                        reason: e,
                    })
                });
            src.advance(len);
            Some(pkt)
        } else {
            // Scan for the next place that is the plausible start of an RP or ASCII packet.
            let mut pos = 0;
            while pos < InvalidPacket::MAX_LEN {
                if pos + 2 == src.len() {
                    return None;
                }
                if src[pos..].starts_with(&RP_HEADER)
                    || AsciiPacket::dehex_byte(src[pos], src[pos + 1]).is_ok()
                {
                    break;
                }
                pos += 1;
            }
            let raw = src[..pos].to_owned();
            src.advance(pos);
            Some(Packet::Invalid(InvalidPacket {
                raw,
                reason: "bytes without ASCII length or RP prefix".to_owned(),
            }))
        }
    }

    pub fn encode(&self, to: &mut BytesMut) {
        match self {
            Packet::Ascii(msg) => msg.encode(to),
            Packet::Rp(msg) => msg.encode(to),
            Packet::Invalid(msg) => to.put_slice(&msg.raw),
        }
    }
}

impl From<AsciiPacket> for Packet {
    fn from(msg: AsciiPacket) -> Self {
        Packet::Ascii(msg)
    }
}

impl From<RpPacket> for Packet {
    fn from(v: RpPacket) -> Self {
        Self::Rp(v)
    }
}

impl From<InvalidPacket> for Packet {
    fn from(v: InvalidPacket) -> Self {
        Self::Invalid(v)
    }
}

/// Bytes that don't necessarily represent a valid packet.
#[derive(Clone)]
pub struct InvalidPacket {
    reason: String,
    raw: Vec<u8>,
}

impl InvalidPacket {
    const MAX_LEN: usize = 1024;

    pub fn reason(&self) -> &str {
        self.reason.as_str()
    }

    pub fn raw(&self) -> &[u8] {
        self.raw.as_slice()
    }
}

impl std::fmt::Debug for InvalidPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvalidPacket")
            .field("reason", &self.reason)
            .field("raw", &self.raw.hex_dump())
            .finish()
    }
}

impl std::fmt::Display for InvalidPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "invalid packet: {}\nraw data:\n{:?}",
            &self.reason,
            &self.raw.hex_dump()
        )
    }
}

impl std::error::Error for InvalidPacket {}

/// Compares the bytes only, not the reason the packet is invalid.
impl PartialEq for InvalidPacket {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

/// An ASCII packet.
///
/// The `Deref<[u8]>` and [`TryFrom`] impls deal with the body (not the framing).
///
///
/// ```text
/// NNMSD...OO CC (CR-LF)
///   ^^^^^^^^ included bytes
/// ```
///
/// Included bytes:
///
/// *   `M`: message type
/// *   `S`: message subtype
/// *   `D...`: data
/// *   `OO`: reserved for future expansion
///
/// Omitted bytes:
///
/// *   `NN`: message length
/// *   `CC`: message checksum
/// *   `(CR-LF)`: line ending
///
/// Every `AsciiPacket`'s body meets the follow constraints:
///
/// * contains only printable ASCII characters.
/// * has length within \[2, 253\], as required by the framing:
///   * all messages must start with message type and subtype bytes.
///   * the message length (of the included bytes and the checksum) must fit in 2 hexadigits.
///
/// To decode a framed packet, see [`Packet::decode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsciiPacket(String);

impl AsciiPacket {
    /// Decodes a framed packet.
    ///
    /// Caller is expected to have already decoded the length and provided exactly one framed
    /// packet, up to and including the trailing `\r\n`.
    fn decode(raw: &[u8]) -> Result<Self, String> {
        let (until_csum, csum_hi, csum_lo) = match raw {
            [d @ .., csum_hi, csum_lo, b'\r', b'\n'] if d.len() >= 4 => (d, *csum_hi, *csum_lo),
            [.., b'\r', b'\n'] => return Err("ASCII packet too short".to_owned()),
            _ => return Err("ASCII packet must end with CRLF".to_owned()),
        };
        let actual_checksum = Self::dehex_byte(csum_hi, csum_lo)
            .map_err(|()| "ASCII packet has unparseable checksum".to_owned())?;
        let expected_checksum = Self::checksum(until_csum);
        if actual_checksum != expected_checksum {
            return Err(format!(
                "ASCII packet doesn't have expected checksum {:02X}",
                expected_checksum
            ));
        }
        AsciiPacket::try_from(&until_csum[2..])
    }

    fn encode(&self, to: &mut BytesMut) {
        to.reserve(6 + self.len());
        let encoded_len = Self::hex_byte(2 + self.0.len() as u8);
        let checksum =
            Self::checksum(&encoded_len[..]).wrapping_add(Self::checksum(self.as_bytes()));
        to.put_slice(&encoded_len[..]);
        to.put_slice(self.0.as_bytes());
        to.put_slice(&Self::hex_byte(checksum)[..]);
        to.put_slice(b"\r\n");
    }

    /// Computes the hexadecimal two’s complement of the modulo-256 sum of the given bytes.
    ///
    /// As specified in section 4.1.6 of the protocol specification.
    fn checksum(bytes: &[u8]) -> u8 {
        bytes.iter().fold(0u8, |acc, &b| acc.wrapping_sub(b))
    }

    /// Decodes an uppercase ASCII hexadigit into `[0, 16)` or returns `Err`.
    pub(crate) fn dehex_nibble(nibble: u8) -> Result<u8, ()> {
        match nibble {
            b'0'..=b'9' => Ok(nibble - b'0'),
            b'A'..=b'F' => Ok(nibble - b'A' + 10),
            _ => Err(()),
        }
    }

    /// Decodes two uppercase ASCII hexadigits into a `u8` or returns `Err`.
    pub(crate) fn dehex_byte(high_nibble: u8, low_nibble: u8) -> Result<u8, ()> {
        Ok(Self::dehex_nibble(high_nibble)? << 4 | Self::dehex_nibble(low_nibble)?)
    }

    /// Encodes the less significant nibble of `nibble` into an ASCII hexadigit.
    pub(crate) fn hex_nibble(nibble: u8) -> u8 {
        #[rustfmt::skip]
        const HEX_CHARS: [u8; 16] = [
            b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7',
            b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F',
        ];
        HEX_CHARS[usize::from(nibble & 0xF)]
    }

    /// Encodes a `u8` into two uppercase ASCII hexadigits.
    pub(crate) fn hex_byte(byte: u8) -> [u8; 2] {
        [Self::hex_nibble(byte >> 4), Self::hex_nibble(byte)]
    }

    /// Checks that `data` contains only printable ASCII characters.
    pub(crate) fn check_printable(value: &[u8]) -> Result<(), String> {
        if let Some(i) = value.iter().position(|&b| b < 0x20 || b > 0x7e) {
            return Err(format!("non-printable character at index {}", i));
        }
        Ok(())
    }
}

impl std::convert::TryFrom<Vec<u8>> for AsciiPacket {
    type Error = String;

    #[inline(never)]
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::check_printable(&value)?;
        // SAFETY: printable ASCII => valid UTF-8.
        let value = unsafe { String::from_utf8_unchecked(value) };
        if value.len() < 2 || value.len() > 253 {
            return Err(format!(
                "ASCII packet body length {} not in [2, 253].\nbody:\n{:?}",
                value.len(),
                &value
            ));
        }
        Ok(AsciiPacket(value))
    }
}

impl std::convert::TryFrom<String> for AsciiPacket {
    type Error = String;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.into_bytes())
    }
}

impl std::convert::TryFrom<&str> for AsciiPacket {
    type Error = String;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.as_bytes().to_owned())
    }
}

impl std::convert::TryFrom<&[u8]> for AsciiPacket {
    type Error = String;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl std::ops::Deref for AsciiPacket {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A binary packet as used by Elk's RP (remote programming) software.
///
/// The `Deref<[u8]` and `TryFrom` impls refer to the body, not the framing.
///
/// This format is undocumented. From reverse engineering, packets appear to be framed as follows:
///
/// 1. a `0x10 0x02` sequence (aka DLE STX).
/// 2. the body, with any `0x10` bytes escaped to `0x10 0x10`.
/// 3. a `0x10 0x03` sequence (aka DLE ETX).
/// 4. a CRC-16/XMODEM of the unescaped data, most significant byte first.
///
/// Currently the length including framing/escapes is limited to 1,024. I've observed a 604-bytea
/// packet; 1,024 is the next power of two.
///
/// To decode a framed packet, see [`Packet::decode`].
#[derive(Clone, PartialEq, Eq)]
pub struct RpPacket(Vec<u8>);

impl RpPacket {
    const MAX_LEN: usize = 1024;

    fn decode(src: &mut BytesMut) -> Result<Option<Self>, InvalidPacket> {
        assert!(src.len() >= 2); // enforced by Packet::decode.
        debug_assert_eq!(&src[0..2], &RP_HEADER); // likewise.
        let mut data = Vec::new();
        let buf = &src[0..std::cmp::min(src.len(), Self::MAX_LEN)];
        let mut pos = 2;
        let mut bad_escape = None;
        while let Some(rel) = memchr::memchr(0x10, &buf[pos..]) {
            match buf.get(pos + rel + 1) {
                None => return Self::decode_unfinished(src),
                Some(0x10) => {
                    data.put_slice(&buf[pos..pos + rel + 1]);
                    pos += rel + 2;
                }
                Some(0x03) => {
                    data.put_slice(&buf[pos..pos + rel]);
                    let crc = match buf.get(..pos + rel + 4) {
                        Some([.., hi, lo]) => u16::from_be_bytes([*hi, *lo]),
                        _ => return Ok(None),
                    };
                    let expected = Self::crc(&data);
                    let pkt = if expected != crc {
                        Err(InvalidPacket {
                            raw: buf[..pos + rel + 4].to_owned(),
                            reason: format!("RP packet doesn't have expected CRC {:02X}", expected),
                        })
                    } else {
                        Ok(Some(RpPacket(data)))
                    };
                    src.advance(pos + rel + 4);
                    return pkt;
                }
                Some(&b) => {
                    bad_escape = Some(b);
                    pos += rel + 1;
                    break;
                }
            }
        }
        if let Some(b) = bad_escape {
            let raw = src[0..pos].to_owned();
            src.advance(pos);
            return Err(InvalidPacket {
                raw,
                reason: format!("RP packet has bad sequence DTS {:02X}", b),
            });
        }
        Self::decode_unfinished(src)
    }

    #[cold]
    fn decode_unfinished(src: &mut BytesMut) -> Result<Option<Self>, InvalidPacket> {
        if src.len() >= Self::MAX_LEN {
            let raw = src[0..Self::MAX_LEN].to_owned();
            src.advance(Self::MAX_LEN);
            return Err(InvalidPacket {
                raw,
                reason: format!("RP packet has no DLE EXT after {} bytes", Self::MAX_LEN),
            });
        }
        Ok(None)
    }

    fn encode(&self, to: &mut BytesMut) {
        to.reserve(self.0.len() + 4); // at least this many bytes are needed
        to.put_slice(&RP_HEADER);
        let mut input_pos = 0;
        while let Some(off) = memchr::memchr(0x10, &self.0[input_pos..]) {
            to.put_slice(&self.0[input_pos..=input_pos + off]);
            to.put_u8(0x10);
            input_pos += off + 1;
        }
        to.put_slice(&self.0[input_pos..]);
        to.put_slice(&RP_FOOTER);
        to.put_slice(&Self::crc(&self.0[..]).to_be_bytes());
    }

    /// Calculates CRC-16/XMODEM on `data`.
    fn crc(data: &[u8]) -> u16 {
        const fn table_entry(b: u8) -> u16 {
            let mut crc = (b as u16) << 8;
            // `for` isn't allowed in const fns yet, so use `while` instead.
            let mut i = 0;
            while i < 8 {
                crc = (crc << 1) ^ if (crc & 0x8000) != 0 { 0x1021 } else { 0 };
                i += 1;
            }
            crc
        }

        const TABLE: [u16; 256] = {
            let mut table = [0u16; 256];
            let mut i = 0;
            while i < 256 {
                table[i] = table_entry(i as u8);
                i += 1;
            }
            table
        };

        data.iter().fold(0u16, |crc, &b| {
            let i = (crc >> 8) as u8 ^ b;
            TABLE[usize::from(i)] ^ (crc << 8)
        })
    }
}

impl std::fmt::Display for RpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        pretty_hex::pretty_hex_write(f, &self.0)
    }
}

impl std::fmt::Debug for RpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RpPacket").field(&self.0.hex_dump()).finish()
    }
}

impl std::convert::TryFrom<Vec<u8>> for RpPacket {
    type Error = String;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let escapes = value.iter().filter(|&&b| b == 0x10).count();
        if 6 + value.len() + escapes > Self::MAX_LEN {
            return Err(format!(
                "{}-byte body that requires {} escapes exceeds maximum framed length {}",
                value.len(),
                escapes,
                Self::MAX_LEN
            ));
        }
        Ok(RpPacket(value))
    }
}

impl std::convert::TryFrom<&[u8]> for RpPacket {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ascii() {
        let as_bytes: &[u8] = &b"0FEE11030000100EA\r\n"[..];
        let mut buf = BytesMut::from(as_bytes);
        let msg = Packet::decode(&mut buf).unwrap();
        assert_eq!(buf.len(), 0);
        assert_eq!(msg, AsciiPacket::try_from("EE11030000100").unwrap().into());
        msg.encode(&mut buf);
        assert_eq!(&buf[..], as_bytes);
    }

    #[test]
    fn valid_rp() {
        let as_bytes: &[u8] = &b"\x10\x02foo\x10\x03\xaf\x96"[..];
        let data = &b"foo"[..];
        let mut buf = BytesMut::from(as_bytes);
        let msg = Packet::decode(&mut buf).unwrap();
        assert_eq!(buf.len(), 0);
        assert_eq!(msg, RpPacket::try_from(data).unwrap().into());
        msg.encode(&mut buf);
        assert_eq!(&buf[..], as_bytes);
    }

    #[test]
    fn valid_rp_with_escape() {
        let as_bytes: &[u8] = &b"\x10\x02foo\x10\x10bar\x10\x03\x7c\x63"[..];
        let data: &[u8] = &b"foo\x10bar"[..];
        let mut buf = BytesMut::from(as_bytes);
        let msg = Packet::decode(&mut buf).unwrap();
        assert_eq!(buf.len(), 0);
        assert_eq!(msg, RpPacket::try_from(data).unwrap().into());
        msg.encode(&mut buf);
        assert_eq!(&buf[..], as_bytes);
    }

    #[test]
    fn bad_prefix() {
        let as_bytes: &[u8] = &b"\xde\xad\xbe\xef0FEE11030000100EA\r\n\xde\xad\xbe\xef"[..];
        let mut buf = BytesMut::from(as_bytes);
        assert!(matches!(
            Packet::decode(&mut buf).unwrap(),
            Packet::Invalid(_)
        ));
        assert_eq!(
            Packet::decode(&mut buf).unwrap(),
            AsciiPacket::try_from("EE11030000100").unwrap().into()
        );
        assert!(Packet::decode(&mut buf).is_none());
    }
}
