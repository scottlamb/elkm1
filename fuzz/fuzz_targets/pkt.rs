// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tries to encode an unframed packet. If it succeeds, ensure it round-trips.

#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let pkt = match data {
        [0, body @ ..] => elkm1::pkt::AsciiPacket::try_from(body).map(elkm1::pkt::Packet::Ascii),
        [1, body @ ..] => elkm1::pkt::RpPacket::try_from(body).map(elkm1::pkt::Packet::Rp),
        _ => return,
    };
    let pkt = match pkt {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut buf = BytesMut::new();
    pkt.encode(&mut buf);
    assert_eq!(&elkm1::pkt::Packet::decode(&mut buf).unwrap(), &pkt);
    assert!(buf.is_empty());
});
