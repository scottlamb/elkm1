// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parses a data stream of framed packets and ensure they round-trip.
//!
//! This covers the invalid framing decode cases which `encode` does not.

#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut left = BytesMut::from(data);
    let mut out = BytesMut::new();
    while let Some(pkt) = elkm1::pkt::Packet::decode(&mut left) {
        //println!("{}/{} bytes left after removing: {:?}", left.len(), data.len(), &pkt);
        let _ = elkm1::msg::Message::parse(&pkt);
        pkt.encode(&mut out);
    }
    //println!("{}/{} bytes left", left.len(), data.len());
    out.extend_from_slice(&left[..]);
    assert_eq!(&out[..], data);
});
