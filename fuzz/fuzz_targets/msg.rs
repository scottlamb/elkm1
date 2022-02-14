// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tries to encode an unframed packet. If it succeeds, ensure it round-trips.

#![no_main]

use libfuzzer_sys::fuzz_target;

use elkm1::msg::Message;

fuzz_target!(|msg: Message| {
    let pkt = msg.to_pkt();
    assert_eq!(msg, Message::parse(&pkt).unwrap().unwrap());
});
