// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use bytes::BytesMut;
use clap::Parser;
use elkm1::tokio::Connection;
use futures::StreamExt;
use pretty_hex::PrettyHex;

#[derive(Parser)]
enum Cmd {
    Connect { addr: String },
    Read { filename: PathBuf },
}

async fn connect(addr: String) {
    let conn = Connection::connect(&addr).await.unwrap();
    tokio::pin!(conn);
    while let Some(pkt) = conn.next().await {
        let pkt = pkt.unwrap();
        log::info!("{:?}", pkt);
    }
}

fn read(filename: PathBuf) {
    let data = std::fs::read(filename).unwrap();
    let mut left = BytesMut::from(&data[..]);
    while let Some(pkt) = elkm1::pkt::Packet::decode(&mut left) {
        println!("{:?}", pkt);
    }
    if !left.is_empty() {
        println!("incomplete data: {:?}", left.hex_dump());
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::new().default_filter_or("info")).init();
    match Cmd::parse() {
        Cmd::Connect { addr } => connect(addr).await,
        Cmd::Read { filename } => read(filename),
    }
}
