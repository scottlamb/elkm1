// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use bytes::BytesMut;
use clap::Parser;
use elkm1::{msg::NUM_AREAS, state::Change};
use futures::StreamExt;
use pretty_hex::PrettyHex;

#[derive(Parser)]
enum Cmd {
    Watch { addr: String },
    Read { filename: PathBuf },
}

async fn watch(addr: String) {
    let panel = elkm1::state::Panel::connect(&addr).await.unwrap();
    log::info!("Tracking changes.");
    tokio::pin!(panel);
    while let Some(pkt) = panel.next().await {
        let pkt = pkt.unwrap();
        log::debug!("received {:#?}", &pkt);
        match pkt.change {
            Some(Change::ZoneChange { zone, prior }) => {
                log::info!(
                    "{}: {:?} -> {:?}",
                    panel.zone_name(zone),
                    prior,
                    panel.zone_statuses().zones[zone.to_index()],
                );
            }
            Some(Change::ArmingStatus { prior }) => {
                let cur = panel.arming_status();
                let area_names = panel.area_names();
                for i in 0..NUM_AREAS {
                    if prior.arming_status[i] != cur.arming_status[i]
                        || prior.up_state[i] != cur.up_state[i]
                        || prior.alarm_state[i] != cur.alarm_state[i]
                    {
                        log::info!(
                            "{}: {:?} {:?} {:?} -> {:?} {:?} {:?}",
                            area_names[i],
                            prior.arming_status[i],
                            prior.up_state[i],
                            prior.alarm_state[i],
                            cur.arming_status[i],
                            cur.up_state[i],
                            cur.alarm_state[i],
                        );
                    }
                }
            }
            _ => {}
        }
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
        Cmd::Watch { addr } => watch(addr).await,
        Cmd::Read { filename } => read(filename),
    }
}
