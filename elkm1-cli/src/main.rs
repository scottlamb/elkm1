// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use bytes::BytesMut;
use clap::Parser;
use elkm1::{msg, state};
use futures::StreamExt;
use pretty_hex::PrettyHex;

#[derive(Parser)]
enum Cmd {
    Watch { addr: String },
    Read { filename: PathBuf },
}

async fn watch(addr: String) {
    let panel = state::Panel::connect(&addr).await.unwrap();
    tracing::info!("tracking changes");
    tokio::pin!(panel);
    while let Some(pkt) = panel.next().await {
        let pkt = pkt.unwrap();
        tracing::debug!(?pkt, "received packet");
        match pkt.change {
            Some(state::Change::ZoneChange { zone, prior }) => {
                tracing::info!(
                    zone.name = %panel.zone_name(zone),
                    prior.state = ?prior,
                    new.state = ?panel.zone_statuses().zones[zone.to_index()],
                    "zone change"
                );
            }
            Some(state::Change::ArmingStatus { prior }) => {
                let cur = panel.arming_status();
                let area_names = panel.area_names();
                for i in 0..msg::NUM_AREAS {
                    if prior.arming_status[i] != cur.arming_status[i]
                        || prior.up_state[i] != cur.up_state[i]
                        || prior.alarm_state[i] != cur.alarm_state[i]
                    {
                        tracing::info!(
                            area.name = %area_names[i],
                            prior.arming_status = ?prior.arming_status[i],
                            prior.up_state = ?prior.up_state[i],
                            prior.alarm_state = ?prior.alarm_state[i],
                            new.arming_status = ?cur.arming_status[i],
                            new.up_state = ?cur.up_state[i],
                            new.alarm_state = ?cur.alarm_state[i],
                            "arming status change",
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

fn setup_tracing() {
    use tracing_subscriber::prelude::*;
    tracing_log::LogTracer::init().unwrap();
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy();
    let sub = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::Layer::new()
            .map_fmt_fields(|f| f.debug_alt())
            .with_thread_names(true)
            .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
            .with_filter(filter),
    );
    tracing::subscriber::set_global_default(sub).unwrap();
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // SAFETY: let's assume nothing touches environment variables.
    unsafe {
        time::util::local_offset::set_soundness(time::util::local_offset::Soundness::Unsound);
    }

    setup_tracing();
    match Cmd::parse() {
        Cmd::Watch { addr } => watch(addr).await,
        Cmd::Read { filename } => read(filename),
    }
}
