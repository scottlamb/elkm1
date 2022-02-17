// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Elk\<-\>MQTT bridge.
//!
//! ## Status
//!
//! Incomplete, not yet even prototype-level quality. Crashes on any error.
//! Unsure if I'm using the (confusing) `rumqttc` API properly, e.g.:
//!
//! *   How long does an `AsyncClient::publish` future take to resolve, and will
//!     it deadlock if I `await` on it before my next call to `EventLoop::poll`?
//! *   Is the `EventLoop::poll` future cancel-safe (safe to use in a `select!)?
//!     Or should I have a `tokio::spawn` loop for it?
//!
//! ## Goals
//!
//! *   Publish all received packets / messages / commands, primarily for debugging.
//! *   Home Assistant integration, as a replacement for the
//!     [`elkm1` integration](https://www.home-assistant.io/integrations/elkm1/) that I've
//!     found to be buggy.
//!     *   [Discovery](https://www.home-assistant.io/docs/mqtt/discovery/)
//!     *   An overall availability topic (with a Last Will \& Testament msg),
//!         used by each HA entity.
//!     *   [Alarm Control Panel](https://www.home-assistant.io/integrations/alarm_control_panel.mqtt/)
//!         for each area. Note this is somewhat lossy; e.g. the `arming` state
//!         doesn't distinguish between target modes (home/away/night/vacation)
//!         or tell when the system will be fully armed. Thus perhaps we should
//!         also publish a raw state on a separate topic.
//!     *   [Sensors](https://www.home-assistant.io/integrations/sensor.mqtt/) for
//!         each zone's status and each area's "ready to arm" status.
//!     *   [Switches](https://www.home-assistant.io/integrations/switch.mqtt/) for zone bypass.
//!     *   [Buttons](https://www.home-assistant.io/integrations/button.mqtt/) for
//!         automation tasks.
//! *   Configuration file
//!     *   MQTT / Elk configuration (currently command line options)
//!     *   Map the Elk's (zone, area, task, etc.) numbers to MQTT topic names,
//!         rather than solely relying on the 16-character names allowed by the
//!         Elk.

use clap::Parser;
use elkm1::state;
use futures::StreamExt;

#[derive(Parser)]
struct Args {
    #[clap(long)]
    mqtt_id: String,

    #[clap(long)]
    mqtt_host: String,

    #[clap(long, default_value_t = 1883)]
    mqtt_port: u16,

    #[clap(long)]
    mqtt_username: Option<String>,

    #[clap(long, requires = "mqtt-username")]
    mqtt_password: Option<String>,

    #[clap(long)]
    elk_addr: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::new().default_filter_or("info")).init();
    let args = Args::parse();
    let mut mqtt_opts = rumqttc::MqttOptions::new(&args.mqtt_id, &args.mqtt_host, args.mqtt_port);
    if let Some(mqtt_username) = args.mqtt_username {
        mqtt_opts.set_credentials(mqtt_username, args.mqtt_password.unwrap());
    }
    mqtt_opts.set_last_will(rumqttc::LastWill {
        topic: "elk/status".to_string(),
        message: "disconnected".into(),
        qos: rumqttc::QoS::AtLeastOnce,
        retain: true,
    });
    let (mqtt_cli, mut mqtt_eventloop) = rumqttc::AsyncClient::new(mqtt_opts, 10);
    let panel = state::Panel::connect(&args.elk_addr).await.unwrap();
    mqtt_cli
        .publish("elk/status", rumqttc::QoS::AtLeastOnce, true, "connected")
        .await
        .unwrap();
    tokio::pin!(panel);
    loop {
        tokio::select! {
            panel_event = panel.next() => {
                let panel_event = panel_event.unwrap().unwrap();
                log::info!("panel event: {:#?}", &panel_event);
                mqtt_cli.publish(
                    "elk/event",
                    rumqttc::QoS::AtLeastOnce,
                    false,
                    serde_json::to_string_pretty(&panel_event).unwrap(),
                ).await.unwrap();
            },
            mqtt_notification = mqtt_eventloop.poll() => {
                let mqtt_notification = mqtt_notification.unwrap();
                log::info!("mqtt notification: {:#?}", &mqtt_notification);
            }
        }
    }
}
