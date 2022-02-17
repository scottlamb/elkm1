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

use std::path::PathBuf;

use elkm1::state;
use futures::StreamExt;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    mqtt: Mqtt,
    elk_addr: String,
}

fn mqtt_default_port() -> u16 { 1883 }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Mqtt {
    #[serde(default)]
    client_id: String,

    host: String,

    #[serde(default = "mqtt_default_port")]
    port: u16,

    username: Option<String>,
    password: Option<String>,

    topic_prefix: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::new().default_filter_or("info")).init();
    let mut args = std::env::args_os();
    let _ = args.next().expect("no argv[0]");
    let config_path: PathBuf = args.next().unwrap().into();
    if args.next().is_some() {
        panic!("extra argument after config");
    }
    let config = std::fs::read(config_path).unwrap();
    let config: Config = serde_json::from_slice(&config[..]).unwrap();


    let mut mqtt_opts = rumqttc::MqttOptions::new(&config.mqtt.client_id, &config.mqtt.host, config.mqtt.port);
    match (config.mqtt.username, config.mqtt.password) {
        (Some(u), Some(p)) => {
            mqtt_opts.set_credentials(u, p);
        },
        (None, None) => {},
        _ => panic!("username without password or vice versa"),
    }
    mqtt_opts.set_last_will(rumqttc::LastWill {
        topic: format!("{}/status", &config.mqtt.topic_prefix),
        message: "disconnected".into(),
        qos: rumqttc::QoS::AtLeastOnce,
        retain: true,
    });
    let (mqtt_cli, mut mqtt_eventloop) = rumqttc::AsyncClient::new(mqtt_opts, 10);
    let panel = state::Panel::connect(&config.elk_addr).await.unwrap();
    mqtt_cli.publish(
        format!("{}/status", &config.mqtt.topic_prefix),
        rumqttc::QoS::AtLeastOnce,
        true,
        "connected",
    ).await.unwrap();
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
