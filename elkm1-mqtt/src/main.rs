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
//!     *   [Binary sensors](https://www.home-assistant.io/integrations/binary.sensor.mqtt/) for
//!         each zone's status and each area's "ready to arm" status.
//!     *   [Switches](https://www.home-assistant.io/integrations/switch.mqtt/) for zone bypass.
//!     *   [Buttons](https://www.home-assistant.io/integrations/button.mqtt/) for
//!         automation tasks.

use std::{collections::HashMap, path::PathBuf};

use elkm1::state;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cfg {
    elk: ElkCfg,
    mqtt: MqttCfg,
}

fn mqtt_default_port() -> u16 {
    1883
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MqttCfg {
    // TODO: default to `elkm1/{id}` instead?
    #[serde(default)]
    client_id: String,

    host: String,

    #[serde(default = "mqtt_default_port")]
    port: u16,

    username: Option<String>,
    password: Option<String>,

    /// The MQTT topic prefix. Defaults to `elkm1/{id}`.
    topic_prefix: Option<String>,

    /// The Home Assistant discovery prefix; omit to not publish.
    ///
    /// Typically should be `homeassistant`.
    ha_discovery_prefix: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ElkCfg {
    /// The Elk's serial number, as shown in ElkRP.
    ///
    /// Unfortunately there's no obvious way to learn this from the Elk's ASCII
    /// protocol.
    ///
    /// This is used as the basis for
    /// [`unique_id`](https://developers.home-assistant.io/docs/entity_registry_index#unique-id-requirements)s
    /// in Home Assistant integration.
    serial_number: String,

    /// A fixed code for arm/disarm commands.
    code: u32,

    /// The Elk M1XEP's hostport, e.g. `elk:2101`.
    host_port: String,

    areas: HashMap<u8, AreaCfg>,
    zones: HashMap<u8, ZoneCfg>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AreaCfg {
    /// A name which is used in the MQTT topic name and HA unique_id for this area.
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZoneCfg {
    /// A name which is used in the MQTT topic name and HA unique_id for this zone.
    name: String,

    /// https://developers.home-assistant.io/docs/core/entity/binary-sensor
    /// eg `door`, `window`, `motion`, `garage_door`
    binary_sensor_device_class: String,
}

/// Returns an area's state in the enumeration format expected by the Home Assistant alarm
/// panel platform.
fn ha_area_state(report: &elkm1::msg::ArmingStatusReport, area: elkm1::msg::Area) -> &'static str {
    let i = area.to_index();
    let arming_status = report.arming_status[i];
    let up_state = report.up_state[i];
    let alarm_state = report.alarm_state[i];

    // https://www.home-assistant.io/integrations/alarm_control_panel.mqtt/
    if alarm_state.is_firing() {
        return "triggered";
    } else if alarm_state == elkm1::msg::AlarmState::AlarmAbortDelayActive {
        return "pending";
    } else if up_state == elkm1::msg::ArmUpState::ArmedWithExitTimer {
        return "arming";
    }
    use elkm1::msg::ArmingStatus;
    match arming_status {
        ArmingStatus::Disarmed => "disarmed",
        ArmingStatus::ArmedStay | ArmingStatus::ArmedStayInstant => "armed_home",
        ArmingStatus::ArmedAway => "armed_away",
        ArmingStatus::ArmedNight | ArmingStatus::ArmedNightInstant => "armed_night",
        ArmingStatus::ArmedVacation => "armed_vacation",
    }
}

async fn publish_area_states(
    mqtt_cli: &rumqttc::AsyncClient,
    panel: &elkm1::state::Panel,
    topic_prefix: &str,
    areas: &HashMap<u8, AreaCfg>,
) {
    for (&area_id, area_cfg) in areas {
        let area = elkm1::msg::Area::try_from(area_id).unwrap();
        mqtt_cli
            .publish(
                format!("{}/area/{}/ha_state", topic_prefix, &area_cfg.name),
                rumqttc::QoS::AtLeastOnce,
                true,
                ha_area_state(panel.arming_status(), area),
            )
            .await
            .unwrap();
    }
}

async fn publish_zone_state(
    mqtt_cli: &rumqttc::AsyncClient,
    panel: &elkm1::state::Panel,
    topic_prefix: &str,
    zone: elkm1::msg::Zone,
    zone_cfg: &ZoneCfg,
) {
    let zone_status = panel.zone_statuses().zones[zone.to_index()];
    let ha_status = match zone_status.logical() {
        elkm1::msg::ZoneLogicalStatus::Normal => "off",
        elkm1::msg::ZoneLogicalStatus::Trouble => "offline",
        elkm1::msg::ZoneLogicalStatus::Violated => "on",
        elkm1::msg::ZoneLogicalStatus::Bypassed => "on",
    };
    mqtt_cli
        .publish(
            format!("{}/zone/{}/ha_state", topic_prefix, &zone_cfg.name),
            rumqttc::QoS::AtLeastOnce,
            true,
            ha_status,
        )
        .await
        .unwrap();
}

/// [Home Assistant alarm control panel config](https://www.home-assistant.io/integrations/alarm_control_panel.mqtt/)
#[derive(Serialize)]
struct HaAlarmPanelConfig<'a> {
    availability_topic: String,
    state_topic: String,
    command_topic: String,
    unique_id: String,
    name: &'a str,
    device: &'a HaDeviceConfig<'a>,
}

/// [Home Assistant binary sensor config](https://www.home-assistant.io/integrations/binary_sensor.mqtt/)
#[derive(Serialize)]
struct HaBinarySensorConfig<'a> {
    availability_topic: String,
    state_topic: String,
    unique_id: String,
    name: &'a str,
    device: &'a HaDeviceConfig<'a>,
    device_class: &'a str,
}

/// [Home Assistant device config](https://developers.home-assistant.io/docs/device_registry_index/#device-properties)
#[derive(Serialize)]
struct HaDeviceConfig<'a> {
    manufacturer: &'a str,
    model: &'a str,
    identifiers: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    // TODO: sw_version.
}

async fn publish_ha_discovery(
    mqtt_cli: &rumqttc::AsyncClient,
    topic_prefix: &str,
    ha_discovery_prefix: &str,
    elk_cfg: &ElkCfg,
) {
    let device = HaDeviceConfig {
        manufacturer: "Elk Products",
        model: "M1",
        name: None,
        identifiers: vec![&elk_cfg.serial_number],
    };
    for (&area_id, area_cfg) in &elk_cfg.areas {
        let cfg = HaAlarmPanelConfig {
            availability_topic: format!("{}/availability", topic_prefix),
            state_topic: format!("{}/area/{}/ha_state", topic_prefix, &area_cfg.name),
            command_topic: format!("{}/area/{}/ha_command", topic_prefix, &area_cfg.name),
            unique_id: format!("elk-{}-area-{}", &elk_cfg.serial_number, area_id),
            name: &area_cfg.name,
            device: &device,
        };
        mqtt_cli
            .publish(
                format!(
                    "{}/alarm_control_panel/{}/config",
                    ha_discovery_prefix, &cfg.unique_id
                ),
                rumqttc::QoS::AtLeastOnce,
                true,
                serde_json::to_string_pretty(&cfg).unwrap(),
            )
            .await
            .unwrap();
    }
    for (&zone_id, zone_cfg) in &elk_cfg.zones {
        let cfg = HaBinarySensorConfig {
            availability_topic: format!("{}/availability", topic_prefix),
            state_topic: format!("{}/zone/{}/ha_state", topic_prefix, &zone_cfg.name),
            unique_id: format!("elk-{}-zone-{}", &elk_cfg.serial_number, zone_id),
            name: &zone_cfg.name,
            device: &device,
            device_class: &zone_cfg.binary_sensor_device_class,
        };
        mqtt_cli
            .publish(
                format!(
                    "{}/binary_sensor/{}/config",
                    ha_discovery_prefix, &cfg.unique_id
                ),
                rumqttc::QoS::AtLeastOnce,
                true,
                serde_json::to_string_pretty(&cfg).unwrap(),
            )
            .await
            .unwrap();
    }
}

async fn handle_publish(
    topic_prefix: &str,
    areas: &HashMap<u8, AreaCfg>,
    code: elkm1::msg::ArmCode,
    panel: &mut elkm1::state::Panel,
    publish: rumqttc::Publish,
) {
    log::info!("publish: {:#?}: {:?}", &publish, &publish.payload);

    // TODO: better topic name matching.
    for (&area_id, area_cfg) in areas {
        let command_topic = format!("{}/area/{}/ha_command", topic_prefix, &area_cfg.name);
        if publish.topic != command_topic {
            continue;
        }

        log::info!(
            "area {}, payload {:?}",
            &area_cfg.name,
            &publish.payload[..]
        );
        let ha_level = std::str::from_utf8(&publish.payload[..]).unwrap();
        let level = match ha_level {
            "DISARM" => elkm1::msg::ArmLevel::Disarm,
            "ARM_AWAY" => elkm1::msg::ArmLevel::ArmedAway,
            "ARM_HOME" => elkm1::msg::ArmLevel::ArmedStay,
            _ => {
                log::warn!("unknown level {:?}", &ha_level);
                return;
            }
        };

        // TODO: this may deadlock because we're not select!ing on the Panel's stream.
        // See note at elkm1::state::Panel.
        panel
            .send(elkm1::state::Command::Arm(elkm1::msg::ArmRequest {
                area: elkm1::msg::Area::try_from(area_id).unwrap(),
                level,
                code,
            }))
            .await
            .unwrap();

        return;
    }
    log::warn!("unknown topic {}", &publish.topic);
}

async fn run_eventloop(
    mut eventloop: rumqttc::EventLoop,
    tx: tokio::sync::mpsc::UnboundedSender<rumqttc::Publish>,
) {
    loop {
        let notification = eventloop.poll().await.unwrap();
        log::debug!("mqtt notification: {:#?}", &notification);

        if let rumqttc::Event::Incoming(rumqttc::Packet::Publish(p)) = notification {
            tx.send(p).unwrap();
        }
        // TODO: examine other messages. ensure acks come?
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::new().default_filter_or("info")).init();
    let mut args = std::env::args_os();
    let _ = args.next().expect("no argv[0]");
    let cfg_path: PathBuf = args.next().unwrap().into();
    if args.next().is_some() {
        panic!("extra argument after cfg");
    }
    let cfg = std::fs::read(cfg_path).unwrap();
    let cfg: Cfg = serde_json::from_slice(&cfg[..]).unwrap();

    let mut mqtt_opts =
        rumqttc::MqttOptions::new(&cfg.mqtt.client_id, &cfg.mqtt.host, cfg.mqtt.port);
    match (cfg.mqtt.username, cfg.mqtt.password) {
        (Some(u), Some(p)) => {
            mqtt_opts.set_credentials(u, p);
        }
        (None, None) => {}
        _ => panic!("username without password or vice versa"),
    }
    let topic_prefix = cfg
        .mqtt
        .topic_prefix
        .unwrap_or_else(|| format!("elkm1/{}", &cfg.elk.serial_number));
    mqtt_opts.set_last_will(rumqttc::LastWill {
        topic: format!("{}/availability", &topic_prefix),
        message: "offline".into(),
        qos: rumqttc::QoS::AtLeastOnce,
        retain: true,
    });
    let (mqtt_cli, mqtt_eventloop) = rumqttc::AsyncClient::new(mqtt_opts, 10);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(run_eventloop(mqtt_eventloop, tx));
    let panel = state::Panel::connect(&cfg.elk.host_port).await.unwrap();
    log::info!("Panel initialized.");
    let code = elkm1::msg::ArmCode::try_from(cfg.elk.code).unwrap();
    if let Some(ha_discovery_prefix) = cfg.mqtt.ha_discovery_prefix {
        publish_ha_discovery(&mqtt_cli, &topic_prefix, &ha_discovery_prefix, &cfg.elk).await;
    }
    publish_area_states(&mqtt_cli, &panel, &topic_prefix, &cfg.elk.areas).await;
    for (&zone_id, zone_cfg) in &cfg.elk.zones {
        let zone = elkm1::msg::Zone::try_from(zone_id).unwrap();
        publish_zone_state(&mqtt_cli, &panel, &topic_prefix, zone, zone_cfg).await;
    }
    let sub_topics = cfg.elk.areas.values().map(|a| rumqttc::SubscribeFilter {
        path: format!("{}/area/{}/ha_command", &topic_prefix, &a.name),
        qos: rumqttc::QoS::AtMostOnce,
    });
    mqtt_cli.subscribe_many(sub_topics).await.unwrap();
    mqtt_cli
        .publish(
            format!("{}/availability", &topic_prefix),
            rumqttc::QoS::AtLeastOnce,
            true,
            "online",
        )
        .await
        .unwrap();
    tokio::pin!(panel);
    loop {
        tokio::select! {
            panel_event = panel.next() => {
                let panel_event = panel_event.unwrap().unwrap();
                log::info!("panel event: {:#?}", &panel_event);
                mqtt_cli.publish(
                    format!("{}/event", &topic_prefix),
                    rumqttc::QoS::AtLeastOnce,
                    false,
                    serde_json::to_string_pretty(&panel_event).unwrap(),
                ).await.unwrap();
                match &panel_event.change {
                    Some(elkm1::state::Change::ArmingStatus { .. }) => {
                        publish_area_states(&mqtt_cli, &panel, &topic_prefix, &cfg.elk.areas).await;
                    }
                    Some(elkm1::state::Change::ZoneChange { zone, .. }) => {
                        let zone_cfg = match cfg.elk.zones.get(&(*zone).into()) {
                            None => continue,
                            Some(c) => c,
                        };
                        publish_zone_state(&mqtt_cli, &panel, &topic_prefix, *zone, zone_cfg).await;
                    }
                    _ => {}
                }
            },
            publish = rx.recv() => {
                let publish = publish.unwrap();
                handle_publish(&topic_prefix, &cfg.elk.areas, code, &mut panel, publish).await;
            }
        }
    }
}
