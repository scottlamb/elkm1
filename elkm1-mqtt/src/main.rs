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

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use elkm1::state::{self, Command, Event};
use futures::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tracing::Instrument;

mod config;

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
    areas: &HashMap<u8, config::Area>,
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
    zone_cfg: &config::Zone,
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
/// https://developers.home-assistant.io/docs/core/entity/alarm-control-panel
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
    elk_cfg: &config::Elk,
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
    areas: &HashMap<u8, config::Area>,
    code: elkm1::msg::ArmCode,
    panel: &mut elkm1::state::Panel,
    publish: rumqttc::Publish,
    panel_span: &tracing::Span,
) {
    tracing::info!(?publish, payload = ?publish.payload, "received mqtt publish");

    // TODO: better topic name matching.
    for (&area_id, area_cfg) in areas {
        let command_topic = format!("{}/area/{}/ha_command", topic_prefix, &area_cfg.name);
        if publish.topic != command_topic {
            continue;
        }

        tracing::info!(
            area.name = %area_cfg.name,
            publish.topic,
            "matched to known area",
        );
        let ha_level = std::str::from_utf8(&publish.payload[..]).unwrap();
        let level = match ha_level {
            "DISARM" => elkm1::msg::ArmLevel::Disarm,
            "ARM_AWAY" => elkm1::msg::ArmLevel::ArmedAway,
            "ARM_HOME" => elkm1::msg::ArmLevel::ArmedStay,
            _ => {
                tracing::warn!(ha_level, "ignoring unknown level");
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
            .instrument(panel_span.clone())
            .await
            .unwrap();

        return;
    }
    tracing::warn!(publish.topic, "ignoring publish to unknown topic");
}

async fn run_eventloop(
    mut eventloop: rumqttc::EventLoop,
    tx: tokio::sync::mpsc::UnboundedSender<rumqttc::Publish>,
) {
    loop {
        let notification = eventloop.poll().await.unwrap();
        tracing::trace!(?notification, "mqtt notification");

        if let rumqttc::Event::Incoming(rumqttc::Packet::Publish(p)) = notification {
            tx.send(p).unwrap();
        }
        // TODO: examine other messages. ensure acks come?
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

async fn handle_listener(
    listener: TcpListener,
    to_panel: tokio::sync::mpsc::Sender<Command>,
    client_senders: ClientSenders,
) {
    loop {
        let (client, cli_addr) = listener.accept().await.expect("accept should succeed");
        let (from_panel_tx, from_panel_rx) = tokio::sync::mpsc::channel(1024);
        client_senders
            .lock()
            .expect("client_senders shouldn't be poisoned")
            .push(from_panel_tx);
        let to_panel = to_panel.clone();
        let span = tracing::info_span!(
            "client",
            net.sock.peer.addr = %cli_addr.ip(),
            net.sock.peer.port = %cli_addr.port(),
        );
        tokio::task::spawn(handle_client(client, from_panel_rx, to_panel).instrument(span));
    }
}

async fn handle_client(
    client: TcpStream,
    mut from_panel: tokio::sync::mpsc::Receiver<Arc<Event>>,
    to_panel: tokio::sync::mpsc::Sender<Command>,
) {
    tracing::info!("accepted connection");
    let mut conn = elkm1::tokio::Connection::from(client);
    loop {
        tokio::select! {
            event = from_panel.recv() => {
                let Some(event) = event else {
                    tracing::error!("closing connection after falling too far behind");
                    return;
                };
                if let Some(ref pkt) = event.pkt {
                    if let Err(err) = conn.send(pkt.clone()).await {
                        tracing::error!(%err, "closing connection due to send error");
                        return;
                    }
                }
            }
            pkt = conn.next() => {
                match pkt {
                    Some(Ok(pkt)) => {
                        tracing::info!(?pkt, "client->panel packet");
                        if let Err(err) = to_panel.send(Command::Raw(pkt.clone())).await {
                            tracing::error!(?pkt, %err, "closing connection after failure enqueueing pkt to panel");
                            return;
                        }
                    },
                    Some(Err(err)) => {
                        tracing::error!(%err, "closing connection due to read error");
                        return;
                    }
                    None => return,
                }
            }
        }
    }
}

type ClientSenders = Arc<Mutex<Vec<tokio::sync::mpsc::Sender<Arc<Event>>>>>;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // SAFETY: let's assume nothing touches environment variables.
    unsafe {
        time::util::local_offset::set_soundness(time::util::local_offset::Soundness::Unsound);
    }

    setup_tracing();
    let mut args = std::env::args_os();
    let _ = args.next().expect("no argv[0]");
    let cfg_path: PathBuf = args.next().unwrap().into();
    if args.next().is_some() {
        panic!("extra argument after cfg");
    }
    let cfg = std::fs::read(cfg_path).unwrap();
    let cfg: config::ConfigFile = serde_json::from_slice(&cfg[..]).unwrap();

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

    let panel = elkm1::tokio::Connection::connect(&cfg.elk.host_port)
        .await
        .unwrap();
    let panel_addr = panel.peer_addr().unwrap();
    let panel_span = tracing::info_span!(
        "panel",
        net.sock.peer.addr = %panel_addr.ip(),
        net.sock.peer.port = %panel_addr.port(),
    );
    let panel = state::Panel::new(panel)
        .instrument(panel_span.clone())
        .await
        .unwrap();
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

    let client_senders = Arc::new(Mutex::new(Vec::new()));
    let (to_panel_tx, mut to_panel_rx) = tokio::sync::mpsc::channel(1024);

    for bind in cfg.binds {
        let listener = tokio::net::TcpListener::bind(bind.ipv4)
            .await
            .expect("bind should succeed");
        tokio::spawn(handle_listener(
            listener,
            to_panel_tx.clone(),
            client_senders.clone(),
        ));
    }
    loop {
        tokio::select! {
            panel_event = panel.next().instrument(panel_span.clone()) => {
                let panel_event = panel_event.unwrap().unwrap();
                tracing::info!(parent: &panel_span, ?panel_event, "panel event");
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

                // Send the message on to clients. If one is stuck, don't let it hold up the show;
                // drop it when the queue fills.
                let panel_event = Arc::new(panel_event);
                let mut l = client_senders.lock().expect("client_senders shouldn't be poisoned");
                l.retain_mut(|tx| !tx.try_send(Arc::clone(&panel_event)).is_err());
            },
            publish = rx.recv() => {
                let publish = publish.unwrap();
                handle_publish(&topic_prefix, &cfg.elk.areas, code, &mut panel, publish, &panel_span).await;
            }
            to_panel = to_panel_rx.recv() => {
                let to_panel = to_panel.expect("to_panel_tx should never be dropped");
                panel.send(to_panel).instrument(panel_span.clone()).await.expect("panel send should not fail");
            }
        }
    }
}
