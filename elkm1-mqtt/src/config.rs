// Copyright (C) 2023 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Types for the `.json` configuration file.

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigFile {
    pub elk: Elk,
    pub mqtt: Mqtt,

    #[serde(default)]
    pub binds: Vec<Bind>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bind {
    pub ipv4: std::net::SocketAddrV4, // TODO: also support ipv6 + unix + systemd socket activation.
}

fn mqtt_default_port() -> u16 {
    1883
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mqtt {
    // TODO: default to `elkm1/{id}` instead?
    #[serde(default)]
    pub client_id: String,

    pub host: String,

    #[serde(default = "mqtt_default_port")]
    pub port: u16,

    pub username: Option<String>,
    pub password: Option<String>,

    /// The MQTT topic prefix. Defaults to `elkm1/{id}`.
    pub topic_prefix: Option<String>,

    /// The Home Assistant discovery prefix; omit to not publish.
    ///
    /// Typically should be `homeassistant`.
    pub ha_discovery_prefix: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elk {
    /// The Elk's serial number, as shown in ElkRP.
    ///
    /// Unfortunately there's no obvious way to learn this from the Elk's ASCII
    /// protocol.
    ///
    /// This is used as the basis for
    /// [`unique_id`](https://developers.home-assistant.io/docs/entity_registry_index#unique-id-requirements)s
    /// in Home Assistant integration.
    pub serial_number: String,

    /// A fixed code for arm/disarm commands.
    pub code: u32,

    /// The Elk M1XEP's hostport, e.g. `elk:2101`.
    pub host_port: String,

    pub areas: HashMap<u8, Area>,
    pub zones: HashMap<u8, Zone>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Area {
    /// A name which is used in the MQTT topic name and HA unique_id for this area.
    pub name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Zone {
    /// A name which is used in the MQTT topic name and HA unique_id for this zone.
    pub name: String,

    /// https://developers.home-assistant.io/docs/core/entity/binary-sensor
    /// eg `door`, `window`, `motion`, `garage_door`
    pub binary_sensor_device_class: String,
}
