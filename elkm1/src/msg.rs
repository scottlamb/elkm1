// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Message layer: statelessly converts [`crate::pkt`] packets into higher-level
//! messages and vice versa.
//!
//! Message types are written to have some general properties:
//!
//! *   They can only represent valid messages at the type level. Ranges of
//!     certain values are enforced via dedicated types.
//! *   Serializing and deserializing a message should always produce an
//!     equal message.
//! *   When using the `arbitrary` cargo feature, they implement `Arbitrary`.
//! *   They may be converted to a general [`Message`] (an enum of all message
//!     types) or a [`crate::pkt::Packet`].

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;

#[cfg(feature = "serde")]
use serde::{de::Error as _, Deserialize, Serialize};

use std::num::NonZeroU8;
use std::str::FromStr;

use crate::pkt::{AsciiPacket, Packet};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {}

fn parse_u8_dec(name: &str, val: &[u8]) -> Result<u8, String> {
    let as_str = std::str::from_utf8(val)
        .map_err(|_| format!("{} expected to be decimal in [0, 255); was bad utf-8", name))?;
    u8::from_str(as_str)
        .map_err(|_| format!("{} expected to be decimal in [0, 255); got {:?}", name, val))
}

/// Defines all ASCII messages, taking care of some `enum Message` and `Into`
/// boilerplate.
macro_rules! ascii_messages {
    (
        $(
            #[doc=$doc:literal]
            $(#[$other_attrs:meta])*
            struct $m:ident $body:tt
        )+
    ) => {
        /// A parsed (ASCII) message of any supported type.
        #[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
        #[cfg_attr(
            feature = "serde",
            derive(Serialize, Deserialize),
            serde(rename_all="camelCase"))
        ]
        #[derive(Clone, Debug, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum Message {
            $(
                #[doc=$doc]
                $m($m),
            )*
        }
        impl Message {
            pub fn to_pkt(&self) -> Packet {
                match self {
                    $(
                        Message::$m(m) => m.into(),
                    )*
                }
            }

            /// Returns true if this message may be a reply to `request`.
            pub fn is_response_to(&self, request: &Message) -> bool {
                match self {
                    $(
                        Message::$m(m) => m.is_response_to(request),
                    )*
                }
            }
        }

        $(
            #[doc=$doc]
            $(#[$other_attrs])*
            #[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
            pub struct $m $body

            impl From<$m> for Message {
                #[inline]
                fn from(value: $m) -> Message {
                    Message::$m(value)
                }
            }
            impl From<&$m> for AsciiPacket {
                #[inline]
                fn from(value: &$m) -> AsciiPacket {
                    value.to_ascii()
                }
            }
            impl From<&$m> for Packet {
                #[inline]
                fn from(value: &$m) -> Packet {
                    Packet::Ascii(value.to_ascii())
                }
            }
        )*
    }
}

ascii_messages! {
    /// `aL`: Arm/Disarm Request.
    ///
    /// For arming to succeed, the supplied `code` must belong to a user which does *not* have the
    /// `Access` permission, as noted in [this issue
    /// comment](https://github.com/BioSehnsucht/ha-elkm1/issues/23#issuecomment-414145743).
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct ArmRequest {
        pub area: Area,
        pub level: ArmLevel,
        pub code: ArmCode,
    }

    /// `AM`: Alarm Memory Update.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct AlarmMemory {
        /// `memory[i]` indicates if area `i` has alarm memory that must be cleared before arming.
        pub memory: [bool; Area::MAX],
    }

    /// `as`: Arming Status Request.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct ArmingStatusRequest {}

    /// `AS`: Arming Status Report.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct ArmingStatusReport {
        pub arming_status: [ArmingStatus; Area::MAX],
        pub up_state: [ArmUpState; Area::MAX],
        pub alarm_state: [AlarmState; Area::MAX],
        pub first_exit_time: u8,
    }

    /// `EE`: Send Entry/Exit Time Data.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct SendTimeData {
        pub area: Area,
        pub ty: TimeDataType,
        pub timer1: u8,
        pub timer2: u8,

        /// The armed state, which according to documentation is only present
        /// for M1 Ver. 4.1.18, 5.1.18 or later.
        pub armed_state: Option<ArmedState>,
    }

    /// `IC`:  Send Valid User Number and Invalid User Code.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct SendCode {
        /// The code, or all 0s if it represents a valid user.
        ///
        /// If this was entered on an Elk keypad, each of the six bytes will
        /// be a digit `[0, 9]`. That is, a zero on the keypad becomes an ASCII
        /// NUL, not a `b'0'`. If the Elk is configured for four-digit codes,
        /// the leading two digits will always be `0`.
        code: [u8; 6],

        /// The user code number.
        ///
        /// There are several "special" values.
        user: u8,
        keypad: Keypad,
    }

    /// `rp`: ElkRP Connection Status.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct RpStatusUpdate {
        status: RpStatus,
    }

    /// `rr`: request Real Time Clock Data.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct RtcRequest {
    }

    /// `RR`: Real Time Clock Data.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct RtcResponse {
        rtc_data: RtcData,
    }

    /// `sd`: Request ASCII String Text Descriptions.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct StringDescriptionRequest {
        pub ty: TextDescriptionType,
        pub num: u8,
    }

    /// `SD`: ASCII String Text Descriptions.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct StringDescriptionResponse {
        pub ty: TextDescriptionType,
        pub num: u8,
        pub show_on_keypad: bool,
        pub text: TextDescription,
    }

    /// `ss`: System Trouble Status Request.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct SystemTroubleStatusRequest {}

    /// `SS`: System Trouble Status Response.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct SystemTroubleStatusResponse {
        pub ac_fail: bool,
        pub box_tamper: ZoneTrouble,
        pub fail_to_communicate: bool,
        pub eeprom_memory_error: bool,
        pub control_low_battery: bool,
        pub transmitter_low_battery: ZoneTrouble,
        pub over_current_trouble: bool,
        pub telephone_fault_trouble: bool,
        pub output_2_trouble: bool,
        pub missing_keypad_trouble: bool,
        pub zone_expander_trouble: bool,
        pub output_expander: bool,
        pub elkrp_remote_access: bool,
        pub common_area_not_armed: bool,
        pub flash_memory_error: bool,
        pub security_alert: ZoneTrouble,
        pub serial_port_expander: bool,
        pub lost_transmitter: ZoneTrouble,
        pub ge_smoke_cleanme: bool,
        pub ethernet: bool,
        pub display_message_keypad_line1: bool,
        pub display_message_keypad_line2: bool,
        pub fire: ZoneTrouble,
    }

    /// `tn`: Task Activation.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct ActivateTask {
        pub task: Task,
    }

    /// `TC`: Task Change Update.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct TaskChange {
        pub task: Task,
    }

    /// `XK`: Control RTC Broadcast / IP Communications Device Test (a heartbeat).
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct Heartbeat {
        rtc_data: RtcData,
    }

    /// `ZC`: Zone Change Update.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct ZoneChange {
        pub zone: Zone,
        pub status: ZoneStatus,
    }

    /// `zs`: Zone Status Request.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all="camelCase"))]
    struct ZoneStatusRequest {}

    /// `ZS`: Zone Status Report.
    #[derive(Copy, Clone, PartialEq, Eq)]
    struct ZoneStatusReport {
        pub zones: [ZoneStatus; Zone::MAX],
    }
}

impl Message {
    pub fn parse(pkt: &Packet) -> Result<Option<Self>, Error> {
        match pkt {
            Packet::Ascii(msg) => Self::parse_ascii(msg),
            Packet::Rp(_) => Ok(None), // todo
            Packet::Invalid { .. } => Ok(None),
        }
    }

    pub fn parse_ascii(pkt: &AsciiPacket) -> Result<Option<Self>, Error> {
        let payload: &[u8] = pkt;
        if payload.len() < 4 {
            return Err(Error("malformed ASCII message: too short".into()));
        }
        let (cmd, data) = payload.split_at(2);
        match cmd {
            b"a0" | b"a1" | b"a2" | b"a3" | b"a4" | b"a5" | b"a6" | b"a7" | b"a8" | b"a9"
            | b"a:" => ArmRequest::from_ascii(cmd[1], data).map(Self::ArmRequest),
            b"AM" => AlarmMemory::from_ascii_data(data).map(Self::AlarmMemory),
            b"as" => ArmingStatusRequest::from_ascii_data(data).map(Self::ArmingStatusRequest),
            b"AS" => ArmingStatusReport::from_ascii_data(data).map(Self::ArmingStatusReport),
            b"EE" => SendTimeData::from_ascii_data(data).map(Self::SendTimeData),
            b"IC" => SendCode::from_ascii_data(data).map(Self::SendCode),
            b"RP" => RpStatusUpdate::from_ascii_data(data).map(Self::RpStatusUpdate),
            b"rr" => RtcRequest::from_ascii_data(data).map(Self::RtcRequest),
            b"RR" => RtcResponse::from_ascii_data(data).map(Self::RtcResponse),
            b"sd" => {
                StringDescriptionRequest::from_ascii_data(data).map(Self::StringDescriptionRequest)
            }
            b"SD" => StringDescriptionResponse::from_ascii_data(data)
                .map(Self::StringDescriptionResponse),
            b"ss" => SystemTroubleStatusRequest::from_ascii_data(data)
                .map(Self::SystemTroubleStatusRequest),
            b"SS" => SystemTroubleStatusResponse::from_ascii_data(data)
                .map(Self::SystemTroubleStatusResponse),
            b"tn" => ActivateTask::from_ascii_data(data).map(Self::ActivateTask),
            b"TC" => TaskChange::from_ascii_data(data).map(Self::TaskChange),
            b"XK" => Heartbeat::from_ascii_data(data).map(Self::Heartbeat),
            b"ZC" => ZoneChange::from_ascii_data(data).map(Self::ZoneChange),
            b"zs" => ZoneStatusRequest::from_ascii_data(data).map(Self::ZoneStatusRequest),
            b"ZS" => ZoneStatusReport::from_ascii_data(data).map(Self::ZoneStatusReport),
            _ => return Ok(None),
        }
        .map(Some)
        .map_err(Error)
    }
}

impl From<&Message> for Packet {
    fn from(value: &Message) -> Packet {
        value.to_pkt()
    }
}

/// Defines an enum for a `u8` with an automatic `TryFrom` that uses the
/// explicit discriminant as the byte value.
macro_rules! byte_enum {
    (
        #[doc=$enum_doc:literal]
        $vis:vis enum $enum:ident {
            $(
                $(#[doc=$var_doc:literal])*
                $var:ident = $val:literal,
            )*
        }
    ) => {
        #[doc=$enum_doc]
        #[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
        #[cfg_attr(
            feature = "serde",
            derive(Serialize, Deserialize),
            serde(rename_all="camelCase"))
        ]
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        #[repr(u8)]
        $vis enum $enum {
            $(
                $(#[doc=$var_doc])*
                $var = $val,
            )*
        }
        impl TryFrom<u8> for $enum {
            type Error = String;
            fn try_from(val: u8) -> Result<Self, Self::Error> {
                Ok(match val {
                    $(
                        $val => Self::$var,
                    )*
                    _ => return Err(format!("bad {} {:?}", stringify!($enum), char::from(val))),
                })
            }
        }
    }
}

/// Almost the same as `byte_enum`, but uses the *numeric* value in the error
/// message, without conversion to `char`.
///
/// TODO: maybe find a slick way to combine these?
macro_rules! num_enum {
    (
        #[doc=$enum_doc:literal]
        $vis:vis enum $enum:ident {
            $(
                $(#[doc=$var_doc:literal])?
                $var:ident = $val:literal,
            )*
        }
    ) => {
        #[doc=$enum_doc]
        #[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
        #[cfg_attr(
            feature = "serde",
            derive(Serialize, Deserialize),
            serde(rename_all="camelCase"))
        ]
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        #[repr(u8)]
        $vis enum $enum {
            $(
                $(#[doc=$var_doc])*
                $var = $val,
            )*
        }
        impl TryFrom<u8> for $enum {
            type Error = String;
            fn try_from(val: u8) -> Result<Self, Self::Error> {
                Ok(match val {
                    $(
                        $val => Self::$var,
                    )*
                    _ => return Err(format!("bad {} {}", stringify!($enum), val)),
                })
            }
        }
    }
}

byte_enum! {
    /// The arming level in an [`ArmRequest`].
    pub enum ArmLevel {
        Disarm = b'0',
        ArmedAway = b'1',
        ArmedStay = b'2',
        ArmedStayInstant = b'3',
        ArmedNight = b'4',
        ArmedNightInstant = b'5',
        ArmedVacation = b'6',

        /// Arm to next away mode; requires M1 Ver. 4.28 or later.
        ArmToNextAwayMode = b'7',

        /// Arm to next stay mode; requires M1 Ver. 4.28 or later.
        ArmToNextStayMode = b'8',

        /// Force arm to away; requires M1 Ver. 4.28 or later.
        ForceArmToAway = b'9',

        /// Force arm to stay; requires M1 Ver. 4.28 or later.
        ForceArmToStay = b':',
    }
}

/// A six-digit numeric arm code.
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct ArmCode([u8; 6]);

impl std::fmt::Debug for ArmCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let as_str = std::str::from_utf8(&self.0[..]).expect("ArmCode is valid UTF-8");
        as_str.fmt(f)
    }
}

/// Converts from a number.
impl TryFrom<u32> for ArmCode {
    type Error = String;

    fn try_from(n: u32) -> Result<Self, String> {
        if n >= 1_000000 {
            return Err("code out of range".into());
        }
        let n = format!("{:06}", n);
        let mut copied = [0u8; 6];
        copied.copy_from_slice(n.as_bytes());
        Ok(ArmCode(copied))
    }
}

/// Converts from ASCII digits.
impl TryFrom<&[u8]> for ArmCode {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 6 {
            return Err("ArmCode must be of length 6".to_owned());
        }
        let mut code = [0u8; 6];
        code.copy_from_slice(value);
        if code.iter().any(|b| !(b'0'..=b'9').contains(b)) {
            return Err("ArmCode must be numeric".to_owned());
        }
        Ok(ArmCode(code))
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary<'_> for ArmCode {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let buf = u.bytes(3)?;
        let n = (u32::from(buf[0]) << 24) | (u32::from(buf[1]) << 16) | (u32::from(buf[2]));
        ArmCode::try_from(n).map_err(|_| arbitrary::Error::IncorrectFormat)
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        let _ = depth;
        (3, Some(3))
    }
}

num_enum! {
    /// The ElkRP connection status as seen in [`RpStatusUpdate`] messages.
    pub enum RpStatus {
        /// When Elk-RP disconnects, this status is broadcast to all other clients.
        Disconnected = 0,

        /// May be sent in response to polls while Elk-RP is connected.
        Connected = 1,

        /// May be sent in response to polls while Elk-M1XEP is powering up/rebooting.
        Initializing = 2,
    }
}

byte_enum! {
    /// Type of time, used in [`SendTimeData`].
    pub enum TimeDataType {
        Exit = b'0',
        Entry = b'1',
    }
}

byte_enum! {
    /// Arm state for [`ArmingStatusReport`].
    pub enum ArmedState {
        Disarmed = b'0',
        ArmedAway = b'1',
        ArmedStay = b'2',
        ArmedStayInstant = b'3',
        ArmedNight = b'4',
        ArmedNightInstant = b'5',
        ArmedVacation = b'6',
    }
}

byte_enum! {
    /// Day of the week, as in `RR` and `XK` messages.
    enum Weekday {
        Sun = b'1',
        Mon = b'2',
        Tue = b'3',
        Wed = b'4',
        Thu = b'5',
        Fri = b'6',
        Sat = b'7',
    }
}

byte_enum! {
    /// Clock display mode: 24-hour or 12-hour.
    enum ClockDisplayMode {
        TwentyFourHour = b'0',
        TwelveHour = b'1',
    }
}

byte_enum! {
    /// Date display mode: `mm/dd` or `dd/mm`.
    enum DateDisplayMode {
        MonthFirst = b'0',
        DayFirst = b'1',
    }
}
/// Creates a `u8` wrapper that enforces a range of `[1, $max]`.
macro_rules! limited_u8 {
    (
        #[doc=$doc:literal]
        $t:ident max=$max:literal
    ) => {
        #[repr(transparent)]
        #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #[doc=$doc]
        #[cfg_attr(feature = "serde", derive(Serialize), serde(transparent))]
        pub struct $t(NonZeroU8);

        impl $t {
            pub const MAX: usize = $max;

            #[inline]
            pub fn to_index(self) -> usize {
                usize::from(self.0.get()) - 1
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = u8::deserialize(deserializer)?;
                if !(1..=$max).contains(&value) {
                    return Err(D::Error::custom(format!("value out of range: {}", value)));
                }
                Ok($t(
                    NonZeroU8::new(value).expect("value should be verified as non-zero")
                ))
            }
        }

        #[cfg(feature = "arbitrary")]
        impl Arbitrary<'_> for $t {
            fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
                Ok(Self(
                    NonZeroU8::new(u.int_in_range(1..=$max)?)
                        .expect("int_in_range should respect range"),
                ))
            }

            fn size_hint(depth: usize) -> (usize, Option<usize>) {
                <u8 as Arbitrary>::size_hint(depth)
            }
        }

        impl std::fmt::Debug for $t {
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(&self.0, f)
            }
        }

        impl std::fmt::Display for $t {
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl TryFrom<u8> for $t {
            type Error = String;

            fn try_from(val: u8) -> Result<Self, Self::Error> {
                if !(1..=$max).contains(&val) {
                    return Err(format!(
                        "{} not in expected {} range of [1, {}]",
                        val,
                        stringify!(t),
                        $max,
                    ));
                }
                Ok(Self(NonZeroU8::new(val).expect("val should be non-zero")))
            }
        }

        impl From<$t> for u8 {
            #[inline]
            fn from(value: $t) -> u8 {
                value.0.get()
            }
        }
    };
}

/// A datetime, loosely defined.
///
/// This currently enforces the ranges mentioned in Elk's spec, e.g. day can't be more than 31.
/// It doesn't use a real date library and thus doesn't prevent silly dates like February 30th.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct DateTime {
    year: u8,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl DateTime {
    /// Parses an ISO 8601 datetime like `YYYY-mm-DDTHH:MM:SS`.
    pub fn from_iso_8601(val: &str) -> Result<Self, String> {
        if val.len() != 19 {
            return Err("wrong length".to_owned());
        }
        let year = u16::from_str(&val[..4]).map_err(|_| "bad year".to_owned())?;
        if !(2000..=2100).contains(&year) {
            return Err(format!("year {} out of range", year));
        }
        if &val[4..5] != "-" {
            return Err("bad year-month separator".to_owned());
        }
        let month = u8::from_str(&val[5..7]).map_err(|_| "bad month".to_owned())?;
        if !(1..=12).contains(&month) {
            return Err(format!("month {} out of range", month));
        }
        if &val[7..8] != "-" {
            return Err("bad month-day separator".to_owned());
        }
        let day = u8::from_str(&val[8..10]).map_err(|_| "bad day".to_owned())?;
        if !(1..=31).contains(&day) {
            return Err(format!("day {} out of range", day));
        }
        if &val[10..11] != "T" {
            return Err("bad date-time separator".to_owned());
        }
        let hour = u8::from_str(&val[11..13]).map_err(|_| "bad hour".to_owned())?;
        if &val[13..14] != ":" {
            return Err("bad hour-minute separator".to_owned());
        }
        if hour > 23 {
            return Err(format!("hour {} out of range", hour));
        }
        let minute = u8::from_str(&val[14..16]).map_err(|_| "bad minute".to_owned())?;
        if minute > 59 {
            return Err(format!("minute {} out of range", minute));
        }
        if &val[16..17] != ":" {
            return Err("bad minute-second separator".to_owned());
        }
        let second = u8::from_str(&val[17..19]).map_err(|_| "bad second".to_owned())?;
        if second > 59 {
            return Err("second out of range".to_owned());
        }
        Ok(Self {
            year: (year - 2000) as u8,
            month,
            day,
            hour,
            minute,
            second,
        })
    }

    pub fn to_iso_8601(&self) -> String {
        format!(
            "20{:02}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary<'_> for DateTime {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            year: u.int_in_range(0..=99)?,
            month: u.int_in_range(1..=12)?,
            day: u.int_in_range(1..=31)?,
            hour: u.int_in_range(0..=23)?,
            minute: u.int_in_range(0..=59)?,
            second: u.int_in_range(0..=59)?,
        })
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (6, None)
    }
}

#[cfg(feature = "serde")]
impl Serialize for DateTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_iso_8601())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for DateTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        Self::from_iso_8601(s).map_err(|_| {
            D::Error::invalid_value(
                serde::de::Unexpected::Str(s),
                &"a datetime of the format YYYY-mm-ddTHH:MM:SS",
            )
        })
    }
}

impl std::fmt::Debug for DateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_iso_8601().fmt(f)
    }
}

impl std::fmt::Display for DateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_iso_8601().fmt(f)
    }
}

/// Real-time clock data: datetime and flags.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
struct RtcData {
    datetime: DateTime,
    weekday: Weekday,
    dst: bool,
    clock_display: ClockDisplayMode,
    date_display: DateDisplayMode,
}

impl RtcData {
    fn from_ascii(data: &[u8]) -> Result<Self, String> {
        if data.len() < 16 {
            return Err("RTC data must be at least 16 bytes".to_owned());
        }
        let year = parse_u8_dec("year", &data[11..13])?;
        debug_assert!(year < 100);
        let month = parse_u8_dec("month", &data[9..11])?;
        if !(1..=12).contains(&month) {
            return Err("month out of range".to_owned());
        }
        let day = parse_u8_dec("day", &data[7..9])?;
        if !(1..=31).contains(&day) {
            return Err("day out of range".to_owned());
        }
        let hour = parse_u8_dec("hour", &data[4..6])?;
        if hour >= 24 {
            return Err("hour out of range".to_owned());
        }
        let minute = parse_u8_dec("minute", &data[2..4])?;
        if minute >= 60 {
            return Err("minute out of range".to_owned());
        }
        let second = parse_u8_dec("second", &data[0..2])?;
        if second >= 60 {
            return Err("second out of range".to_owned());
        }
        let weekday = Weekday::try_from(data[6])?;
        let dst = parse_bool(data[13], "dst flag")?;
        let clock_display = ClockDisplayMode::try_from(data[14])?;
        let date_display = DateDisplayMode::try_from(data[15])?;
        Ok(Self {
            datetime: DateTime {
                year,
                month,
                day,
                hour,
                minute,
                second,
            },
            weekday,
            dst,
            clock_display,
            date_display,
        })
    }

    fn to_ascii(self) -> impl Iterator<Item = u8> {
        format!(
            "{:02}{:02}{:02}{:01}{:02}{:02}{:02}{:01}{:01}{:01}",
            self.datetime.second,
            self.datetime.minute,
            self.datetime.hour,
            self.weekday as u8 as char,
            self.datetime.day,
            self.datetime.month,
            self.datetime.year,
            i32::from(self.dst),
            self.clock_display as u8 as char,
            self.date_display as u8 as char,
        )
        .into_bytes()
        .into_iter()
    }
}

limited_u8! {
    /// A zone number in the range of `[1, 208]`.
    Zone max=208
}

limited_u8! {
    /// An area number in the range of `[1, 8]`.
    Area max=8
}

limited_u8! {
    /// A keypad number in the range of `[1, 16]`.
    Keypad max=16
}

limited_u8! {
    /// An automation task number in the range of `[1, 32]`.
    Task max=32
}

impl SendTimeData {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < 10 {
            return Err(format!("expected at least 10 bytes, got {}", data.len()));
        }
        let area = match data[0] {
            b @ b'1'..=b'8' => {
                Area(NonZeroU8::new(b - b'0').expect("1..=8 - 0 should be non-zero"))
            }
            b => return Err(format!("expected area in [1, 8], got {:?}", b)),
        };
        let ty = TimeDataType::try_from(data[1])?;
        let timer1 = parse_u8_dec("timer1", &data[2..5])?;
        let timer2 = parse_u8_dec("timer2", &data[5..8])?;
        let armed_state = if data.len() < 11 {
            None
        } else {
            Some(ArmedState::try_from(data[8])?)
        };
        Ok(SendTimeData {
            area,
            ty,
            timer1,
            timer2,
            armed_state,
        })
    }
    fn to_ascii(&self) -> AsciiPacket {
        let mut msg = format!(
            "EE{}{}{:03}{:03}",
            &self.area, self.ty as u8 as char, self.timer1, self.timer2
        );
        if let Some(s) = self.armed_state {
            msg.push(s as u8 as char);
        }
        msg.push_str("00"); // reserved
        AsciiPacket::try_from(msg).expect("SendTimeData invalid")
    }
    pub fn is_response_to(&self, _request: &Message) -> bool {
        false
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct ZoneStatus(
    /// The decoded hex nibble as a value in \[0, 16\).
    u8,
);

impl std::fmt::Debug for ZoneStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ZoneStatus")
            .field(&self.logical())
            .field(&self.physical())
            .finish()
    }
}

impl ZoneStatus {
    pub const UNCONFIGURED: ZoneStatus = ZoneStatus(0);

    pub const fn new(logical: ZoneLogicalStatus, physical: ZonePhysicalStatus) -> Self {
        ZoneStatus((logical as u8) << 2 | (physical as u8))
    }

    fn from_ascii(hex_nibble: u8) -> Result<Self, String> {
        Ok(ZoneStatus(AsciiPacket::dehex_nibble(hex_nibble).map_err(
            |()| format!("bad zone status {:?}", char::from(hex_nibble)),
        )?))
    }

    fn to_ascii(self) -> u8 {
        AsciiPacket::hex_nibble(self.0)
    }

    pub fn logical(self) -> ZoneLogicalStatus {
        match self.0 >> 2 {
            0b00 => ZoneLogicalStatus::Normal,
            0b01 => ZoneLogicalStatus::Trouble,
            0b10 => ZoneLogicalStatus::Violated,
            0b11 => ZoneLogicalStatus::Bypassed,
            _ => unreachable!(),
        }
    }

    pub fn physical(self) -> ZonePhysicalStatus {
        match self.0 & 0b11 {
            0b00 => ZonePhysicalStatus::Unconfigured,
            0b01 => ZonePhysicalStatus::Open,
            0b10 => ZonePhysicalStatus::EOL,
            0b11 => ZonePhysicalStatus::Short,
            _ => unreachable!(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary<'_> for ZoneStatus {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let b = u.bytes(1)?[0];
        if (b & 0xF0) != 0 {
            return Err(arbitrary::Error::IncorrectFormat);
        }
        Ok(Self(b))
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (1, Some(1))
    }
}

/// Zone physical status, the least significant 2 bits of a zone status nibble.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ZonePhysicalStatus {
    Unconfigured = 0b00,
    Open = 0b01,
    EOL = 0b10,
    Short = 0b11,
}

/// Zone logical status, the most significant 2 bits of a zone status nibble.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ZoneLogicalStatus {
    Normal = 0b00,
    Trouble = 0b01,
    Violated = 0b10,
    Bypassed = 0b11,
}

impl ZoneChange {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err(format!("expected at least 4 bytes, got {}", data.len()));
        }
        let zone = Zone::try_from(parse_u8_dec("zone", &data[0..3])?)?;
        Ok(ZoneChange {
            zone,
            status: ZoneStatus::from_ascii(data[3])?,
        })
    }
    fn to_ascii(self) -> AsciiPacket {
        let msg = format!("ZC{:03}{:1X}00", self.zone, self.status.0);
        AsciiPacket::try_from(msg).expect("ZoneChange invalid")
    }
    pub fn is_response_to(&self, _request: &Message) -> bool {
        false
    }
}

impl ZoneStatusRequest {
    fn from_ascii_data(_data: &[u8]) -> Result<Self, String> {
        Ok(ZoneStatusRequest {})
    }
    fn to_ascii(&self) -> AsciiPacket {
        AsciiPacket::try_from("zs00".to_owned()).expect("ZoneStatusRequest invalid")
    }
    pub fn is_response_to(&self, _request: &Message) -> bool {
        false
    }
}

impl ZoneStatusReport {
    pub const ALL_UNCONFIGURED: ZoneStatusReport = ZoneStatusReport {
        zones: [ZoneStatus::UNCONFIGURED; 208],
    };

    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < Zone::MAX {
            return Err(format!(
                "expected at least {} bytes, got {}",
                Zone::MAX,
                data.len()
            ));
        }
        let mut zones = [ZoneStatus(0); Zone::MAX];
        for i in 0..Zone::MAX {
            zones[i] = ZoneStatus::from_ascii(data[i])?;
        }
        Ok(ZoneStatusReport { zones })
    }
    fn to_ascii(self) -> AsciiPacket {
        let mut msg = Vec::with_capacity(4 + Zone::MAX);
        msg.extend(b"ZS");
        for s in &self.zones {
            msg.push(s.to_ascii());
        }
        msg.extend(b"00");
        AsciiPacket::try_from(msg).expect("ZoneStatusReport should be valid")
    }
    pub fn is_response_to(&self, request: &Message) -> bool {
        matches!(request, Message::ZoneStatusRequest(_))
    }
}

#[cfg(feature = "serde")]
impl Serialize for ZoneStatusReport {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        todo!()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ZoneStatusReport {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        todo!()
    }
}

impl std::fmt::Debug for ZoneStatusReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.zones.iter().enumerate().filter_map(|(i, s)| {
                if s.0 == 0 {
                    return None;
                }
                Some((i + 1, s))
            }))
            .finish()
    }
}

impl ArmRequest {
    fn from_ascii(subtype: u8, data: &[u8]) -> Result<Self, String> {
        // Message::parse will only call ArmRequest with valid subtypes.
        let level = ArmLevel::try_from(subtype).expect("subtype must be valid");
        if data.len() < 9 {
            return Err(format!(
                "Expected ArmRequest to have at least 9 bytes of data, got {}",
                data.len()
            ));
        }
        let area = Area::try_from(parse_u8_dec("area", &data[0..1])?)?;
        let code = ArmCode::try_from(&data[1..7])?;
        Ok(ArmRequest { area, level, code })
    }

    pub fn to_ascii(&self) -> AsciiPacket {
        let msg: Vec<u8> = [b'a', self.level as u8, self.area.0.get() + b'0']
            .iter()
            .chain(self.code.0.iter())
            .chain(b"00".iter())
            .copied()
            .collect();
        AsciiPacket::try_from(msg).expect("ArmRequest invalid")
    }

    pub fn is_response_to(&self, _request: &Message) -> bool {
        false
    }
}

impl ArmingStatusRequest {
    fn from_ascii_data(_data: &[u8]) -> Result<Self, String> {
        Ok(ArmingStatusRequest {})
    }
    pub fn to_ascii(&self) -> AsciiPacket {
        AsciiPacket::try_from("as00".to_owned()).expect("ArmingStatusRequest invalid")
    }
    pub fn is_response_to(&self, _request: &Message) -> bool {
        false
    }
}

byte_enum! {
    /// The arming status of a single area, as in the `S` array of an [`ArmingStatusReport`].
    pub enum ArmingStatus {
        Disarmed = b'0',
        ArmedAway = b'1',
        ArmedStay = b'2',
        ArmedStayInstant = b'3',
        ArmedNight = b'4',
        ArmedNightInstant = b'5',
        ArmedVacation = b'6',
    }
}

byte_enum! {
    /// The arm up state for use in [`ArmingStatusReport`].
    pub enum ArmUpState {
        NotReadyToArm = b'0',
        ReadyToArm = b'1',
        ReadyToForceArm = b'2',
        ArmedWithExitTimer = b'3',
        ArmedFully = b'4',
        ForceArmedWithForceArmZoneViolated = b'5',
        ArmedWithBypass = b'6',
    }
}

byte_enum! {
    /// The alarm state for use in [`ArmingStatusReport`].
    pub enum AlarmState {
        NoAlarmActive = b'0',
        EntranceDelayActive = b'1',
        AlarmAbortDelayActive = b'2',
        FireAlarm = b'3',
        MedicalAlarm = b'4',
        PoliceAlarm = b'5',
        BurglarAlarm = b'6',
        Aux1Alarm = b'7',
        Aux2Alarm = b'8',
        Aux3Alarm = b'9',
        Aux4Alarm = b':',
        CarbonMonoxideAlarm = b';',
        EmergencyAlarm = b'<',
        FreezeAlarm = b'=',
        GasAlarm = b'>',
        HeatAlarm = b'?',
        WaterAlarm = b'@',
        FireSupervisory = b'A',
        VerifyFire = b'B',
    }
}

impl AlarmMemory {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() != Area::MAX {
            return Err(format!("expected {} bytes", Area::MAX));
        }
        let mut memory = [false; Area::MAX];
        for i in 0..Area::MAX {
            memory[i] = parse_bool(data[i], "memory status")?;
        }
        Ok(AlarmMemory { memory })
    }
    pub fn to_ascii(&self) -> AsciiPacket {
        let msg: Vec<_> = b"AM"
            .iter()
            .copied()
            .chain(self.memory.iter().copied().map(fmt_bool))
            .collect();
        AsciiPacket::try_from(msg).expect("AlarmMemory valid ascii")
    }
    pub fn is_response_to(&self, _request: &Message) -> bool {
        false
    }
}

impl AlarmState {
    #[inline]
    pub fn is_firing(self) -> bool {
        self as u8 > AlarmState::FireAlarm as u8
    }
}

impl ArmingStatus {
    fn has_entry_delay(self) -> bool {
        use ArmingStatus::*;
        matches!(self, ArmedAway | ArmedStay | ArmedNight | ArmedVacation)
    }
}

impl ArmingStatusReport {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < 26 {
            return Err(format!("expected at least {} data", 26));
        }
        let mut arming_status = [ArmingStatus::Disarmed; Area::MAX];
        let mut up_state = [ArmUpState::ReadyToArm; Area::MAX];
        let mut alarm_state = [AlarmState::NoAlarmActive; Area::MAX];
        for i in 0..Area::MAX {
            arming_status[i] = ArmingStatus::try_from(data[i])?;
            up_state[i] = ArmUpState::try_from(data[Area::MAX + i])?;
            alarm_state[i] = AlarmState::try_from(data[2 * Area::MAX + i])?;
        }
        let first_exit_time =
            AsciiPacket::dehex_byte(data[24], data[25]).map_err(|()| "bad first_exit_time")?;
        Ok(ArmingStatusReport {
            arming_status,
            up_state,
            alarm_state,
            first_exit_time,
        })
    }
    pub fn to_ascii(&self) -> AsciiPacket {
        let msg: Vec<_> = b"AS"
            .iter()
            .copied()
            .chain(self.arming_status.iter().map(|&v| v as u8))
            .chain(self.up_state.iter().map(|&v| v as u8))
            .chain(self.alarm_state.iter().map(|&v| v as u8))
            .chain(AsciiPacket::hex_byte(self.first_exit_time).iter().copied())
            .collect();
        AsciiPacket::try_from(msg).expect("ArmingStatusResponse valid ascii")
    }
    pub fn is_response_to(&self, request: &Message) -> bool {
        matches!(request, Message::ArmingStatusRequest(_))
    }

    /// Checks if a `from`->`to` transition is likely to be spurious.
    ///
    /// See [this thread](https://www.elkproducts.com/forums/topic/spurious-armed-fully-message/).
    pub fn is_transition_suspicious(from: &ArmingStatusReport, to: &ArmingStatusReport) -> bool {
        for ((f_s, t_s), t_u) in from
            .arming_status
            .iter()
            .zip(to.arming_status.iter())
            .zip(to.up_state.iter())
        {
            if *f_s == ArmingStatus::Disarmed
                && t_s.has_entry_delay()
                && *t_u == ArmUpState::ArmedFully
            {
                return true;
            }
        }
        false
    }
}

impl RpStatusUpdate {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err(format!("expected at least 4 bytes, got {}", data.len()));
        }
        let b = AsciiPacket::dehex_byte(data[0], data[1]).map_err(|()| "invalid hex code")?;
        let status = RpStatus::try_from(b)?;
        Ok(RpStatusUpdate { status })
    }
    fn is_response_to(&self, _request: &Message) -> bool {
        matches!(self.status, RpStatus::Connected | RpStatus::Initializing)
    }
    fn to_ascii(self) -> AsciiPacket {
        let msg: Vec<u8> = [b'R', b'P']
            .iter()
            .copied()
            .chain(AsciiPacket::hex_byte(self.status as u8))
            .chain([b'0', b'0'])
            .collect();
        AsciiPacket::try_from(msg).expect("RpStatusUpdate valid")
    }
}

num_enum! {
    /// Type of object to describe in a [`StringDescriptionRequest`].
    pub enum TextDescriptionType {
        Zone = 0,
        Area = 1,
        User = 2,
        Keypad = 3,
        Output = 4,
        Task = 5,
        Telephone = 6,
        Light = 7,
        AlarmDuration = 8,
        CustomSettings = 9,
        Counter = 10,
        Thermostat = 11,
        FunctionKey1 = 12,
        FunctionKey2 = 13,
        FunctionKey3 = 14,
        FunctionKey4 = 15,
        FunctionKey5 = 16,
        FunctionKey6 = 17,
        AudioZone = 18,
        AudioSource = 19,
    }
}

impl SendCode {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < 19 {
            return Err(format!("expected at least 19 bytes, got {}", data.len()));
        }
        let mut code = [0u8; 6];
        for i in 0..6 {
            code[i] = AsciiPacket::dehex_byte(data[2 * i], data[2 * i + 1])
                .map_err(|()| "invalid hex code")?;
        }
        let user = parse_u8_dec("user", &data[12..15])?;
        let keypad = Keypad::try_from(parse_u8_dec("keypad", &data[15..17])?)?;
        Ok(SendCode { code, user, keypad })
    }
    fn is_response_to(&self, request: &Message) -> bool {
        // We could narrow it down further by eliminating invalid code responses with a different
        // code, but this is probably pointless.
        matches!(request, Message::ArmRequest(_))
    }
    fn to_ascii(&self) -> AsciiPacket {
        let trailer = format!("{:03}{:02}00", self.user, self.keypad);
        let msg: Vec<u8> = [b'I', b'C']
            .iter()
            .copied()
            .chain(self.code.iter().copied().flat_map(AsciiPacket::hex_byte))
            .chain(trailer.as_bytes().iter().copied())
            .collect();
        AsciiPacket::try_from(msg).expect("SendCode valid")
    }
}

impl RtcRequest {
    fn from_ascii_data(_data: &[u8]) -> Result<Self, String> {
        Ok(RtcRequest {})
    }
    fn to_ascii(self) -> AsciiPacket {
        AsciiPacket::try_from("rr00").expect("RtcResponse valid")
    }
    fn is_response_to(&self, _request: &Message) -> bool {
        false
    }
}

impl RtcResponse {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        Ok(RtcResponse {
            rtc_data: RtcData::from_ascii(data)?,
        })
    }
    fn to_ascii(self) -> AsciiPacket {
        let msg: Vec<u8> = [b'R', b'R']
            .iter()
            .copied()
            .chain(self.rtc_data.to_ascii())
            .collect();
        AsciiPacket::try_from(msg).expect("RtcResponse valid")
    }
    fn is_response_to(&self, request: &Message) -> bool {
        matches!(request, Message::RtcRequest(_))
    }
}

impl StringDescriptionRequest {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < 5 {
            return Err(format!("expected at least 5 bytes, got {}", data.len()));
        }
        let ty = TextDescriptionType::try_from(parse_u8_dec("type", &data[0..2])?)?;
        let num = parse_u8_dec("num", &data[2..5])?;
        Ok(StringDescriptionRequest { ty, num })
    }
    fn is_response_to(&self, _request: &Message) -> bool {
        false
    }
    fn to_ascii(&self) -> AsciiPacket {
        let msg = format!("sd{:02}{:03}00", self.ty as u8, self.num);
        AsciiPacket::try_from(msg).expect("StringDescriptionRequest valid")
    }
}

/// A 16-byte printable ASCII description, with spaces used as trailing padding.
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct TextDescription([u8; 16]);

impl TextDescription {
    pub const EMPTY: TextDescription = TextDescription(*b"                ");

    /// Uses up to 16 bytes of `text`, which must be ASCII printable characters.
    pub fn new(text: &str) -> Result<Self, String> {
        AsciiPacket::check_no_low_bytes(text.as_bytes())?;
        let mut this = Self::default();
        for (b_in, b_out) in text.as_bytes().iter().zip(this.0.iter_mut()) {
            *b_out = *b_in;
        }
        Ok(this)
    }

    pub fn as_str(&self) -> &str {
        let end = self
            .0
            .iter()
            .position(|&b| b == b' ')
            .unwrap_or(self.0.len());
        std::str::from_utf8(&self.0[..end]).expect("TextDescription should be valid UTF-8")
    }

    pub fn is_empty(&self) -> bool {
        self.0[0] == b' '
    }
}

impl std::fmt::Display for TextDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.as_str(), f)
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct TextDescriptions<const N: usize>(pub [TextDescription; N]);

impl<const N: usize> TextDescriptions<N> {
    pub const ALL_EMPTY: TextDescriptions<N> = TextDescriptions([TextDescription::EMPTY; N]);
}

impl<const N: usize> std::ops::Index<usize> for TextDescriptions<N> {
    type Output = TextDescription;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<const N: usize> std::fmt::Debug for TextDescriptions<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.0.iter().enumerate().filter_map(|(i, d)| {
                if d.is_empty() {
                    return None;
                }
                Some((i + 1, d))
            }))
            .finish()
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary<'_> for TextDescription {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut buf = [b' '; 16];
        let mut i = 0;
        u.arbitrary_loop(Some(0), Some(16), |u| {
            buf[i] = u.int_in_range(0x21..=0x7F)?;
            i += 1;
            Ok(std::ops::ControlFlow::Continue(()))
        })?;
        Ok(TextDescription(buf))
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (0, Some(16))
    }
}

impl Default for TextDescription {
    fn default() -> Self {
        TextDescription([b' '; 16])
    }
}

impl std::fmt::Debug for TextDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

impl std::ops::Deref for TextDescription {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl std::cmp::PartialEq<str> for TextDescription {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl StringDescriptionResponse {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < 21 {
            return Err(format!("expected at least 5 bytes, got {}", data.len()));
        }
        let ty = TextDescriptionType::try_from(parse_u8_dec("type", &data[0..2])?)?;
        let num = parse_u8_dec("num", &data[2..5])?;
        let mut text: [u8; 16] = data[5..21]
            .try_into()
            .expect("fixed slice and array lengths should match");
        let show_on_keypad = (text[0] & 0b1000_0000) != 0;
        text[0] &= 0b0111_1111;
        let text = TextDescription(text);
        Ok(StringDescriptionResponse {
            ty,
            num,
            show_on_keypad,
            text,
        })
    }
    fn to_ascii(&self) -> AsciiPacket {
        let mut out = Vec::with_capacity(7 + 16 + 2);
        use std::io::Write;
        write!(&mut out, "SD{:02}{:03}", self.ty as u8, self.num)
            .expect("write to Vec should succeed");
        out.extend(&self.text.0[..]);
        out.extend(b"00");
        if self.show_on_keypad {
            out[7] |= 0x80;
        }
        AsciiPacket::try_from(out).expect("StringDescriptionResponse valid")
    }
    fn is_response_to(&self, request: &Message) -> bool {
        matches!(
            request,
            Message::StringDescriptionRequest(StringDescriptionRequest { ty, num })

            // > If the first character in a requested name is a “space” or
            // > less, then the next names are searched until a name is found
            // > whose first character is greater than “space” or the “Show On
            // > Keypad” bit is set. If no valid names are found, a “000” for
            // > the NNN address is returned. This speeds up the loading of
            // > names so that invalid names are not returned. M1 version 2.4.6
            // or later.
            if self.ty == *ty && (self.num >= *num || self.num == 0)
        )
    }
}

impl SystemTroubleStatusRequest {
    fn from_ascii_data(_data: &[u8]) -> Result<Self, String> {
        Ok(SystemTroubleStatusRequest {})
    }
    fn to_ascii(&self) -> AsciiPacket {
        AsciiPacket::try_from("ss00").expect("SystemTroubleStatusRequest should be valid")
    }
    fn is_response_to(&self, _request: &Message) -> bool {
        false
    }
}

impl SystemTroubleStatusResponse {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < 34 {
            return Err(format!(
                "SS should be at least 34 bytes, got {}",
                data.len()
            ));
        }
        let ac_fail = parse_bool(data[0], "ac_fail")?;
        let box_tamper = ZoneTrouble::parse(data[1], "box_tamper")?;
        let fail_to_communicate = parse_bool(data[2], "fail_to_communicate")?;
        let eeprom_memory_error = parse_bool(data[3], "eeprom_memory_error")?;
        let control_low_battery = parse_bool(data[4], "control_low_battery")?;
        let transmitter_low_battery = ZoneTrouble::parse(data[5], "transmitter_low_battery")?;
        let over_current_trouble = parse_bool(data[6], "over_current_trouble")?;
        let telephone_fault_trouble = parse_bool(data[7], "telephone_fault_trouble")?;
        // data[8] is unused
        let output_2_trouble = parse_bool(data[9], "output_2_trouble")?;
        let missing_keypad_trouble = parse_bool(data[10], "missing_keypad_trouble")?;
        let zone_expander_trouble = parse_bool(data[11], "zone_expander_trouble")?;
        let output_expander = parse_bool(data[12], "output_expander")?;
        // data[13] is not used
        let elkrp_remote_access = parse_bool(data[14], "elkrp_remote_access")?;
        // data[15] is not used
        let common_area_not_armed = parse_bool(data[16], "common_area_not_armed")?;
        let flash_memory_error = parse_bool(data[17], "flash_memory_error")?;
        let security_alert = ZoneTrouble::parse(data[18], "security_alert")?;
        let serial_port_expander = parse_bool(data[19], "serial_port_expander")?;
        let lost_transmitter = ZoneTrouble::parse(data[20], "lost_transmitter")?;
        let ge_smoke_cleanme = parse_bool(data[21], "ge_smoke_cleanme")?;
        let ethernet = parse_bool(data[22], "ethernet")?;
        // data[23..=30] are not used.
        let display_message_keypad_line1 = parse_bool(data[31], "display_message_keypad_line1")?;
        let display_message_keypad_line2 = parse_bool(data[32], "display_message_keypad_line2")?;
        let fire = ZoneTrouble::parse(data[33], "fire")?; // TODO: different?
        Ok(SystemTroubleStatusResponse {
            ac_fail,
            box_tamper,
            fail_to_communicate,
            eeprom_memory_error,
            control_low_battery,
            transmitter_low_battery,
            over_current_trouble,
            telephone_fault_trouble,
            output_2_trouble,
            missing_keypad_trouble,
            zone_expander_trouble,
            output_expander,
            elkrp_remote_access,
            common_area_not_armed,
            flash_memory_error,
            security_alert,
            serial_port_expander,
            lost_transmitter,
            ge_smoke_cleanme,
            ethernet,
            display_message_keypad_line1,
            display_message_keypad_line2,
            fire,
        })
    }
    fn to_ascii(&self) -> AsciiPacket {
        AsciiPacket::try_from(
            &[
                b'S',
                b'S',
                fmt_bool(self.ac_fail),
                self.box_tamper.fmt(),
                fmt_bool(self.fail_to_communicate),
                fmt_bool(self.eeprom_memory_error),
                fmt_bool(self.control_low_battery),
                self.transmitter_low_battery.fmt(),
                fmt_bool(self.over_current_trouble),
                fmt_bool(self.telephone_fault_trouble),
                b'0',
                fmt_bool(self.output_2_trouble),
                fmt_bool(self.missing_keypad_trouble),
                fmt_bool(self.zone_expander_trouble),
                fmt_bool(self.output_expander),
                b'0',
                fmt_bool(self.elkrp_remote_access),
                b'0',
                fmt_bool(self.common_area_not_armed),
                fmt_bool(self.flash_memory_error),
                self.security_alert.fmt(),
                fmt_bool(self.serial_port_expander),
                self.lost_transmitter.fmt(),
                fmt_bool(self.ge_smoke_cleanme),
                fmt_bool(self.ethernet),
                b'0',
                b'0',
                b'0',
                b'0',
                b'0',
                b'0',
                b'0',
                b'0',
                fmt_bool(self.display_message_keypad_line1),
                fmt_bool(self.display_message_keypad_line2),
                self.fire.fmt(),
                b'0',
                b'0',
            ][..],
        )
        .expect("SystemTroubleStatusRequest should be valid")
    }
    fn is_response_to(&self, request: &Message) -> bool {
        matches!(request, Message::SystemTroubleStatusRequest(_))
    }
}

/// Represents an optional zone number that is in trouble.
///
/// This is meant to be like an `Option<Zone>`, but the Elk protocol has an
/// off-by-one error. Zone trouble is communicated in `SS` as `b'0' +
/// zone_number`, and so the maximum zone of 208 doesn't fit in a byte. To
/// maintain our property that all messages round-trip successfully (and
/// certainly without panicking due to out-of-range condition), we have this
/// dedicated type which doesn't allow zone 208. I have no idea how the Elk
/// would handle trouble with that zone, but it seems worth avoiding that zone
/// number if possible...
#[derive(Copy, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ZoneTrouble(u8);

impl ZoneTrouble {
    pub fn none() -> Self {
        ZoneTrouble(0)
    }

    pub fn get(self) -> Option<Zone> {
        NonZeroU8::new(self.0).map(Zone)
    }

    fn parse(data: u8, which: &str) -> Result<Self, String> {
        data.checked_sub(b'0')
            .map(ZoneTrouble)
            .ok_or_else(|| format!("invalid {which} zone trouble byte"))
    }

    fn fmt(&self) -> u8 {
        self.0 + b'0'
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ZoneTrouble {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <Option<u8> as Deserialize>::deserialize(deserializer)?;
        match value {
            None => Ok(Self(0)),
            Some(value) if !(1..=207).contains(&value) => {
                Err(D::Error::custom(format!("value out of range: {}", value)))
            }
            Some(value) => Ok(Self(value)),
        }
    }
}

impl std::fmt::Debug for ZoneTrouble {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.get(), f)
    }
}

impl TryFrom<u8> for ZoneTrouble {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if !(1..208).contains(&value) {
            return Err(format!("invalid zone {value} for trouble message"));
        }
        Ok(ZoneTrouble(value))
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary<'_> for ZoneTrouble {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        u.int_in_range(1..=207).map(Self)
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        let _ = depth;
        (1, Some(1))
    }
}

impl ActivateTask {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < 3 {
            return Err(format!("expected at least 3 bytes, got {}", data.len()));
        }
        let task = Task::try_from(parse_u8_dec("task", &data[..3])?)?;
        Ok(ActivateTask { task })
    }
    fn to_ascii(&self) -> AsciiPacket {
        let msg = format!("tn{:03}00", self.task.0);
        AsciiPacket::try_from(msg).expect("Task valid")
    }
    fn is_response_to(&self, _request: &Message) -> bool {
        false
    }
}

impl TaskChange {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < 3 {
            return Err(format!("expected at least 3 bytes, got {}", data.len()));
        }
        let task = Task::try_from(parse_u8_dec("task", &data[..3])?)?;
        Ok(TaskChange { task })
    }
    fn to_ascii(&self) -> AsciiPacket {
        let msg = format!("TC{:03}000", self.task.0);
        AsciiPacket::try_from(msg).expect("Task valid")
    }
    fn is_response_to(&self, request: &Message) -> bool {
        matches!(request, Message::ActivateTask(t) if t.task == self.task)
    }
}

impl Heartbeat {
    fn from_ascii_data(data: &[u8]) -> Result<Self, String> {
        Ok(Heartbeat {
            rtc_data: RtcData::from_ascii(data)?,
        })
    }
    fn to_ascii(self) -> AsciiPacket {
        let msg: Vec<u8> = [b'X', b'K']
            .iter()
            .copied()
            .chain(self.rtc_data.to_ascii())
            .collect();
        AsciiPacket::try_from(msg).expect("Heartbeat valid")
    }
    fn is_response_to(&self, _request: &Message) -> bool {
        false
    }
}

fn parse_bool(b: u8, name: &str) -> Result<bool, String> {
    match b {
        b'0' => Ok(false),
        b'1' => Ok(true),
        _ => Err(format!("unexpected value {b:x?} for {name}")),
    }
}

fn fmt_bool(b: bool) -> u8 {
    match b {
        false => b'0',
        true => b'1',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn valid_am_update() {
        let pkt = Packet::Ascii(AsciiPacket::try_from("AM00000001").unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(
            msg,
            Message::AlarmMemory(AlarmMemory {
                memory: [false, false, false, false, false, false, false, true]
            })
        );
        assert_eq!(msg.to_pkt(), pkt);
    }

    #[test]
    fn valid_as_report_with_timer() {
        let mut expected = ArmingStatusReport {
            arming_status: [ArmingStatus::Disarmed; Area::MAX],
            up_state: [ArmUpState::ReadyToArm; Area::MAX],
            alarm_state: [AlarmState::NoAlarmActive; Area::MAX],
            first_exit_time: 59,
        };
        expected.arming_status[0] = ArmingStatus::ArmedStay;
        expected.up_state[0] = ArmUpState::ArmedWithExitTimer;
        let pkt = Packet::Ascii(AsciiPacket::try_from("AS2000000031111111000000003B").unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(msg, Message::ArmingStatusReport(expected));
        assert_eq!(msg.to_pkt(), pkt);
    }

    #[test]
    fn valid_old_ee_report() {
        let pkt = Packet::Ascii(AsciiPacket::try_from("EE1103000000").unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(
            msg,
            Message::SendTimeData(SendTimeData {
                area: Area::try_from(1).unwrap(),
                ty: TimeDataType::Entry,
                timer1: 30,
                timer2: 0,
                armed_state: None,
            })
        );
        assert_eq!(msg.to_pkt(), pkt);
    }

    #[test]
    fn valid_new_ee_report() {
        let pkt = Packet::Ascii(AsciiPacket::try_from("EE11030000100").unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(
            msg,
            Message::SendTimeData(SendTimeData {
                area: Area::try_from(1).unwrap(),
                ty: TimeDataType::Entry,
                timer1: 30,
                timer2: 0,
                armed_state: Some(ArmedState::ArmedAway),
            })
        );
        assert_eq!(msg.to_pkt(), pkt);
    }

    #[test]
    fn valid_new_ic_report() {
        let pkt = Packet::Ascii(AsciiPacket::try_from("IC0000010203040000100").unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(
            msg,
            Message::SendCode(SendCode {
                code: [0, 0, 1, 2, 3, 4],
                user: 0,
                keypad: Keypad::try_from(1).unwrap(),
            })
        );
        assert_eq!(msg.to_pkt(), pkt);
    }

    #[test]
    fn valid_rp_update() {
        let pkt = Packet::Ascii(AsciiPacket::try_from("RP0100").unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(
            msg,
            Message::RpStatusUpdate(RpStatusUpdate {
                status: RpStatus::Connected,
            })
        );
        assert_eq!(msg.to_pkt(), pkt);
    }

    #[test]
    fn valid_sd_req() {
        let pkt = Packet::Ascii(AsciiPacket::try_from("sd0100100").unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(
            msg,
            Message::StringDescriptionRequest(StringDescriptionRequest {
                ty: TextDescriptionType::Area,
                num: 1,
            })
        );
        assert_eq!(msg.to_pkt(), pkt);
    }

    #[test]
    fn valid_sd_report() {
        let pkt = Packet::Ascii(AsciiPacket::try_from("SD05001Garage Door     00").unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(
            msg,
            Message::StringDescriptionResponse(StringDescriptionResponse {
                ty: TextDescriptionType::Task,
                num: 1,
                show_on_keypad: false,
                text: TextDescription::new("Garage Door").unwrap(),
            })
        );
        assert_eq!(msg.to_pkt(), pkt);
    }

    #[test]
    fn valid_sd_report_with_high_bit() {
        let pkt =
            Packet::Ascii(AsciiPacket::try_from(&b"SD05001\xc7arage Door     00"[..]).unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(
            msg,
            Message::StringDescriptionResponse(StringDescriptionResponse {
                ty: TextDescriptionType::Task,
                num: 1,
                show_on_keypad: true,
                text: TextDescription::new("Garage Door").unwrap(),
            })
        );
        assert_eq!(msg.to_pkt(), pkt);
    }

    #[test]
    fn valid_ss_report() {
        let pkt =
            Packet::Ascii(AsciiPacket::try_from("SS000000000100000000000000000000010A00").unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(
            msg,
            Message::SystemTroubleStatusResponse(SystemTroubleStatusResponse {
                output_2_trouble: true,
                display_message_keypad_line1: true,
                fire: ZoneTrouble::try_from(17).expect("17 should be a valid zone"),
                ..Default::default()
            })
        );
        assert_eq!(msg.to_pkt(), pkt);
    }

    #[test]
    fn valid_zc_report() {
        let pkt = Packet::Ascii(AsciiPacket::try_from("ZC016900").unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(
            msg,
            Message::ZoneChange(ZoneChange {
                zone: Zone::try_from(16).unwrap(),
                status: ZoneStatus::new(ZoneLogicalStatus::Violated, ZonePhysicalStatus::Open),
            })
        );
        assert_eq!(msg.to_pkt(), pkt);
    }

    #[test]
    fn suspicious() {
        let disarmed = ArmingStatusReport {
            arming_status: [ArmingStatus::Disarmed; Area::MAX],
            up_state: [ArmUpState::ReadyToArm; Area::MAX],
            alarm_state: [AlarmState::NoAlarmActive; Area::MAX],
            first_exit_time: 0,
        };
        let mut arming = disarmed;
        arming.arming_status[0] = ArmingStatus::ArmedStay;
        arming.up_state[0] = ArmUpState::ArmedWithExitTimer;
        let mut armed = disarmed;
        armed.arming_status[0] = ArmingStatus::ArmedStay;
        armed.up_state[0] = ArmUpState::ArmedFully;
        assert!(!ArmingStatusReport::is_transition_suspicious(
            &disarmed, &arming
        ));
        assert!(ArmingStatusReport::is_transition_suspicious(
            &disarmed, &armed
        ));
        assert!(!ArmingStatusReport::is_transition_suspicious(
            &arming, &armed
        ));
        assert!(!ArmingStatusReport::is_transition_suspicious(
            &armed, &disarmed
        ));
    }

    #[test]
    fn rtc() {
        const ENCODED: &[u8; 16] = b"0059107251205110";
        let parsed = RtcData::from_ascii(ENCODED).unwrap();
        assert_eq!(
            parsed,
            RtcData {
                datetime: DateTime::from_iso_8601("2005-12-25T10:59:00").unwrap(),
                weekday: Weekday::Sat,
                dst: true,
                clock_display: ClockDisplayMode::TwelveHour,
                date_display: DateDisplayMode::MonthFirst,
            },
        );
        let reencoded: Vec<u8> = parsed.to_ascii().collect();
        assert_eq!(&ENCODED[..], &reencoded[..]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_limited() {
        assert_eq!(
            ZoneTrouble(0),
            serde_json::from_str::<ZoneTrouble>("null").unwrap()
        );
        assert_eq!(
            ZoneTrouble(207),
            serde_json::from_str::<ZoneTrouble>("207").unwrap()
        );
        serde_json::from_str::<ZoneTrouble>("208").unwrap_err();
        assert_eq!(
            Zone::try_from(208).unwrap(),
            serde_json::from_str::<Zone>("208").unwrap()
        );
        serde_json::from_str::<Zone>("255").unwrap_err();
    }
}
