// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Message layer: statelessly converts [`crate::pkt`] packets into higher-level
//! messages and vice versa.

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;

use std::str::FromStr;

use crate::pkt::{AsciiPacket, Packet};

#[derive(Clone, Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {}

fn parse_u8_dec(name: &str, val: &str) -> Result<u8, String> {
    u8::from_str(val)
        .map_err(|_| format!("{} expected to be decimal in [0, 255); got {:?}", name, val))
}

/// Defines all messages, taking care of some `enum Message` and `Into`
/// boilerplate.
macro_rules! messages {
    (
        $(
            #[doc=$doc:literal]
            $(#[$other_attrs:meta])*
            struct $m:ident $body:tt
        )+
    ) => {
        /// A parsed (ASCII) message of any supported type.
        #[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
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
            pub fn is_reply_to(&self, request: &Message) -> bool {
                match self {
                    $(
                        Message::$m(m) => m.is_reply_to(request),
                    )*
                }
            }
        }

        $(
            #[doc=$doc]
            $(#[$other_attrs])*
            #[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
            pub struct $m $body

            impl Into<Message> for $m {
                #[inline]
                fn into(self) -> Message {
                    Message::$m(self)
                }
            }
            impl Into<AsciiPacket> for &$m {
                #[inline]
                fn into(self) -> AsciiPacket {
                    self.to_ascii()
                }
            }
            impl Into<Packet> for &$m {
                #[inline]
                fn into(self) -> Packet {
                    Packet::Ascii(self.to_ascii())
                }
            }
        )*
    }
}

messages! {
    /// `as`: Arming Status Request.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ArmingStatusRequest {}

    /// `AS`: Arming Status Report.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    struct ArmingStatusReport {
        pub arming_status: [ArmingStatus; NUM_AREAS],
        pub up_state: [ArmUpState; NUM_AREAS],
        pub alarm_state: [AlarmState; NUM_AREAS],
    }

    /// `EE`: Send Entry/Exit Time Data.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SendTimeData {
        pub area: Area,
        pub ty: TimeDataType,
        pub timer1: u8,
        pub timer2: u8,

        /// The armed state, which according to documentation is only present
        /// for M1 Ver. 4.1.18, 5.1.18 or later.
        pub armed_state: Option<ArmedState>,
    }

    /// `sd`: Request ASCII String Text Descriptions.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct StringDescriptionRequest {
        pub ty: TextDescriptionType,
        pub num: u8,
    }

    /// `SD`: ASCII String Text Descriptions.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct StringDescriptionResponse {
        pub ty: TextDescriptionType,
        pub num: u8,
        pub text: TextDescription,
    }

    /// `ZC`: Zone Change Update.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    struct ZoneChange {
        pub zone: Zone,
        pub status: ZoneStatus,
    }

    /// `zs`: Zone Status Request.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ZoneStatusRequest {}

    /// `ZS`: Zone Status Report.
    #[derive(Clone, PartialEq, Eq)]
    struct ZoneStatusReport {
        pub zones: [ZoneStatus; NUM_ZONES],
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
        if pkt.len() < 4 {
            return Err(Error("malformed ASCII message: too short".into()));
        }
        let (cmd, rest) = pkt.split_at(2);

        // The "00" bytes are apparently mandatory. Even when the data is
        // extended (as "EE" was), new bytes are added before the "00".
        // The "00"s get in the way of checking lengths for the new fields, so
        // remove them now.
        let data = match rest.strip_suffix("00") {
            Some(d) => d,
            None => {
                return Err(Error(
                    "malformed ASCII message: missing reserved bytes".into(),
                ))
            }
        };
        match cmd {
            "as" => ArmingStatusRequest::from_ascii_data(data).map(Self::ArmingStatusRequest),
            "AS" => ArmingStatusReport::from_ascii_data(data).map(Self::ArmingStatusReport),
            "EE" => SendTimeData::from_ascii_data(data).map(Self::SendTimeData),
            "sd" => {
                StringDescriptionRequest::from_ascii_data(data).map(Self::StringDescriptionRequest)
            }
            "SD" => StringDescriptionResponse::from_ascii_data(data)
                .map(Self::StringDescriptionResponse),
            "ZC" => ZoneChange::from_ascii_data(data).map(Self::ZoneChange),
            "zs" => ZoneStatusRequest::from_ascii_data(data).map(Self::ZoneStatusRequest),
            "ZS" => ZoneStatusReport::from_ascii_data(data).map(Self::ZoneStatusReport),
            _ => return Ok(None),
        }
        .map(Some)
        .map_err(Error)
    }
}

impl Into<Packet> for &Message {
    fn into(self) -> Packet {
        self.to_pkt()
    }
}

/// Defines an enum for a `u8` with an automatic `TryFrom` that uses the
/// explicit discriminant as the byte value.
macro_rules! byte_enum {
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

/// Creates a `u8` wrapper that enforces a range of `[1, $max]`.
macro_rules! limited_u8 {
    (
        #[doc=$enum_doc:literal]
        $t:ident max=$max:literal
    ) => {
        #[repr(transparent)]
        #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $t(u8);

        impl $t {
            pub fn to_index(self) -> usize {
                self.0 as usize - 1
            }
        }

        #[cfg(feature = "arbitrary")]
        impl Arbitrary<'_> for $t {
            fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
                let mut buf = [0u8; 1];
                u.fill_buffer(&mut buf)?;
                $t::try_from(buf[0]).map_err(|_| arbitrary::Error::IncorrectFormat)
            }

            fn size_hint(_depth: usize) -> (usize, Option<usize>) {
                (1, Some(1))
            }
        }

        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(&self.0, f)
            }
        }

        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl TryFrom<u8> for $t {
            type Error = String;
            fn try_from(val: u8) -> Result<Self, Self::Error> {
                if val < 1 || val > $max {
                    return Err(format!(
                        "{} not in expected {} range of [1, {}]",
                        val,
                        stringify!(t),
                        $max
                    ));
                }
                Ok(Self(val))
            }
        }

        impl Into<u8> for $t {
            fn into(self) -> u8 {
                self.0
            }
        }
    };
}

limited_u8! {
    /// A zone number in the range of `[1, 208]`.
    Zone max=208
}

limited_u8! {
    /// An area number in the range of `[1, 8]`.
    Area max=8
}

impl SendTimeData {
    fn from_ascii_data(data: &str) -> Result<Self, String> {
        if data.len() < 8 {
            return Err(format!("expected at least 8 bytes, got {}", data.len()));
        }
        let area = match data.as_bytes()[0] {
            b @ b'1'..=b'8' => Area(b - b'0'),
            b => return Err(format!("expected area in [1, 8], got {:?}", b)),
        };
        let ty = TimeDataType::try_from(data.as_bytes()[1])?;
        let timer1 = parse_u8_dec("timer1", &data[2..5])?;
        let timer2 = parse_u8_dec("timer2", &data[5..8])?;
        let armed_state = data
            .as_bytes()
            .get(8)
            .copied()
            .map(ArmedState::try_from)
            .transpose()?;
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
    pub fn is_reply_to(&self, _request: &Message) -> bool {
        false
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq)]
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
    pub fn new(logical: ZoneLogicalStatus, physical: ZonePhysicalStatus) -> Self {
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
        let mut buf = [0u8; 1];
        u.fill_buffer(&mut buf)?;
        if (buf[0] & 0xF0) != 0 {
            return Err(arbitrary::Error::IncorrectFormat);
        }
        Ok(Self(buf[0]))
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
    fn from_ascii_data(data: &str) -> Result<Self, String> {
        if data.len() < 4 {
            return Err(format!("expected at least 4 bytes, got {}", data.len()));
        }
        let zone = Zone::try_from(parse_u8_dec("zone", &data[0..3])?)?;
        Ok(ZoneChange {
            zone,
            status: ZoneStatus::from_ascii(data.as_bytes()[3])?,
        })
    }
    fn to_ascii(&self) -> AsciiPacket {
        let msg = format!("ZC{:03}{:1X}00", self.zone, self.status.0);
        AsciiPacket::try_from(msg).expect("ZoneChange invalid")
    }
    pub fn is_reply_to(&self, _request: &Message) -> bool {
        false
    }
}

impl ZoneStatusRequest {
    fn from_ascii_data(_data: &str) -> Result<Self, String> {
        Ok(ZoneStatusRequest {})
    }
    fn to_ascii(&self) -> AsciiPacket {
        AsciiPacket::try_from("zs00".to_owned()).expect("ZoneStatusRequest invalid")
    }
    pub fn is_reply_to(&self, _request: &Message) -> bool {
        false
    }
}

pub const NUM_ZONES: usize = 208;

impl ZoneStatusReport {
    fn from_ascii_data(data: &str) -> Result<Self, String> {
        let args = data.as_bytes();
        if args.len() < NUM_ZONES {
            return Err(format!(
                "expected at least {} bytes, got {}",
                NUM_ZONES,
                args.len()
            ));
        }
        let mut zones = [ZoneStatus(0); NUM_ZONES];
        for i in 0..NUM_ZONES {
            zones[i] = ZoneStatus::from_ascii(args[i])?;
        }
        Ok(ZoneStatusReport { zones })
    }
    fn to_ascii(&self) -> AsciiPacket {
        let mut msg = Vec::with_capacity(4 + NUM_ZONES);
        msg.extend(b"ZS");
        for s in &self.zones {
            msg.push(s.to_ascii());
        }
        msg.extend(b"00");
        AsciiPacket::try_from(msg).expect("ZoneStatusReport should be valid")
    }
    pub fn is_reply_to(&self, request: &Message) -> bool {
        matches!(request, Message::ZoneStatusRequest(_))
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

impl ArmingStatusRequest {
    fn from_ascii_data(_data: &str) -> Result<Self, String> {
        Ok(ArmingStatusRequest {})
    }
    pub fn to_ascii(&self) -> AsciiPacket {
        AsciiPacket::try_from("as00".to_owned()).expect("ArmingStatusRequest invalid")
    }
    pub fn is_reply_to(&self, _request: &Message) -> bool {
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

pub const NUM_AREAS: usize = 8;

impl ArmingStatusReport {
    fn from_ascii_data(data: &str) -> Result<Self, String> {
        let data = data.as_bytes();
        if data.len() < 3 * NUM_AREAS {
            return Err(format!("expected at least {} bytes", 3 * NUM_AREAS));
        }
        let mut arming_status = [ArmingStatus::Disarmed; NUM_AREAS];
        let mut up_state = [ArmUpState::ReadyToArm; NUM_AREAS];
        let mut alarm_state = [AlarmState::NoAlarmActive; NUM_AREAS];
        for i in 0..8 {
            arming_status[i] = ArmingStatus::try_from(data[i])?;
            up_state[i] = ArmUpState::try_from(data[NUM_AREAS + i])?;
            alarm_state[i] = AlarmState::try_from(data[2 * NUM_AREAS + i])?;
        }
        Ok(ArmingStatusReport {
            arming_status,
            up_state,
            alarm_state,
        })
    }
    pub fn to_ascii(&self) -> AsciiPacket {
        //let msg = Vec::with_capacity(4 + 3 * NUM_AREAS);
        //msg.extend(b"AS");
        let msg: Vec<_> = b"AS"
            .iter()
            .copied()
            .chain(self.arming_status.iter().map(|&v| v as u8))
            .chain(self.up_state.iter().map(|&v| v as u8))
            .chain(self.alarm_state.iter().map(|&v| v as u8))
            .chain(b"00".iter().copied())
            .collect();
        AsciiPacket::try_from(msg).expect("ArmingStatusResponse valid ascii")
    }
    pub fn is_reply_to(&self, request: &Message) -> bool {
        matches!(request, Message::ArmingStatusRequest(_))
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

impl StringDescriptionRequest {
    fn from_ascii_data(data: &str) -> Result<Self, String> {
        if data.len() < 5 {
            return Err(format!("expected at least 5 bytes, got {}", data.len()));
        }
        let ty = TextDescriptionType::try_from(parse_u8_dec("type", &data[0..2])?)?;
        let num = parse_u8_dec("num", &data[2..5])?;
        Ok(StringDescriptionRequest { ty, num })
    }
    fn is_reply_to(&self, _request: &Message) -> bool {
        false
    }
    fn to_ascii(&self) -> AsciiPacket {
        let msg = format!("sd{:02}{:03}00", self.ty as u8, self.num);
        AsciiPacket::try_from(msg).expect("StringDescriptionRequest valid")
    }
}

/// A 16-byte printable ASCII description, with spaces used as trailing padding.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TextDescription([u8; 16]);

impl TextDescription {
    /// Uses up to 16 bytes of `text`, which must be ASCII printable characters.
    pub fn new(text: &str) -> Result<Self, String> {
        AsciiPacket::check_printable(text.as_bytes())?;
        let mut this = Self::default();
        for (b_in, b_out) in text.as_bytes().iter().zip(this.0.iter_mut()) {
            *b_out = *b_in;
        }
        Ok(this)
    }

    fn as_padded_str(&self) -> &str {
        std::str::from_utf8(&self.0[..]).unwrap()
    }

    pub fn as_str(&self) -> &str {
        self.as_padded_str().trim_end_matches(' ')
    }

    pub fn is_empty(&self) -> bool {
        self.0[0] == b' '
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary<'_> for TextDescription {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut buf = [0u8; 16];
        u.fill_buffer(&mut buf)?;
        AsciiPacket::check_printable(&buf).map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(TextDescription(buf))
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (16, Some(16))
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

impl std::fmt::Display for TextDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&**self, f)
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
    fn from_ascii_data(data: &str) -> Result<Self, String> {
        if data.len() < 21 {
            return Err(format!("expected at least 5 bytes, got {}", data.len()));
        }
        let ty = TextDescriptionType::try_from(parse_u8_dec("type", &data[0..2])?)?;
        let num = parse_u8_dec("num", &data[2..5])?;
        let text = TextDescription(
            data[5..21]
                .as_bytes()
                .try_into()
                .expect("text slice->array"),
        );
        Ok(StringDescriptionResponse { ty, num, text })
    }
    fn to_ascii(&self) -> AsciiPacket {
        let msg = format!(
            "SD{:02}{:03}{}00",
            self.ty as u8,
            self.num,
            self.text.as_padded_str()
        );
        AsciiPacket::try_from(msg).expect("StringDescriptionResponse valid")
    }
    fn is_reply_to(&self, request: &Message) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ee_report() {
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
                text: TextDescription::new("Garage Door").unwrap(),
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
}
