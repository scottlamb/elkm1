// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Message layer: converts pkt frames into higher-level messages.

use std::str::FromStr;

use crate::pkt::{AsciiPacket, Packet};

#[derive(Debug)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    SendTimeData(SendTimeData),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TimeDataType {
    Exit = 0,
    Entry = 1,
}
impl TimeDataType {
    fn from_ascii(s: &str) -> Result<TimeDataType, String> {
        Ok(match s {
            "0" => TimeDataType::Exit,
            "1" => TimeDataType::Entry,
            _ => return Err(format!("unknown timed data type {:?}", s)),
        })
    }
    fn to_ascii(self) -> &'static str {
        match self {
            TimeDataType::Exit => "0",
            TimeDataType::Entry => "1",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ArmedState {
    Disarmed = 0,
    ArmedAway = 1,
    ArmedStay = 2,
    ArmedStayInstant = 3,
    ArmedNight = 4,
    ArmedNightInstant = 5,
    ArmedVacation = 6,
}
impl ArmedState {
    fn from_ascii(s: &str) -> Result<ArmedState, String> {
        Ok(match s {
            "0" => ArmedState::Disarmed,
            "1" => ArmedState::ArmedAway,
            "2" => ArmedState::ArmedStay,
            "3" => ArmedState::ArmedStayInstant,
            "4" => ArmedState::ArmedNight,
            "5" => ArmedState::ArmedNightInstant,
            "6" => ArmedState::ArmedVacation,
            _ => return Err(format!("unknown armed state {:?}", s)),
        })
    }
    fn to_ascii(self) -> &'static str {
        match self {
            ArmedState::Disarmed => "0",
            ArmedState::ArmedAway => "1",
            ArmedState::ArmedStay => "2",
            ArmedState::ArmedStayInstant => "3",
            ArmedState::ArmedNight => "4",
            ArmedState::ArmedNightInstant => "5",
            ArmedState::ArmedVacation => "6",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendTimeData {
    area: u8,
    data: TimeDataType,
    timer1: u8,
    timer2: u8,
    armed_state: Option<ArmedState>,
}
impl SendTimeData {
    fn from_ascii_data(args: &str) -> Result<SendTimeData, String> {
        if args.len() < 8 {
            return Err(format!("expected at least 8 bytes, got {}", args.len()));
        }
        let area = match args.as_bytes()[0] {
            b @ b'1'..=b'8' => b - b'0',
            b => return Err(format!("expected area in [1, 8], got {:?}", b)),
        };
        let data = TimeDataType::from_ascii(&args[1..2])?;
        let timer1 = parse_u8_dec("timer1", &args[2..5])?;
        let timer2 = parse_u8_dec("timer2", &args[5..8])?;
        let armed_state = args.get(8..9).map(ArmedState::from_ascii).transpose()?;
        Ok(SendTimeData {
            area,
            data,
            timer1,
            timer2,
            armed_state,
        })
    }

    fn to_ascii(&self) -> AsciiPacket {
        let mut msg = format!(
            "EE{}{}{:03}{:03}",
            &self.area,
            &self.data.to_ascii(),
            self.timer1,
            self.timer2
        );
        if let Some(s) = &self.armed_state {
            msg.push_str(s.to_ascii());
        }
        msg.push_str("00"); // reserved
        AsciiPacket::try_from(msg).expect("SendTimeData invalid")
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

    fn parse_ascii(pkt: &AsciiPacket) -> Result<Option<Self>, Error> {
        let (cmd, args) = pkt.split_at(2);
        match cmd {
            "EE" => SendTimeData::from_ascii_data(args).map(Self::SendTimeData),
            _ => return Ok(None),
        }
        .map(Some)
        .map_err(Error)
    }

    pub fn to_pkt(&self) -> Packet {
        match self {
            Message::SendTimeData(m) => Packet::Ascii(m.to_ascii()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ee() {
        let pkt = Packet::Ascii(AsciiPacket::try_from("EE11030000100").unwrap());
        let msg = Message::parse(&pkt).unwrap().unwrap();
        assert_eq!(
            msg,
            Message::SendTimeData(SendTimeData {
                area: 1,
                data: TimeDataType::Entry,
                timer1: 30,
                timer2: 0,
                armed_state: Some(ArmedState::ArmedAway),
            })
        );
        assert_eq!(msg.to_pkt(), pkt);
    }
}
