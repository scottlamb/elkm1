// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! High-level interface to an Elk M1.
//!
//! ## Flow control
//!
//! The Elk's protocol specification describes a severely limited buffer.
//! Section 2 includes the following:
//!
//! > Buffer size in the M1 is limited so it is best to wait for a response
//! > after each command to avoid buffer overflow and lost data. Be aware that
//! > data is transmitted from the M1 asynchronously so the message received
//! > immediately after a command may be unrelated to the response you are
//! > expecting.
//!
//! Section 4.1.8 includes the following:
//!
//! > The M1’s incoming message buffer can hold up to 250 characters. Control
//! > messages take different times to process messages: Lighting control
//! > messages may take up to 500 ms to process the message and send it to a
//! > M1XSP Serial Port Expander if it is used. The M1XSP can buffer two control
//! > messages. Some of the lighting control systems have status feedback with
//! > failure retries which may take 2 to 3 seconds to transmit to a faulty
//! > light control signal.
//!
//! Currently `Panel` attempts to wait for a response after each command. This
//! seems theoretically imperfect because the Elk's asynchronous messages may be
//! indistinguishable from (untagged) command replies. If this becomes a problem
//! in practice, a future version may also impose a delay on any message whose
//! reply can be sent unsolicited.
//!
//! ## State tracking ##
//!
//! On connection start, `Panel` will send commands to learn the state of the
//! Elk:
//!
//! *   `as` (arming status request)
//! *   `zs` (zone status request)
//! *   `sd` (ASCII string text description request) for each configured zone,
//!     area, and task.
//! *   `ka` (request keypad area assignments)
//!
//! It will update these according to received messages. If the Elk is
//! configured to send asynchronous updates (see global settings 36–40),
//! `Panel`'s state should track the Elk's.

use std::pin::Pin;
use std::task::Poll;

use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::net::ToSocketAddrs;

use crate::msg::{
    ArmingStatusRequest, Message, StringDescriptionRequest, ZoneChange, ZoneLogicalStatus,
    ZonePhysicalStatus, ZoneStatus, ZoneStatusRequest, NUM_AREAS, NUM_ZONES,
};
use crate::pkt::Packet;
use crate::tokio::Connection;

pub struct Panel {
    conn: Connection,
    zone_status: Option<[ZoneStatus; NUM_ZONES]>,
}

impl Panel {
    /// Connects to the panel.
    ///
    /// Currently this completes all initialization steps before returning.
    /// In a future version, it may instead with a stream that will later yield
    /// a `Change::Initialized` event or some such.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, std::io::Error> {
        let conn = Connection::connect(addr).await?;
        Self::with_connection(conn).await
    }

    async fn with_connection(conn: Connection) -> Result<Self, std::io::Error> {
        let mut this = Panel {
            conn,
            zone_status: None,
        };
        this.init_req(ArmingStatusRequest {}.into()).await?;
        this.init_req(ZoneStatusRequest {}.into()).await?;
        for area in 1..=NUM_AREAS {
            println!("sending sd for {}", area);
            this.init_req(
                StringDescriptionRequest {
                    ty: crate::msg::TextDescriptionType::Area,
                    num: area as u8,
                }
                .into(),
            )
            .await?;
        }
        // TODO: zone names.
        // TODO: task names.
        /*for i in 0..NUM_ZONES {
            if this.zone_status.as_deref().unwrap()[i].physical() != ZonePhysicalStatus::Unconfigured {
                this.init_req()
            }
        }*/
        Ok(this)
    }

    /// Sends a message as part of initialization and waits for the reply.
    ///
    /// Processes but doesn't report any other messages received while waiting.
    async fn init_req(&mut self, send: Message) -> Result<(), std::io::Error> {
        println!("sending: {:?}", &send);
        self.conn.send(send.to_pkt()).await?;
        while let Some(received) = self.conn.next().await {
            let received = self.interpret(received?);
            println!("received: {:#?}", &received);
            if let Some(Ok(r)) = &received.msg {
                if r.is_reply_to(&send) {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Interprets a received packet, creating an `Event` and updating state.
    fn interpret(&mut self, pkt: Packet) -> Event {
        let msg = Message::parse(&pkt).transpose();
        let mut change = None;
        if let Some(Ok(m)) = &msg {
            match m {
                //Message::ArmingStatusRequest(_) => todo!(),
                //Message::ArmingStatusReport(_) => todo!(),
                //Message::SendTimeData(_) => todo!(),
                Message::ZoneChange(m) => {
                    if let Some(ref mut s) = self.zone_status {
                        let s = &mut s[m.zone.to_index()];
                        if *s != m.status {
                            change = Some(Change::ZoneChange(m.clone()));
                        }
                        *s = m.status;
                    }
                }
                //Message::ZoneStatusRequest(_) => todo!(),
                Message::ZoneStatusReport(m) => {
                    self.zone_status = Some(m.zones);
                }
                _ => {}
            }
        }
        Event { pkt, msg, change }
    }

    pub fn zone_status(&self) -> Option<&[ZoneStatus; NUM_ZONES]> {
        self.zone_status.as_ref()
    }
}

impl Stream for Panel {
    type Item = Result<Event, std::io::Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = Pin::into_inner(self);
        // First process received messages.
        match this.conn.poll_next_unpin(cx) {
            Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(Ok(pkt))) => {
                let event = this.interpret(pkt);
                return Poll::Ready(Some(Ok(event)));
            }
            Poll::Pending => {}
        }

        // TODO: send anything that needs to be sent...

        Poll::Pending
    }
}

#[allow(unused_variables)]
impl Sink<Command> for Panel {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        todo!()
    }

    fn start_send(self: Pin<&mut Self>, item: Command) -> Result<(), Self::Error> {
        todo!()
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        todo!()
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub pkt: crate::pkt::Packet,
    pub msg: Option<Result<crate::msg::Message, crate::msg::Error>>,
    pub change: Option<Change>,
}

#[derive(Clone, Debug)]
pub enum Change {
    /// Received a `ZC` which does not match the zone's known prior state.
    ZoneChange(ZoneChange),
}

#[derive(Clone, Debug)]
pub enum Command {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        msg::{
            AlarmState, ArmUpState, ArmingStatus, ArmingStatusReport, StringDescriptionResponse,
            TextDescription, TextDescriptionType, ZoneStatusReport, NUM_AREAS,
        },
        pkt::AsciiPacket,
        tokio::testutil::socketpair,
    };

    async fn send<P: Into<Packet>>(conn: &mut Connection, pkt: P) {
        conn.send(pkt.into()).await.unwrap();
    }

    async fn send_ascii(conn: &mut Connection, msg: &str) {
        conn.send(AsciiPacket::try_from(msg).unwrap().into())
            .await
            .unwrap();
    }

    async fn next_msg(conn: &mut Connection) -> Message {
        let pkt = match conn.next().await {
            Some(Ok(Packet::Ascii(p))) => p,
            _ => unreachable!(),
        };
        Message::parse_ascii(&pkt).unwrap().unwrap()
    }

    #[tokio::test]
    async fn init() {
        let (client, mut server) = socketpair().await;

        let arming_status = [ArmingStatus::Disarmed; NUM_AREAS];
        let up_state = [ArmUpState::NotReadyToArm; NUM_AREAS];
        let alarm_state = [AlarmState::NoAlarmActive; NUM_AREAS];
        let mut zones = [ZoneStatus::default(); NUM_ZONES];
        zones[0] = ZoneStatus::new(
            crate::msg::ZoneLogicalStatus::Normal,
            crate::msg::ZonePhysicalStatus::EOL,
        );

        let (client, _) = tokio::join!(
            async { Panel::with_connection(client).await.unwrap() },
            async {
                send_ascii(&mut server, "XK384014409022200000").await;
                let pkt = next_msg(&mut server).await;
                assert_eq!(pkt, ArmingStatusRequest {}.into());
                send(
                    &mut server,
                    &ArmingStatusReport {
                        arming_status,
                        up_state,
                        alarm_state,
                    },
                )
                .await;
                let pkt = next_msg(&mut server).await;
                assert_eq!(pkt, ZoneStatusRequest {}.into());
                send(&mut server, &ZoneStatusReport { zones }).await;
                for area in 1..=NUM_AREAS as u8 {
                    let pkt = next_msg(&mut server).await;
                    assert_eq!(
                        pkt,
                        StringDescriptionRequest {
                            ty: TextDescriptionType::Area,
                            num: area,
                        }
                        .into()
                    );
                    send(
                        &mut server,
                        &StringDescriptionResponse {
                            ty: crate::msg::TextDescriptionType::Area,
                            num: area,
                            text: TextDescription::new("home").unwrap(),
                        },
                    )
                    .await;
                }
            }
        );

        assert_eq!(&client.zone_status().unwrap()[..], &zones[..]);
    }
}
