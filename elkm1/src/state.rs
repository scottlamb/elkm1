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
    ArmingStatusReport, ArmingStatusRequest, Message, StringDescriptionRequest, TextDescription,
    TextDescriptionType, Zone, ZoneStatus, ZoneStatusRequest, NUM_AREAS, NUM_ZONES,
};
use crate::pkt::Packet;
use crate::tokio::Connection;

pub struct Panel {
    conn: Connection,
    state: PanelState,
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

    pub fn zone_name(&self, zone: Zone) -> &TextDescription {
        self.state.zone_names[zone.to_index()]
            .as_ref()
            .expect("zone_name is set post-init")
    }

    pub fn zone_status(&self) -> &[ZoneStatus; NUM_ZONES] {
        self.state
            .zone_status
            .as_ref()
            .expect("zone_status is set post-init")
    }

    async fn with_connection(conn: Connection) -> Result<Self, std::io::Error> {
        let mut this = Panel {
            conn,
            state: PanelState::default(),
        };
        this.init_req(ArmingStatusRequest {}.into()).await?;
        this.init_req(ZoneStatusRequest {}.into()).await?;
        this.send_sds(TextDescriptionType::Area, NUM_AREAS).await?;
        this.send_sds(TextDescriptionType::Zone, NUM_ZONES).await?;
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
    async fn init_req(&mut self, send: Message) -> Result<Event, std::io::Error> {
        log::debug!("init_req: sending {:#?}", &send);
        self.conn.send(send.to_pkt()).await?;
        while let Some(received) = self.conn.next().await {
            let received = self.interpret(received?);
            log::debug!("init_req: received {:#?}", &received);
            if let Some(Ok(r)) = &received.msg {
                if r.is_reply_to(&send) {
                    return Ok(received);
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("EOF while expecting reply to {:?}", &send),
        ))
    }

    /// Sends a range of `sd` requests, waiting for each response.
    async fn send_sds(
        &mut self,
        ty: TextDescriptionType,
        max: usize,
    ) -> Result<(), std::io::Error> {
        let mut unfilled_i = 0;
        while unfilled_i < max {
            let num = unfilled_i as u8 + 1;
            let reply = self
                .init_req(StringDescriptionRequest { ty, num }.into())
                .await?;
            let reply = match reply.msg {
                Some(Ok(Message::StringDescriptionResponse(r))) => r,
                _ => unreachable!("only SD should be accepted as reply to sd"),
            };
            debug_assert_eq!(ty, reply.ty); // checked by SDR::is_reply_to.
            let names = self.state.names_mut(ty).expect("have names for ty");
            let reply_i = if let Some(i) = reply.num.checked_sub(1) {
                i as usize
            } else {
                // no remaining non-empty names.
                for j in unfilled_i..max {
                    names[j] = Some(TextDescription::default());
                }
                return Ok(());
            };
            debug_assert!(reply_i >= unfilled_i); // checked by SDR::is_reply_to also.
            while unfilled_i < reply_i {
                // skipped empty names.
                names[unfilled_i] = Some(TextDescription::default());
                unfilled_i += 1;
            }
            names[unfilled_i] = Some(reply.text);
            unfilled_i += 1;
        }
        Ok(())
    }

    /// Interprets a received packet, creating an `Event` and updating state.
    fn interpret(&mut self, pkt: Packet) -> Event {
        let msg = Message::parse(&pkt).transpose();
        let mut change = None;
        if let Some(Ok(m)) = &msg {
            match m {
                Message::ArmingStatusReport(m) => {
                    if let Some(ref prior) = self.state.arming_status {
                        if prior != m {
                            change = Some(Change::ArmingStatus(*prior));
                        }
                    }
                    self.state.arming_status = Some(*m);
                }
                //Message::SendTimeData(_) => todo!(),
                Message::ZoneChange(m) => {
                    if let Some(ref mut s) = self.state.zone_status {
                        let s = &mut s[m.zone.to_index()];
                        if *s != m.status {
                            change = Some(Change::ZoneChange {
                                zone: m.zone,
                                prior: *s,
                            });
                        }
                        *s = m.status;
                    }
                }
                Message::ZoneStatusReport(m) => {
                    self.state.zone_status = Some(m.zones);
                }
                _ => {}
            }
        }
        Event { pkt, msg, change }
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

#[derive(Debug, Eq, PartialEq)]
struct PanelState {
    arming_status: Option<ArmingStatusReport>,
    zone_status: Option<[ZoneStatus; NUM_ZONES]>,
    zone_names: [Option<TextDescription>; NUM_ZONES],
    area_names: [Option<TextDescription>; NUM_AREAS],
}

impl PanelState {
    /// Returns a const reference to the given names, if valid/understood.
    #[cfg(test)]
    fn names(&self, ty: TextDescriptionType) -> Option<&[Option<TextDescription>]> {
        Some(match ty {
            TextDescriptionType::Area => &self.area_names[..],
            TextDescriptionType::Zone => &self.zone_names[..],
            _ => return None,
        })
    }

    /// Returns a mutable reference to the given names, if valid/understood.
    fn names_mut(&mut self, ty: TextDescriptionType) -> Option<&mut [Option<TextDescription>]> {
        Some(match ty {
            TextDescriptionType::Area => &mut self.area_names[..],
            TextDescriptionType::Zone => &mut self.zone_names[..],
            _ => return None,
        })
    }
}

// Implemented explicitly because there's no Default on arrays > size 32.
impl Default for PanelState {
    fn default() -> Self {
        Self {
            arming_status: None,
            zone_status: None,
            zone_names: [None; NUM_ZONES],
            area_names: [None; NUM_AREAS],
        }
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub pkt: crate::pkt::Packet,
    pub msg: Option<Result<crate::msg::Message, crate::msg::Error>>,
    pub change: Option<Change>,
}

/// An understood state change.
///
/// The enum value includes the *prior* state of the panel.
///
/// The caller can retrieve the current state via [`Panel`] accessors. Note that
/// if the caller wishes to learn exactly what changed in this message, it
/// should compare them *before* calling `<Panel as futures::Stream>::poll_next`
/// again, so that no other messages are included in the diff.
#[derive(Clone, Debug)]
pub enum Change {
    /// Received a `ZC` which does not match the zone's known prior state.
    ZoneChange { zone: Zone, prior: ZoneStatus },

    /// Received a `AS` which does not match the prior arming state.
    ArmingStatus(ArmingStatusReport),
}

#[derive(Clone, Debug)]
pub enum Command {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        msg::{
            AlarmState, ArmUpState, ArmingStatus, ArmingStatusReport, StringDescriptionResponse,
            TextDescription, ZoneStatusReport, NUM_AREAS,
        },
        pkt::AsciiPacket,
        tokio::testutil::socketpair,
    };

    use pretty_assertions::assert_eq;

    async fn send<P: Into<Packet>>(conn: &mut Connection, pkt: P) {
        conn.send(pkt.into()).await.unwrap();
    }

    async fn send_ascii(conn: &mut Connection, msg: &str) {
        conn.send(AsciiPacket::try_from(msg).unwrap().into())
            .await
            .unwrap();
    }

    async fn next_msg(conn: &mut Connection) -> Option<Message> {
        let pkt = match conn.next().await {
            Some(Ok(Packet::Ascii(p))) => p,
            None => return None,
            _ => unreachable!(),
        };
        Some(Message::parse_ascii(&pkt).unwrap().unwrap())
    }

    /// Responds to init packets with fixed state.
    async fn serve_init(conn: &mut Connection, state: &PanelState) {
        while let Some(pkt) = next_msg(conn).await {
            // Simulate asynchronous messages.
            send_ascii(conn, "XK384014409022200000").await;
            match pkt {
                Message::ArmingStatusRequest(_) => {
                    send(conn, state.arming_status.as_ref().unwrap()).await;
                }
                Message::ZoneStatusRequest(_) => {
                    send(
                        conn,
                        &ZoneStatusReport {
                            zones: state.zone_status.unwrap(),
                        },
                    )
                    .await;
                }
                Message::StringDescriptionRequest(StringDescriptionRequest { ty, num }) => {
                    let names = state.names(ty).unwrap();
                    let mut i = num as usize - 1;
                    while i < names.len() && names[i].unwrap().is_empty() {
                        i += 1;
                    }
                    let (num, text) = if i == names.len() {
                        (0, TextDescription::default())
                    } else {
                        (i as u8 + 1, names[i].unwrap())
                    };
                    send(conn, &StringDescriptionResponse { ty, num, text }).await;
                }
                _ => unreachable!(),
            }
        }
    }

    #[tokio::test]
    async fn init() {
        let (client, mut server) = socketpair().await;

        let mut state = PanelState {
            arming_status: Some(ArmingStatusReport {
                arming_status: [ArmingStatus::Disarmed; NUM_AREAS],
                up_state: [ArmUpState::NotReadyToArm; NUM_AREAS],
                alarm_state: [AlarmState::NoAlarmActive; NUM_AREAS],
            }),
            zone_status: Some([ZoneStatus::default(); NUM_ZONES]),
            zone_names: [Some(TextDescription::default()); NUM_ZONES],
            area_names: [Some(TextDescription::default()); NUM_AREAS],
        };
        state.zone_names[1] = Some(TextDescription::new("front door").unwrap());
        state.zone_status.as_mut().unwrap()[0] = ZoneStatus::new(
            crate::msg::ZoneLogicalStatus::Normal,
            crate::msg::ZonePhysicalStatus::EOL,
        );
        let (_, client_state) = tokio::join!(serve_init(&mut server, &state), async {
            Panel::with_connection(client).await.unwrap().state
        },);
        assert_eq!(client_state, state);
    }
}
