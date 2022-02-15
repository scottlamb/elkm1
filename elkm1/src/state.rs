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
use std::time::Duration;

use futures::{Future, Sink, SinkExt, Stream, StreamExt};
use tokio::net::ToSocketAddrs;
use tokio::time::Sleep;

use crate::msg::{
    ArmingStatusReport, ArmingStatusRequest, Message, StringDescriptionRequest, TextDescription,
    TextDescriptionType, TextDescriptions, Zone, ZoneStatus, ZoneStatusReport, ZoneStatusRequest,
    NUM_AREAS, NUM_ZONES,
};
use crate::pkt::Packet;
use crate::tokio::Connection;

/// Delay in applying an `ArmingReport` transition suspected of being spurious.
///
/// The Elk appears to follow these spurious reports with correct ones almost
/// immediately. The generous delay here is in case something else in the
/// system goes out to lunch at a bad time: the Elk M1XEP, the network,
/// the local process (not polling the `Panel` promptly), etc.
const SUSPICIOUS_TRANSITION_DELAY: Duration = Duration::from_secs(5);

pub struct Panel {
    conn: Connection,
    state: PanelState,
    pending_arm: Option<(Pin<Box<Sleep>>, ArmingStatusReport)>,
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
        &self.state.zone_names.0[zone.to_index()]
    }

    pub fn area_names(&self) -> &TextDescriptions<NUM_AREAS> {
        &self.state.area_names
    }

    pub fn arming_status(&self) -> &ArmingStatusReport {
        self.state
            .arming_status
            .as_ref()
            .expect("arming_status is set post-init")
    }

    pub fn zone_statuses(&self) -> &ZoneStatusReport {
        self.state
            .zone_statuses
            .as_ref()
            .expect("zone_status is set post-init")
    }

    async fn with_connection(conn: Connection) -> Result<Self, std::io::Error> {
        let mut this = Panel {
            conn,
            state: PanelState::default(),
            pending_arm: None,
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
                return Ok(());
            };
            assert!(reply_i >= unfilled_i); // checked by SDR::is_reply_to also.
            names[reply_i] = reply.text;
            unfilled_i = reply_i + 1;
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
                    change = self.interpret_arming_status(m);
                }
                //Message::SendTimeData(_) => todo!(),
                Message::ZoneChange(m) => {
                    if let Some(ref mut s) = self.state.zone_statuses {
                        let s = &mut s.zones[m.zone.to_index()];
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
                    self.state.zone_statuses = Some(*m);
                }
                _ => {}
            }
        }
        Event {
            pkt: Some(pkt),
            msg,
            change,
        }
    }

    fn interpret_arming_status(&mut self, msg: &ArmingStatusReport) -> Option<Change> {
        let prior = match self.state.arming_status {
            None => {
                self.state.arming_status = Some(*msg);
                return None;
            }
            Some(ref s) => s,
        };

        // When arming with a timer, the Elk appears to sends a spurious "fully
        // armed" message then corrects it, as described in this thread:
        // <https://www.elkproducts.com/forums/topic/spurious-armed-fully-message/>.
        // Hold on to that message, and only apply it if there isn't another
        // transition within a reasonable time.
        if let Some((_, pending)) = self.pending_arm.take() {
            if ArmingStatusReport::is_transition_suspicious(prior, msg) {
                log::warn!(
                    "next arming report after suspicious transition is also suspicious; \
                     applying anyway\nprior: {:#?}\npending: {:#?}\nnew: {:#?}",
                    prior,
                    &pending,
                    &msg,
                );
            }
        } else if ArmingStatusReport::is_transition_suspicious(prior, msg) {
            log::debug!(
                "Delaying arming status transition suspected to be spurious.\n\
                 prior: {:#?}\npending: {:#?}",
                prior,
                msg,
            );
            self.pending_arm = Some((
                Box::pin(tokio::time::sleep(SUSPICIOUS_TRANSITION_DELAY)),
                *msg,
            ));
            return None;
        }
        if prior != msg {
            let prior = *prior;
            self.state.arming_status = Some(*msg);
            return Some(Change::ArmingStatus { prior });
        }
        None
    }
}

impl Stream for Panel {
    type Item = Result<Event, std::io::Error>;

    fn poll_next(
        self: Pin<&mut Self>,
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

        if let Some((s, a)) = this.pending_arm.as_mut() {
            if s.as_mut().poll(cx).is_ready() {
                let prior = this
                    .state
                    .arming_status
                    .expect("have prior arming_status when transition pending");
                let event = Event {
                    pkt: None,
                    msg: None,
                    change: Some(Change::ArmingStatus { prior }),
                };
                log::warn!(
                    "Deferred arming status taking effect.\n\
                     prior: {:?}\npending: {:?}\n",
                    prior,
                    a,
                );
                this.state.arming_status = Some(*a);
                this.pending_arm.take();
                return Poll::Ready(Some(Ok(event)));
            }
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
    zone_statuses: Option<ZoneStatusReport>,
    zone_names: TextDescriptions<NUM_ZONES>,
    area_names: TextDescriptions<NUM_AREAS>,
}

impl PanelState {
    /// Returns a const reference to the given names, if valid/understood.
    #[cfg(test)]
    fn names(&self, ty: TextDescriptionType) -> Option<&[TextDescription]> {
        Some(match ty {
            TextDescriptionType::Area => &self.area_names.0[..],
            TextDescriptionType::Zone => &self.zone_names.0[..],
            _ => return None,
        })
    }

    /// Returns a mutable reference to the given names, if valid/understood.
    fn names_mut(&mut self, ty: TextDescriptionType) -> Option<&mut [TextDescription]> {
        Some(match ty {
            TextDescriptionType::Area => &mut self.area_names.0[..],
            TextDescriptionType::Zone => &mut self.zone_names.0[..],
            _ => return None,
        })
    }
}

// Implemented explicitly because there's no Default on arrays > size 32.
impl Default for PanelState {
    fn default() -> Self {
        Self {
            arming_status: None,
            zone_statuses: None,
            zone_names: TextDescriptions::ALL_EMPTY,
            area_names: TextDescriptions::ALL_EMPTY,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub pkt: Option<crate::pkt::Packet>,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Change {
    /// Received a `ZC` which does not match the zone's known prior state.
    ZoneChange { zone: Zone, prior: ZoneStatus },

    /// Received a `AS` which does not match the prior arming state.
    ArmingStatus { prior: ArmingStatusReport },
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
                    send(conn, state.zone_statuses.as_ref().unwrap()).await;
                }
                Message::StringDescriptionRequest(StringDescriptionRequest { ty, num }) => {
                    let names = state.names(ty).unwrap();
                    let mut i = num as usize - 1;
                    while i < names.len() && names[i].is_empty() {
                        i += 1;
                    }
                    let (num, text) = if i == names.len() {
                        (0, TextDescription::default())
                    } else {
                        (i as u8 + 1, names[i])
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
                first_exit_time: 0,
            }),
            zone_statuses: Some(ZoneStatusReport::ALL_UNCONFIGURED),
            zone_names: TextDescriptions::ALL_EMPTY,
            area_names: TextDescriptions::ALL_EMPTY,
        };
        state.zone_names.0[1] = TextDescription::new("front door").unwrap();
        state.zone_statuses.as_mut().unwrap().zones[0] = ZoneStatus::new(
            crate::msg::ZoneLogicalStatus::Normal,
            crate::msg::ZonePhysicalStatus::EOL,
        );
        let (_, client_state) = tokio::join!(serve_init(&mut server, &state), async {
            Panel::with_connection(client).await.unwrap().state
        },);
        assert_eq!(client_state, state);
    }

    struct Activity {
        msg: &'static str,
        checker: fn(&Event, &Panel),
    }

    async fn follow_activities(
        activities: &[Activity],
        panel: &mut Panel,
        server: &mut Connection,
    ) {
        for a in activities {
            tokio::join!(send_ascii(server, a.msg), async {
                let event = panel.next().await.unwrap().unwrap();
                match &event.pkt {
                    Some(Packet::Ascii(p)) => assert_eq!(&p[..], a.msg),
                    _ => unreachable!(),
                }
                (a.checker)(&event, &panel);
            });
        }
    }

    #[tokio::test]
    async fn follow_arm_with_delay() {
        let (client, mut server) = socketpair().await;
        const INITIAL: PanelState = PanelState {
            arming_status: Some(ArmingStatusReport {
                arming_status: [ArmingStatus::Disarmed; NUM_AREAS],
                up_state: [ArmUpState::ReadyToArm; NUM_AREAS],
                alarm_state: [AlarmState::NoAlarmActive; NUM_AREAS],
                first_exit_time: 0,
            }),
            zone_statuses: Some(ZoneStatusReport::ALL_UNCONFIGURED),
            zone_names: TextDescriptions::ALL_EMPTY,
            area_names: TextDescriptions::ALL_EMPTY,
        };

        let mut panel = Panel {
            conn: client,
            state: INITIAL,
            pending_arm: None,
        };
        // t= 0: IC0000000000000010200           2022-02-14T21:54:23Z
        // t= 0: LD117300111354021400022200
        // t= 0: AS00000000111111110000000000
        // t= 0: AM00000000
        // t= 0: AS20000000411111110000000000
        // t= 0: AM00000000
        // t= 0: ZC... (many no-ops)
        // t= 1: EE10060180200
        // t= 1: AS2000000031111111000000003B
        // t= 1: AM00000000
        // t= 8: XK305413214022200000
        // t=38: XK305413214022200000
        // t=59: AS20000000411111110000000000
        // t=59: AM00000000
        // t=59: ZC... (many no-ops)
        // t=99: XK005613214022200000            2022-02-14T21:56:02Z
        let activities = [
            Activity {
                msg: "IC0000000000000010200",
                checker: |event, _panel| {
                    assert_eq!(event.change, None);
                },
            },
            Activity {
                msg: "LD117300111354021400022200",
                checker: |event, _panel| {
                    assert_eq!(event.change, None);
                },
            },
            Activity {
                msg: "AS00000000111111110000000000",
                checker: |event, panel| {
                    assert_eq!(event.change, None);
                    assert!(panel.pending_arm.is_none());
                },
            },
            Activity {
                msg: "AM00000000",
                checker: |event, _panel| {
                    assert_eq!(event.change, None);
                },
            },
            Activity {
                msg: "AS20000000411111110000000000",
                checker: |event, panel| {
                    assert_eq!(panel.state, INITIAL);
                    assert!(panel.pending_arm.is_some());
                    assert_eq!(event.change, None);
                },
            },
            Activity {
                msg: "AM00000000",
                checker: |event, _panel| {
                    assert_eq!(event.change, None);
                },
            },
            // t= 0: AS20000000411111110000000000
            Activity {
                msg: "AS20000000411111110000000000",
                checker: |event, panel| {
                    assert!(matches!(event.change, Some(Change::ArmingStatus { .. })));
                    assert!(panel.pending_arm.is_none());
                    assert_eq!(
                        panel.state.arming_status.unwrap().arming_status[0],
                        ArmingStatus::ArmedStay
                    );
                },
            },
        ];
        follow_activities(&activities, &mut panel, &mut server).await;
    }
}
