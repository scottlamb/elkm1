// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! tokio-based [`Connection`] for framed packets.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_util::codec::Framed;

use crate::pkt::Packet;

/// A connection to an Elk control panel.
///
/// This handles framing but nothing more. It doesn't interpet state or
/// rate-limit sending to avoid overflowing the Elk's buffer. See
/// [`crate::state::Panel`] for that.
// TODO: support direct UART connection also. (AsyncFd on /dev/tty*?)
pub struct Connection(Framed<TcpStream, Codec>);

impl Connection {
    /// Opens an unencrypted connection to an Elk M1XEP (which typically uses port 2101).
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Connection, std::io::Error> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Connection(Framed::new(stream, Codec)))
    }
}

impl Stream for Connection {
    type Item = Result<Packet, std::io::Error>;

    #[inline]
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_next_unpin(cx)
    }
}

impl Sink<Packet> for Connection {
    type Error = std::io::Error;

    #[inline]
    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), <Self as Sink<Packet>>::Error>> {
        self.0.poll_ready_unpin(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: Packet,
    ) -> Result<(), <Self as futures::Sink<Packet>>::Error> {
        tracing::debug!(pkt = ?item, "sending packet");
        self.0.start_send_unpin(item)
    }

    #[inline]
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), <Self as Sink<Packet>>::Error>> {
        self.0.poll_flush_unpin(cx)
    }

    #[inline]
    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), <Self as Sink<Packet>>::Error>> {
        self.0.poll_flush_unpin(cx)
    }
}

struct Codec;

impl tokio_util::codec::Decoder for Codec {
    type Item = Packet;
    type Error = std::io::Error;

    #[inline]
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(Packet::decode(src))
    }
}

impl tokio_util::codec::Encoder<Packet> for Codec {
    type Error = std::io::Error;

    #[inline]
    fn encode(&mut self, item: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.encode(dst);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// Cross-platform, tokio equivalent of `socketpair(2)`.
    pub(crate) async fn socketpair() -> (Connection, Connection) {
        // Another process on the machine could connect to the server and mess
        // this up, but that's unlikely enough to ignore in test code.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server = listener.accept().await.unwrap().0;
        let client = Connection(Framed::new(client, Codec));
        let server = Connection(Framed::new(server, Codec));
        (client, server)
    }
}
