// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! tokio-based [`Connection`] for framed packets.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures::{Sink, Stream, StreamExt};
//use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::net::{TcpStream, ToSocketAddrs};
//use tokio::io::unix::AsyncFd;
//use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::pkt::Packet;

// TODO: support direct UART connection also. (AsyncFd on /dev/tty*?)
pub struct Connection(Framed<TcpStream, Codec>);

impl Connection {
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Connection, std::io::Error> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Connection(Framed::new(stream, Codec)))
    }
}

impl Stream for Connection {
    type Item = Result<Packet, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_next_unpin(cx).map_err(|_e| todo!())
    }
}

impl Sink<Packet> for Connection {
    type Error = std::io::Error;
    fn poll_ready(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), <Self as Sink<Packet>>::Error>> {
        todo!()
    }
    fn start_send(
        self: Pin<&mut Self>,
        _: Packet,
    ) -> Result<(), <Self as futures::Sink<Packet>>::Error> {
        todo!()
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), <Self as Sink<Packet>>::Error>> {
        todo!()
    }
    fn poll_close(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), <Self as Sink<Packet>>::Error>> {
        todo!()
    }
}

struct Codec;

impl tokio_util::codec::Decoder for Codec {
    type Item = Packet;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(Packet::decode(src))
    }
}

impl tokio_util::codec::Encoder<Packet> for Codec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.encode(dst);
        Ok(())
    }
}
