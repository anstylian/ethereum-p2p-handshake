use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{instrument, trace};

use crate::{
    connection::Connection,
    messages::{auth_ack::AuthAck, hello::Hello, Disconnect, FrameMessage, Ping, Pong},
};

pub enum State {
    Auth,
    AuthAck,
    Header,
    Body(usize),
}

#[derive(Debug)]
pub enum Message {
    Auth,
    AuthAck(AuthAck),
    Hello,
    Disconnect,
    Ping,
    Pong,
    // Frame(BytesMut),
    // Framed(FrameMessage),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MessageRet {
    Auth,
    AuthAck(AuthAck),
    Hello(Hello),
    Disconnect(Disconnect),
    Ping(Ping),
    Ignore,
    // Frame(BytesMut),
    // Framed(FrameMessage),
}

pub struct MessageCodec<'a, R: rand::Rng> {
    connection: Connection<'a, R>,
    state: State,
}

impl<'a, R: rand::Rng> MessageCodec<'a, R> {
    pub fn new(connection: Connection<'a, R>) -> Self {
        Self {
            connection,
            state: State::Auth,
        }
    }
}

impl<'a, R: rand::Rng> Encoder<Message> for MessageCodec<'a, R> {
    type Error = eyre::Error;

    #[instrument(skip_all)]
    fn encode(&mut self, item: Message, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        trace!("Sending: {item:?}");
        match item {
            Message::Auth => {
                self.state = State::AuthAck;
                let auth = self.connection.generate_auth_message()?;
                dst.extend_from_slice(&auth);
            }
            Message::AuthAck(_) => {
                todo!();
            }
            Message::Hello => {
                let mut hello = self.connection.create_hello();
                println!("Send hello: {hello:02x}");
                let hello = self.connection.write_frame(&mut hello);
                dst.extend_from_slice(&hello);
            }
            Message::Disconnect => {
                let mut disconnect = self.connection.create_disconnect();
                let disconnect = self.connection.write_frame(&mut disconnect);
                dst.extend_from_slice(&disconnect);
            }
            Message::Ping => {
                let mut ping = self.connection.create_ping();
                let ping = self.connection.write_frame(&mut ping);
                dst.extend_from_slice(&ping);
            }
            Message::Pong => {
                let mut pong = self.connection.create_pong();
                let pong = self.connection.write_frame(&mut pong);
                dst.extend_from_slice(&pong);
            }
        }
        Ok(())
    }
}

impl<'a, R: rand::Rng> Decoder for MessageCodec<'a, R> {
    type Item = MessageRet;
    type Error = eyre::Error;

    #[instrument(skip_all)]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                State::Auth => {
                    self.state = State::AuthAck;
                }
                State::AuthAck => {
                    trace!("Receive auth ack. Buf len: {}", buf.len());
                    if buf.len() < 2 {
                        return Ok(None);
                    }

                    let payload = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    let total_size = payload + 2;

                    if buf.len() < total_size {
                        trace!(
                            "missing bytes to complete AuthAck. Received: {}, Remaining: {}",
                            buf.len(),
                            total_size
                        );
                        return Ok(None);
                    }

                    let auth_ack = self
                        .connection
                        .read_auth_ack(&mut buf.split_to(total_size))?;

                    self.state = State::Header;
                    return Ok(Some(MessageRet::AuthAck(auth_ack)));
                }
                State::Header => {
                    if buf.len() < 32 {
                        trace!("Buffer can not hold the header: buf len: {}", buf.len());
                        trace!("Buffer: {:02x?}", buf);
                        return Ok(None);
                    }

                    let len = self.connection.read_header(&mut buf.split_to(32))?;

                    self.state = State::Body(len);
                }
                State::Body(len) => {
                    if buf.len() < len {
                        trace!("Expected {} body, but only have {}", len, buf.len());
                        return Ok(None);
                    }

                    let mut data = buf.split_to(len);
                    println!("Remaining buffer: {buf:02x?}");
                    let mut ret = BytesMut::new();
                    ret.extend_from_slice(&self.connection.read_body(&mut data, len)?);

                    self.state = State::Header;

                    let mut r = ret.clone();
                    let message = self.connection.read_message(&mut r)?;
                    return Ok(Some(message));
                }
            }
        }
    }
}
