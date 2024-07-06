use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{instrument, trace};

use crate::{connection::Connection, messages::auth_ack::AuthAck};

pub enum State {
    Auth,
    AuthAck,
    Header,
    Body,
}

pub enum Message {
    Auth,
    AuthAck(AuthAck),
    Frame(BytesMut),
}

pub struct MessageCodec<'a, R: rand::Rng> {
    connection: Connection<'a, R>,
    random_generator: R,
    state: State,
}

impl<'a, R: rand::Rng> MessageCodec<'a, R> {
    pub fn new(connection: Connection<'a, R>, random_generator: R) -> Self {
        Self {
            connection,
            random_generator,
            state: State::Auth,
        }
    }
}

impl<'a, R: rand::Rng> Encoder<Message> for MessageCodec<'a, R> {
    type Error = eyre::Error;

    fn encode(&mut self, item: Message, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        match item {
            Message::Auth => {
                self.state = State::AuthAck;
                let auth = self.connection.generate_auth_message()?;
                dst.extend_from_slice(&auth);
            }
            Message::AuthAck(_) => {
                todo!();
            }
            Message::Frame(data) => {
                dst.extend_from_slice(&data);
            }
        }
        Ok(())
    }
}

impl<'a, R: rand::Rng> Decoder for MessageCodec<'a, R> {
    type Item = Message;
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
                    return Ok(Some(Message::AuthAck(auth_ack)));
                }
                State::Header => {
                    if buf.len() < 32 {
                        trace!("Buffer can not hold the header: buf len: {}", buf.len());
                    }

                    self.connection.read_header(&mut buf.split_to(32));

                    self.state = State::Body;
                }
                State::Body => {
                    if buf.len() < self.connection.body_size() {
                        trace!(
                            "Expected {} body, but only have {}",
                            self.connection.body_size(),
                            buf.len()
                        );
                        return Ok(None);
                    }

                    let mut data = buf.split_to(self.connection.body_size());
                    let mut ret = BytesMut::new();
                    ret.extend_from_slice(
                        &self
                            .connection
                            .read_body(&mut data, self.connection.body_size())?,
                    );

                    self.state = State::Header;

                    return Ok(Some(Message::Frame(ret)));
                }
            }
        }
    }
}
