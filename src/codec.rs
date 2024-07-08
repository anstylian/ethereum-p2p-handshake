use alloy_rlp::Encodable;
use bytes::BytesMut;
use eyre::Result;
use snap::raw::Encoder as SnapEncoder;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{instrument, trace};

use crate::{
    messages::{
        auth_ack::AuthAck,
        disconnect::{Disconnect, DisconnectReason},
        ethstatus::EthStatus,
        hello::Hello,
        Ping,
    },
    rlpx::Rlpx,
    utils::pk2id,
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
    Hello,
    Disconnect(DisconnectReason), // disconnect with reason
    SubProtocolStatus,
    #[allow(dead_code)]
    Ping,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MessageRet {
    #[allow(dead_code)]
    /// Auth is send from the initiator to the recipient
    /// since we are implementing only the initators part, we are
    /// never receiving this message
    Auth,
    AuthAck(AuthAck),
    Hello(Hello),
    Disconnect(Disconnect),
    Ping,
    Pong,
    Ignore,
}

enum Id {
    #[allow(dead_code)]
    P2pCapability(u8),
    Other(u8),
}

impl Id {
    fn id(self) -> u8 {
        match self {
            Id::P2pCapability(id) => id,
            Id::Other(id) => id + 0x10,
        }
    }
}

/// In the codec due to the RLPx Transport Protocol we need to keep state.
/// The state is needed in two cases:
/// 1. We initiate the handshake
///     When we initiate the handshake we need to exchange secrets with the other party
///     to our establish the session keys.
/// 2. After we establish the session keys we need to decode frames.
///     Frames are split into header and body. When we decode the header  
///     (to know the length of the body we expect), we make changes in our keccak256 MAC state
///     that we need to preserve.
pub struct MessageCodec<'a> {
    rlpx: Rlpx<'a>,
    state: State,
    snap_encoder: SnapEncoder,
}

impl<'a> MessageCodec<'a> {
    pub fn new(rlpx: Rlpx<'a>) -> Self {
        Self {
            rlpx,
            state: State::Auth,
            snap_encoder: SnapEncoder::new(),
        }
    }

    fn snappy_compress(&mut self, message_id: Id, input: BytesMut) -> Result<BytesMut> {
        let mut compressed = BytesMut::zeroed(1 + snap::raw::max_compress_len(input.len() - 1));

        let compressed_size = self
            .snap_encoder
            .compress(&input[1..], &mut compressed[1..])?;
        compressed.truncate(compressed_size + 1);

        compressed[0] = message_id.id();

        Ok(compressed)
    }
}

// TODO: make the Codec states more strict. Now its ok because we are using a specific flow

impl<'a> Encoder<Message> for MessageCodec<'a> {
    type Error = eyre::Error;

    #[instrument(name = "encode", skip_all)]
    fn encode(&mut self, item: Message, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        trace!("Sending: {item:?}");
        match item {
            Message::Auth => {
                self.state = State::AuthAck;
                let auth = self.rlpx.generate_auth_message()?;
                dst.extend_from_slice(&auth);
            }
            Message::Hello => {
                let mut hello =
                    Hello::new_default_values(*pk2id(self.rlpx.initiator_public_key())).encoded();
                let hello = self.rlpx.write_frame(&mut hello);
                dst.extend_from_slice(&hello);
            }
            // Message::Disconnect(reason) => {
            //     let mut disconnect = Disconnect::new(reason).encoded();
            //     let disconnect = self.rlpx.write_frame(&mut disconnect);
            //     dst.extend_from_slice(&disconnect);
            // }
            Message::Ping => {
                let mut ping = Ping::encoded();
                let ping = self.rlpx.write_frame(&mut ping);
                dst.extend_from_slice(&ping);
            }
            Message::SubProtocolStatus => {
                let status = EthStatus::new();
                let mut status_rlp = BytesMut::new();
                0x0u8.encode(&mut status_rlp);
                status.encode(&mut status_rlp);

                let mut compressed_msg = self.snappy_compress(Id::Other(0), status_rlp)?;

                let status = self.rlpx.write_frame(&mut compressed_msg);
                tracing::warn!("Sending status: {:02x}", status);
                dst.extend_from_slice(&status);
            }
            Message::Disconnect(reason) => {
                let mut disconnect = Disconnect::new(reason).encoded();
                let disconnect = self.rlpx.write_frame(&mut disconnect);
                dst.extend_from_slice(&disconnect);
            }
        }
        Ok(())
    }
}

impl<'a> Decoder for MessageCodec<'a> {
    type Item = MessageRet;
    type Error = eyre::Error;

    #[instrument(name = "decode", skip_all)]
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
                    let total_size = payload + 2; // plus 2 for the 2 bytes holding the size

                    if buf.len() < total_size {
                        trace!(
                            "missing bytes to complete AuthAck. Received: {}, Remaining: {}",
                            buf.len(),
                            total_size
                        );
                        return Ok(None);
                    }

                    let auth_ack = self.rlpx.read_auth_ack(&mut buf.split_to(total_size))?;

                    self.state = State::Header;
                    return Ok(Some(MessageRet::AuthAck(auth_ack)));
                }
                State::Header => {
                    trace!("Reading header");
                    if buf.len() < 32 {
                        trace!("Buffer can not hold the header: buf len: {}", buf.len());
                        trace!("Buffer: {:02x?}", buf);
                        return Ok(None);
                    }

                    let len = self.rlpx.read_header(&mut buf.split_to(32))?;

                    self.state = State::Body(len);
                }
                State::Body(len) => {
                    trace!(body_len=?len, "Reading body");
                    if buf.len() < len {
                        trace!("Expected {} body, but only have {}", len, buf.len());
                        return Ok(None);
                    }

                    let mut data = buf.split_to(len);
                    let mut ret = BytesMut::new();
                    ret.extend_from_slice(&self.rlpx.read_body(&mut data, len)?);

                    self.state = State::Header;

                    let mut r = ret.clone();
                    let message = self.rlpx.read_message(&mut r)?;
                    trace!(message=?message, "Received message");
                    return Ok(Some(message));
                }
            }
        }
    }
}
