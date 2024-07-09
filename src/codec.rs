use alloy_rlp::{Decodable, Encodable};
use bytes::BytesMut;
use eyre::Result;
use snap::raw::{Decoder as SnapDecoder, Encoder as SnapEncoder};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, instrument, trace};

use crate::{
    messages::{
        self,
        auth_ack::AuthAck,
        disconnect::{self, Disconnect, DisconnectReason},
        ethstatus::EthStatus,
        hello::{self, Hello},
        Ping, Pong,
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
    SubProtocolStatus(EthStatus),
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
    EthStatus(EthStatus),
}

#[derive(Debug)]
pub enum Id {
    #[allow(dead_code)]
    P2pCapability(u8),
    Other(u8),
}

impl Id {
    pub fn id(&self) -> u8 {
        match self {
            Id::P2pCapability(id) => *id,
            Id::Other(id) => id + 0x10,
        }
    }
}

impl From<u8> for Id {
    fn from(id: u8) -> Self {
        if id < 0x10 {
            Id::P2pCapability(id)
        } else {
            Id::Other(id - 0x10)
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
    snap_decoder: SnapDecoder,
}

impl<'a> MessageCodec<'a> {
    pub fn new(rlpx: Rlpx<'a>) -> Self {
        Self {
            rlpx,
            state: State::Auth,
            snap_encoder: SnapEncoder::new(),
            snap_decoder: SnapDecoder::new(),
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

    #[instrument(skip_all)]
    fn snappy_decompress(&mut self, input: &[u8]) -> Result<BytesMut> {
        let len = snap::raw::decompress_len(input)?;
        let mut decompress = BytesMut::zeroed(len + 1);
        // TODO: handle decompress size

        self.snap_decoder.decompress(input, &mut decompress)?;

        Ok(decompress)
    }

    fn last_zero_from_tail(v: &[u8]) -> usize {
        let mut idx = v.len() - 1;

        while idx > 0 {
            if v[idx - 1] == 0 {
                idx -= 1;
            } else {
                break;
            }
        }

        idx
    }

    #[instrument(skip_all)]
    fn read_message(&mut self, message: &mut BytesMut) -> Result<MessageRet> {
        trace!("Message bytes: {:02x}", message);

        let (mut message_id, mut message) = message.split_at(1);
        let message_id: u8 = u8::decode(&mut message_id)?;
        debug!("message_id: {:?}", message_id);

        match message_id {
            hello::ID => {
                trace!("Hello bytes: {message:02x?}");
                let hello: Hello = Hello::decode(&mut message)?;
                debug!("Hello message from target node: {:?}", hello);

                Ok(MessageRet::Hello(hello))
            }
            disconnect::ID => {
                tracing::debug!("Disconnect bytes: {message:02x?}");
                let idx = Self::last_zero_from_tail(message);

                let buf = match self.snappy_decompress(&message[..idx]) {
                    Ok(b) => b,
                    Err(e) => {
                        trace!("Disconnect failed to decode using snappy: {e:?}. Try to decode directly from rlp");
                        BytesMut::from(message)
                    }
                };

                let disconnect = Disconnect::decode(&mut buf.as_ref())?;
                debug!("Disconnect: {}", disconnect);
                Ok(MessageRet::Disconnect(disconnect))
            }
            messages::PING_ID => {
                trace!("Ping bytes: {message:02x?}");
                if message.starts_with(Ping::bytes()) {
                    Ok(MessageRet::Ping)
                } else {
                    eyre::bail!("This is not a ping message: {message:02x?}")
                }
            }
            messages::PONG_ID => {
                trace!("Pong bytes: {message:02x?}");
                if message.starts_with(Pong::bytes()) {
                    Ok(MessageRet::Pong)
                } else {
                    eyre::bail!("This is not a ping message: {message:02x?}")
                }
            }
            id => {
                let id: Id = id.into();

                if id.id() == 16 {
                    debug!("Start decoding EthStatus: len: {:?}", message.len());

                    let idx = Self::last_zero_from_tail(message);
                    let buf = self.snappy_decompress(&message[..idx])?;
                    let eth_status = EthStatus::decode(&mut buf.as_ref())?;

                    Ok(MessageRet::EthStatus(eth_status))
                } else {
                    tracing::warn!("unknown id: {id:?}");
                    Ok(MessageRet::Ignore)
                }
            }
        }
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
            Message::Ping => {
                let mut ping = Ping::encoded();
                let ping = self.rlpx.write_frame(&mut ping);
                dst.extend_from_slice(&ping);
            }
            Message::SubProtocolStatus(status) => {
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
                    let message = self.read_message(&mut r)?;
                    trace!(message=?message, "Received message");
                    return Ok(Some(message));
                }
            }
        }
    }
}
