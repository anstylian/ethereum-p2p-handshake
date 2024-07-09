use std::net::SocketAddr;

use codec::{Message, MessageCodec};
use eyre::Result;
use futures::SinkExt;
use rlpx::Rlpx;
use tokio::net::TcpStream;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{debug, error, instrument, trace, warn};

use crate::{messages::hello::Hello, utils::pk2id};

pub mod codec;
pub mod enode;
mod mac;
pub mod messages;
pub mod parties;
pub mod rlpx;
mod utils;

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    pub fn static_random_generator() -> impl Rng {
        rand_chacha::ChaCha8Rng::seed_from_u64(625)
    }
}

pub type RlpxTransport<'a> = Framed<TcpStream, MessageCodec<'a>>;

#[instrument(skip_all, fields(recipient=?stream.peer_addr()?))]
pub async fn rlpx_transport(stream: TcpStream, rlpx: Rlpx<'_>) -> Result<RlpxTransport> {
    let recipient_address = stream.peer_addr()?;
    let message_codec = MessageCodec::new(rlpx);
    let mut transport = Framed::new(stream, message_codec);

    handshake(&mut transport, recipient_address).await?;

    Ok(transport)
}

#[instrument(skip_all)]
async fn handshake(transport: &mut RlpxTransport<'_>, recipient_address: SocketAddr) -> Result<()> {
    transport.send(Message::Auth).await?;

    loop {
        match transport.next().await {
            Some(request) => {
                match request {
                    Ok(message) => {
                        match message {
                            Message::Auth => unreachable!(), // This is not supported yet
                            Message::AuthAck(auth_ack) => {
                                trace!(?auth_ack, "AuthAck message received.");
                                let hello = Hello::new_default_values(*pk2id(
                                    transport.codec().initiator_public_key(),
                                ));
                                trace!(?hello, "Sending Hello message");
                                transport.send(Message::Hello(hello)).await?;
                            }
                            Message::Hello(hello) => {
                                debug!(?hello, "Hello message received");
                                debug!("Handshake is done, we have received the first frame successfully");
                                break;
                            }
                            Message::Disconnect(disconnect) => {
                                trace!("Disconnect recevived: {}", disconnect);
                                break;
                            }
                            Message::Ping => {
                                trace!("Ping received during handshake. ignore");
                            }
                            Message::Pong => {
                                trace!("Pong received during handshake. ignore");
                            }
                            Message::SubProtocolMessage(_) => {
                                trace!("SubProtocolMessage received during handshake. ignore");
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error!!!: {e:?}");
                        break;
                    }
                }
            }
            None => {
                let msg = "HANDSHAKE: Stream is finish. Is possible that you tried to reach the same node too frequently. Wait a bit and try again.";
                warn!(msg);
                eyre::bail!(format!("{msg} address: {:?}", recipient_address));
            }
        }
    }

    Ok(())
}
