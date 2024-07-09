//! The goal of ethereum-p2p-handshake is to connect to an ethereum node and complete the handshake
//! process.
//!
//! The implementation is following the description of [The RLPx Transport Protocol](https://github.com/ethereum/devp2p/blob/master/rlpx.md)

use std::{sync::OnceLock, time::Duration};

use argh::FromArgs;
use codec::{Message, MessageCodec, MessageRet};
use eyre::{bail, eyre, Result};
use futures::{future::join_all, sink::SinkExt};
use tokio::{
    net::TcpStream,
    task::JoinHandle,
    time::{self, Instant},
};
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::{
    messages::disconnect::DisconnectReason,
    parties::{initiator::Initiator, recipient::Recipient},
    rlpx::Rlpx,
};

mod codec;
mod enode;
mod mac;
mod messages;
mod parties;
mod rlpx;
mod utils;

#[derive(FromArgs, Debug)]
/// Implementatation of the Ethereum P2P handshake
struct EthereumHandshake {
    /// ethereum Node Id
    #[argh(positional)]
    enodes: Vec<String>,
}

static INITIATOR: OnceLock<Initiator> = OnceLock::new();

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "warn,ethereum_p2p_handshake=trace")
    }
    let args: EthereumHandshake = argh::from_env();

    tracing_subscriber::fmt::init();

    let random_generator = &mut rand::thread_rng();

    info!("Starting ethereum handshake only node");
    let now = Instant::now();

    let initiator = Initiator::new(random_generator).await?;
    INITIATOR.get_or_init(|| initiator);

    trace!("Initiator: {:?}", INITIATOR);
    debug!(
        "Initiator NodeId: {:02x?}",
        INITIATOR.get().unwrap().node_id()
    );

    info!("Arguments: {args:?}");

    let enode = args.enodes;

    debug!("Parsed args: {enode:?}");

    let tasks: Vec<_> = enode
        .into_iter()
        .map(|enode| -> JoinHandle<Result<()>> {
            tokio::task::spawn(async move {
                let recipient = Recipient::new(enode.parse()?)?;
                trace!("Recipient: {recipient:?}");
                let addr = recipient.address().to_owned();

                let stream = match recipient.connect().await {
                    Ok(s) => s,
                    Err(e) => {
                        error!(
                            address = ?recipient.address(),
                            "Connection failed with: {e:?}"
                        );
                        bail!("Connection failed with: {e:?}")
                    }
                };
                let rlpx = Rlpx::new(INITIATOR.get().unwrap(), recipient);

                time::timeout(Duration::from_secs(5), connection_handler(stream, rlpx))
                    .await
                    .map_err(|e| eyre!("{:?}: {e:?}", addr))?
            })
        })
        .collect();

    let tasks_res = join_all(tasks).await;
    info!("Total elpased time {:#?}", now.elapsed());

    for join_handle in tasks_res {
        match join_handle {
            Err(e) => error!("Join handle error: {e:?}"),
            Ok(Err(e)) => {
                error!("{e:?}");
            }
            Ok(Ok(_)) => {}
        }
    }

    Ok(())
}

#[instrument(skip_all, fields(recipient=?stream.peer_addr()?))]
async fn connection_handler(stream: TcpStream, rlpx: Rlpx<'_>) -> Result<()> {
    let recipient_address = stream.peer_addr()?;
    let message_codec = MessageCodec::new(rlpx);
    let mut rlpx_transport = Framed::new(stream, message_codec);

    rlpx_transport.send(Message::Auth).await?;

    let mut ping_counter = 10;
    let mut start = false;

    loop {
        match rlpx_transport.next().await {
            Some(request) => match request {
                Ok(MessageRet::Auth) => unreachable!(),
                Ok(MessageRet::AuthAck(auth_ack)) => {
                    info!(?auth_ack, "AuthAck message received");
                    rlpx_transport.send(Message::Hello).await?;
                }
                Ok(MessageRet::Hello(hello)) => {
                    info!(?hello, "Hello message received");
                    info!("Handshake is done, we have received the first frame successfully");
                    info!("Sending disconnect and clossing the connection");
                    rlpx_transport.send(Message::Ping).await?;
                    rlpx_transport.send(Message::SubProtocolStatus).await?;

                    // break;
                    start = true;
                }
                Ok(MessageRet::Disconnect(disconnect)) => {
                    info!(?disconnect, "Disconnect recevived");
                    break;
                }
                Ok(MessageRet::Ping) => {
                    info!("Ping recevived");
                }
                Ok(MessageRet::Pong) => {
                    info!("Ping recevived");
                }
                Ok(MessageRet::Ignore) => {
                    info!("Ignore unsupported message");
                }
                Err(e) => {
                    error!("Error!!!: {e:?}");
                    break;
                }
            },
            None => {
                let msg = "Stream is finish. Is possible that you tried to reach the same node too frequently. Wait a bit and try again.";
                warn!(msg);
                eyre::bail!(format!("{msg} address: {:?}", recipient_address));
            }
        }

        if start {
            rlpx_transport.send(Message::Ping).await?;
            ping_counter -= 1;
        }

        if ping_counter == 0 {
            rlpx_transport
                .send(Message::Disconnect(DisconnectReason::UselessPeers))
                .await?;
            break;
        }
    }

    rlpx_transport.close().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    pub fn static_random_generator() -> impl Rng {
        rand_chacha::ChaCha8Rng::seed_from_u64(625)
    }
}
