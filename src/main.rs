//! The goal of ethereum-p2p-handshake is to connect to an ethereum node and complete the handshake
//! process.
//!
//! The implementation is following the description of [The RLPx Transport Protocol](https://github.com/ethereum/devp2p/blob/master/rlpx.md)

use std::sync::OnceLock;

use argh::FromArgs;
use codec::{Message, MessageCodec, MessageRet};
use eyre::{bail, Result};
use futures::{future::join_all, sink::SinkExt};
use tokio::{net::TcpStream, task::JoinHandle};
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::{
    connection::Connection,
    parties::{initiator::Initiator, recipient::Recipient},
};

mod codec;
mod connection;
mod enode;
mod mac;
mod messages;
mod parties;
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
        std::env::set_var("RUST_LOG", "warn,ethereum_p2p_handshake=info")
    }
    let args: EthereumHandshake = argh::from_env();

    tracing_subscriber::fmt::init();

    let random_generator = &mut rand::thread_rng();

    info!("Starting ethereum handshake only node");

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
            let jh = tokio::task::spawn(async move {
                let recipient = Recipient::new(enode.parse()?)?;
                trace!("Recipient: {recipient:?}");

                let stream = match recipient.connect().await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Connection failed with: {e:?}");
                        bail!("Connection failed with: {e:?}")
                    }
                };
                let connection = Connection::new(INITIATOR.get().unwrap(), recipient);

                connection_handler(stream, connection).await
            });
            jh
        })
        .collect();

    let tasks_res = join_all(tasks).await;

    for join_handle in tasks_res {
        let Ok(Ok(_)) = join_handle else {
            error!("{join_handle:?}");
            continue;
        };
    }

    Ok(())
}

#[instrument(skip_all, fields(recipient=?stream.peer_addr()?))]
async fn connection_handler(stream: TcpStream, connection: Connection<'_>) -> Result<()> {
    let message_codec = MessageCodec::new(connection);
    let mut transport = Framed::new(stream, message_codec);

    transport.send(Message::Auth).await?;

    loop {
        match transport.next().await {
            Some(request) => match request {
                Ok(MessageRet::Auth) => unreachable!(),
                Ok(MessageRet::AuthAck(auth_ack)) => {
                    info!(?auth_ack, "AuthAck message received");
                    transport.send(Message::Hello).await?;
                }
                Ok(MessageRet::Hello(hello)) => {
                    info!(?hello, "Hello message received");
                    info!("Handshake is done, we have received the first frame successfully");
                    info!("Sending disconnect and clossing the connection");
                    transport.send(Message::Disconnect).await?;
                    break;
                }
                Ok(MessageRet::Disconnect(disconnect)) => {
                    info!(?disconnect, "Disconnect recevived");
                    break;
                }
                Ok(MessageRet::Ping(_)) => {
                    info!("Ping recevived");
                }
                Ok(MessageRet::Ignore) => {
                    info!("Ignore unsupported message");
                }
                Err(e) => {
                    error!("Error: {e:?}");
                    break;
                }
            },
            None => {
                warn!("Stream is finish. Is possible that you tried to reach the same node too frequently. Wait a bit and try again.");
                break;
            }
        }
    }

    transport.close().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    pub fn static_random_generator() -> impl Rng {
        rand_chacha::ChaCha8Rng::seed_from_u64(625)
    }
}
