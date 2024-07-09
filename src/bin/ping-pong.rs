//! The goal of ethereum-p2p-handshake is to connect to an ethereum node and complete the handshake
//! process.
//!
//! The implementation is following the description of [The RLPx Transport Protocol](https://github.com/ethereum/devp2p/blob/master/rlpx.md)

use std::{net::SocketAddr, sync::OnceLock, time::Duration};

use argh::FromArgs;
use eyre::{bail, eyre, Result};
use futures::{future::join_all, sink::SinkExt};
use tokio::{
    task::JoinHandle,
    time::{self, Instant},
};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, instrument, trace, warn};

use ethereum_p2p_handshake::{
    codec::Message,
    messages::{
        decode_subprotocol_message,
        disconnect::{Disconnect, DisconnectReason},
        SubProtocolMessage,
    },
    parties::{initiator::Initiator, recipient::Recipient},
    rlpx::Rlpx,
    RlpxTransport,
};

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

                let transport = time::timeout(
                    Duration::from_secs(5),
                    ethereum_p2p_handshake::rlpx_transport(stream, rlpx),
                )
                .await
                .map_err(|e| eyre!("{:?}: {e:?}", addr))??;

                ping_pong(transport, addr).await
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

#[instrument(skip_all)]
async fn ping_pong<'a>(transport: RlpxTransport<'a>, addr: SocketAddr) -> Result<()> {
    let mut transport = transport;
    let mut ping_counter = 10;

    loop {
        match transport.next().await {
            Some(request) => {
                match request {
                    Ok(message) => {
                        match message {
                            Message::Auth => unreachable!(), // This is not supported yet
                            Message::AuthAck(_) => {
                                unreachable!()
                            }
                            Message::Hello(_) => {
                                unreachable!()
                            }
                            Message::Disconnect(disconnect) => {
                                info!("Disconnect recevived: {}", disconnect);
                                break;
                            }
                            Message::Ping => {
                                info!("Ping received during handshake. Sending Pong.");
                                transport.send(Message::Pong).await?;
                                ping_counter -= 1;
                            }
                            Message::Pong => {
                                info!("Pong received during handshake. Sending Ping");
                                transport.send(Message::Ping).await?;
                                ping_counter -= 1;
                            }
                            Message::SubProtocolMessage(message) => {
                                info!("SubProtocolMessage received during handshake.");
                                let mut message = message;
                                let message = decode_subprotocol_message(&mut message)?;

                                if let Some(SubProtocolMessage::EthStatus(eth_status)) = message {
                                    transport
                                        .send(Message::SubProtocolMessage(eth_status.encoded()))
                                        .await?;
                                } else {
                                    info!("Unsupported message received. Ignore");
                                }

                                transport.send(Message::Ping).await?;
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
                let msg = "Stream is finish. Is possible that you tried to reach the same node too frequently. Wait a bit and try again.";
                warn!(msg);
                eyre::bail!(format!("{msg} address: {:?}", addr));
            }
        }

        if ping_counter == 0 {
            transport
                .send(Message::Disconnect(Disconnect::new(
                    DisconnectReason::TooManyPeers,
                )))
                .await?;
            break;
        }
    }

    transport.close().await?;

    Ok(())
}
