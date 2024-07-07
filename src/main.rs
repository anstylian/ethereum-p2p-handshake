//! The goal of ethereum-p2p-handshake is to connect to an ethereum node and complete the handshake
//! process.
//!
//! The implementation is following the description of [The RLPx Transport Protocol](https://github.com/ethereum/devp2p/blob/master/rlpx.md)

use std::time::Duration;

use argh::FromArgs;
use codec::{Message, MessageCodec, MessageRet};
use eyre::Result;
use futures::sink::SinkExt;
use messages::Disconnect;
use tokio::net::TcpStream;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, trace};
use tracing_subscriber::{fmt, Registry};

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

// TODO: close the streams

#[derive(FromArgs, Debug)]
/// Implementatation of the Ethereum P2P handshake
struct EthereumHandshake {
    /// ethereum node Id
    #[argh(positional)]
    enodes: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "warn,ethereum_p2p_handshake=trace")
    }

    tracing_subscriber::fmt::init();
    // let fmt_layer = fmt::layer().with_ansi(false);
    //
    // let subscriber = Registry::default().with(fmt_layer);
    // tracing::subscriber::set_global_default(subscriber)?;

    let random_generator = &mut rand::thread_rng();

    info!("Starting ethereum handshake only node");
    let args: EthereumHandshake = argh::from_env();
    info!("Arguments: {args:?}");

    let enode = args.enodes;

    debug!("Parsed args: {enode:?}");

    let initiator = Initiator::new(random_generator).await?;
    trace!("Initiator: {initiator:?}");
    debug!("Initiator NodeId: {:02x?}", initiator.node_id());

    let recipient = Recipient::new(enode.parse()?)?;
    trace!("Recipient: {recipient:?}");

    // let recipient = recipient.connect().await?;
    let stream = recipient.connect().await?;
    let connection = Connection::new(&initiator, recipient, random_generator);

    connection_handler(stream, connection).await?;

    Ok(())
}

async fn connection_handler<R: rand::Rng>(
    stream: TcpStream,
    connection: Connection<'_, R>,
) -> Result<()> {
    let message_codec = MessageCodec::new(connection);
    let mut transport = Framed::new(stream, message_codec);

    transport.send(Message::Auth).await?;

    let mut start_ping = false;
    let mut ping_countdown = 1000;

    while let Some(request) = transport.next().await {
        match request {
            Ok(MessageRet::Auth) => todo!(),
            Ok(MessageRet::AuthAck(auth_ack)) => {
                info!("AuthAck message received: {auth_ack:?}");
                transport.send(Message::Hello).await?;
            }
            Ok(MessageRet::Hello(hello)) => {
                info!("Hello message received: {hello:?}");
                transport.send(Message::Disconnect).await?;
                break;

                // ping_countdown -= 1;
            }
            Ok(MessageRet::Disconnect(disconnect)) => {
                info!("Disconnect recevived: {disconnect:?}");
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
        }

        if ping_countdown == 0 {
            info!("Disconnect send");
            transport.send(Message::Disconnect).await?;
            break;
        }

        if start_ping {
            info!("Sending ping: {:?}", ping_countdown);
            transport.send(Message::Ping).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
            ping_countdown -= 1;
        }
    }

    transport.close().await?;

    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use rand::{Rng, SeedableRng};
//
//     use crate::{
//         connection::Connection,
//         parties::{initiator::Initiator, recipient::Recipient},
//     };
//
//     pub fn static_random_generator() -> impl Rng {
//         rand_chacha::ChaCha8Rng::seed_from_u64(625)
//     }
//
//     #[tokio::test]
//     async fn test_drive() {
//         if std::env::var_os("RUST_LOG").is_none() {
//             std::env::set_var("RUST_LOG", "warn,ethereum_p2p_handshake=trace")
//         }
//         tracing_subscriber::fmt::init();
//
//         let random_generator1 = &mut static_random_generator();
//         let random_generator2 = &mut static_random_generator();
//
//         let file1 = "./testing_files/secret1";
//         let initiator = Initiator::test_new(random_generator1, file1)
//             .await
//             .expect("Failed to create initator 1");
//
//         let file2 = "./testing_files/secret2";
//
//         // This is just to create a valid public key
//         let initiator2 = Initiator::test_new(random_generator1, file2)
//             .await
//             .expect("Failed to create initator 2");
//         let mut recipient: Recipient = initiator2
//             .clone()
//             .try_into()
//             .expect("Failed to create recipient from intiator");
//         recipient.port(8080);
//         let connected_recipient = recipient.connect().await.expect("Failed to connect");
//
//         // this is the reverse side so we can decrypt the messeges
//         let mut recipient_other: Recipient = initiator
//             .clone()
//             .try_into()
//             .expect("Failed to create recipient for the other side");
//         recipient_other.port(8081);
//         let connected_recipient_other = recipient_other.connect().await.expect("Failed to connect");
//
//         let mut connection = Connection::new(&initiator, connected_recipient, random_generator1);
//         let mut auth_message = connection
//             .generate_auth_message()
//             .expect("Failed to create auth message");
//
//         println!("Encrypted messege: {:02x}", auth_message);
//
//         let mut connection_other =
//             Connection::new(&initiator2, connected_recipient_other, random_generator2);
//         connection_other
//             .decrypt_message_auth(&mut auth_message)
//             .expect("Failed to decrypt auth");
//
//         // connection.generate_auth_message(random_generator);
//     }
// }
