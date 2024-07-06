//! The goal of ethereum-p2p-handshake is to connect to an ethereum node and complete the handshake
//! process.
//!
//! The implementation is following the description of [The RLPx Transport Protocol](https://github.com/ethereum/devp2p/blob/master/rlpx.md)

use argh::FromArgs;
use eyre::Result;
use tracing::{debug, info, trace};

use crate::{
    connection::Connection,
    parties::{initiator::Initiator, recipient::RecipientDefinition},
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

    let random_generator = &mut rand::thread_rng();

    info!("Starting ethereum handshake only node");
    let args: EthereumHandshake = argh::from_env();
    info!("Arguments: {args:?}");

    // let enode = Enode::new(&args.enodes)?;
    let enode = args.enodes;

    debug!("Parsed args: {enode:?}");

    let initiator = Initiator::new(random_generator).await?;
    trace!("Initator: {initiator:?}");

    let recipient = RecipientDefinition::new(enode.parse()?)?;
    trace!("Recipient: {recipient:?}");

    let recipient = recipient.connect().await?;

    let mut connection = Connection::new(&initiator, recipient, random_generator);
    connection.send_auth_message().await?;
    connection.receive_auth_ack().await?;
    connection.receive().await?;
    connection.sent_hello().await?;
    connection.receive().await?;
    println!("---->send PING");
    connection.sent_ping().await?;
    println!("---->recv PONG");
    connection.receive().await?;
    println!("---->send PING");
    connection.sent_ping().await?;
    println!("---->recv PONG");
    connection.receive().await?;

    connection.abort();

    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    use crate::{
        connection::Connection,
        parties::{initiator::Initiator, recipient::RecipientDefinition},
    };

    pub fn static_random_generator() -> impl Rng {
        rand_chacha::ChaCha8Rng::seed_from_u64(625)
    }

    #[tokio::test]
    async fn test_drive() {
        if std::env::var_os("RUST_LOG").is_none() {
            std::env::set_var("RUST_LOG", "warn,ethereum_p2p_handshake=trace")
        }
        tracing_subscriber::fmt::init();

        let random_generator1 = &mut static_random_generator();
        let random_generator2 = &mut static_random_generator();

        let file1 = "./testing_files/secret1";
        let initiator = Initiator::test_new(random_generator1, file1)
            .await
            .expect("Failed to create initator 1");

        let file2 = "./testing_files/secret2";

        // This is just to create a valid public key
        let initiator2 = Initiator::test_new(random_generator1, file2)
            .await
            .expect("Failed to create initator 2");
        let mut recipient: RecipientDefinition = initiator2
            .clone()
            .try_into()
            .expect("Failed to create recipient from intiator");
        recipient.port(8080);
        let connected_recipient = recipient.connect().await.expect("Failed to connect");

        // this is the reverse side so we can decrypt the messeges
        let mut recipient_other: RecipientDefinition = initiator
            .clone()
            .try_into()
            .expect("Failed to create recipient for the other side");
        recipient_other.port(8081);
        let connected_recipient_other = recipient_other.connect().await.expect("Failed to connect");

        let mut connection = Connection::new(&initiator, connected_recipient, random_generator1);
        let mut auth_message = connection
            .generate_auth_message()
            .expect("Failed to create auth message");

        println!("Encrypted messege: {:02x}", auth_message);

        let mut connection_other =
            Connection::new(&initiator2, connected_recipient_other, random_generator2);
        connection_other
            .decrypt_message_auth(&mut auth_message)
            .expect("Failed to decrypt auth");

        // connection.generate_auth_message(random_generator);
    }
}
