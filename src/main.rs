//! The goal of ethereum-p2p-handshake is to connect to an ethereum node and complete the handshake
//! process.
//!
//! The implementation is following the description of [The RLPx Transport Protocol](https://github.com/ethereum/devp2p/blob/master/rlpx.md)

use argh::FromArgs;
use eyre::Result;
use tracing::{debug, info, trace};

use crate::{
    connection::Connection,
    ecies::parties::{initiator::Initiator, recipient::RecipientDefinition},
};

mod connection;
mod ecies;
mod enode;
mod messages;
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
        std::env::set_var("RUST_LOG", "warn,ethereum_p2p_handshake=debug")
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

    let mut connection = Connection::new(&initiator, recipient);
    connection.send_auth_message(random_generator).await?;

    connection.abort();

    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    use crate::{
        connection::Connection,
        ecies::parties::{initiator::Initiator, recipient::RecipientDefinition},
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

        let random_generator = &mut static_random_generator();

        let file1 = "./testing_files/secret1";
        let initiator = Initiator::test_new(random_generator, file1)
            .await
            .expect("Failed to create initator 1");

        let file2 = "./testing_files/secret2";

        // This is just to create a valid public key
        let initiator2 = Initiator::test_new(random_generator, file2)
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

        let mut connection = Connection::new(&initiator, connected_recipient);
        let mut auth_message = connection
            .generate_auth_message(random_generator)
            .expect("Failed to create auth message");

        println!("Encrypted messege: {:02x}", auth_message);

        let mut connection_other = Connection::new(&initiator2, connected_recipient_other);
        connection_other
            .decrypt_message_auth(&mut auth_message)
            .expect("Failed to decrypt auth");

        // connection.generate_auth_message(random_generator);
    }
}
