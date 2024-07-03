//! The goal of ethereum-p2p-handshake is to connect to an ethereum node and complete the handshake
//! process.
//!
//! The implementation is following the description of [The RLPx Transport Protocol](https://github.com/ethereum/devp2p/blob/master/rlpx.md)

use argh::FromArgs;
use eyre::Result;
use tracing::{debug, info, trace};

use crate::ecies::{initiator::Initiator, recipient::Recipient};

mod ecies;
mod enode;
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

    let initiator = Initiator::new(random_generator).await;
    trace!("Initator: {initiator:?}");

    let recipient = Recipient::new(enode.parse()?);
    trace!("Recipient: {recipient:?}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    use crate::ecies::{initiator::Initiator, recipient::Recipient};
    pub fn static_random_generator() -> impl Rng {
        rand_chacha::ChaCha8Rng::seed_from_u64(625)
    }

    #[tokio::test]
    async fn test_drive() {
        let random_generator = &mut static_random_generator();

        let file1 = "./testing_files/secret1";
        let initiator = Initiator::test_new(random_generator, file1)
            .await
            .expect("Failed to create initator 1");
        let _recipient: Recipient = initiator
            .try_into()
            .expect("Failed to create recipient from intiator");

        let file2 = "./testing_files/secret2";
        let initiator2 = Initiator::test_new(random_generator, file2)
            .await
            .expect("Failed to create initator 2");
        let _recipient2: Recipient = initiator2
            .try_into()
            .expect("Failed to create recipient from intiator");
    }
}
