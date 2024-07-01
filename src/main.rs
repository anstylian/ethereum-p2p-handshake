//! The goal of ethereum-p2p-handshake is to connect to an ethereum node and complete the handshake
//! process.
//!
//! The implementation is following the description of [The RLPx Transport Protocol](https://github.com/ethereum/devp2p/blob/master/rlpx.md)

use argh::FromArgs;
use enode::Enode;
use eyre::Result;
use tracing::{debug, info, trace};

use crate::ecies::initiator::Initiator;

mod ecies;
mod enode;
mod utils;

#[derive(FromArgs, Debug)]
/// Implementatation of the Ethereum P2P handshake
struct EthereumHandshake {
    /// ethereum node Id
    #[argh(positional)]
    enodes: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "warn,ethereum_p2p_handshake=debug")
    }
    tracing_subscriber::fmt::init();

    info!("Starting ethereum handshake only node");
    let args: EthereumHandshake = argh::from_env();
    info!("Arguments: {args:?}");

    let enodes: Result<Vec<_>> = args.enodes.into_iter().map(|e| Enode::new(&e)).collect();
    let enodes = enodes?;
    debug!("Parsed args: {enodes:?}");

    let initiator = Initiator::new().await;
    trace!("Initator: {initiator:?}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ecies::deterministic_secrtets::DeterministicInitiator;

    #[tokio::test]
    async fn test_drive() {
        let _initator = DeterministicInitiator::new()
            .await
            .expect("Failed to create deterministic initator");
    }
}
