use alloy_primitives::B256;
use eyre::{eyre, Result};
use secp256k1::PublicKey;
use std::{net::SocketAddr, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tracing::{debug, instrument};

use crate::{enode::Enode, utils::id2pk};

/// Connection timeout in seconds
const CONNECTION_TIMEOUT: u64 = 30;

#[derive(Debug)]
pub struct Recipient {
    public_key: PublicKey,
    address: SocketAddr,
    ephemeral_public_key: Option<PublicKey>,
    nonce: Option<B256>,
}

impl Recipient {
    pub fn new(enode: Enode) -> Result<Self> {
        Ok(Self {
            public_key: id2pk(enode.node_id())?,
            address: enode.address(),
            ephemeral_public_key: None,
            nonce: None,
        })
    }

    #[instrument(skip_all)]
    pub async fn connect(&self) -> Result<TcpStream> {
        debug!("Connecting to {}", self.address);
        let stream = timeout(
            Duration::from_secs(CONNECTION_TIMEOUT),
            TcpStream::connect(self.address),
        )
        .await??;

        Ok(stream)
    }

    pub fn address(&self) -> &SocketAddr {
        &self.address
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn ephemeral_public_key(&self) -> Result<&PublicKey> {
        self.ephemeral_public_key
            .as_ref()
            .ok_or(eyre!("Recipient public key is not initialized"))
    }

    pub fn nonce(&self) -> Result<&B256> {
        self.nonce
            .as_ref()
            .ok_or(eyre!("Recipient public key is not initialized"))
    }

    pub fn set_nonce(&mut self, nonce: B256) {
        self.nonce = Some(nonce);
    }

    pub fn set_ephemeral_public_key(&mut self, public_key: PublicKey) {
        self.ephemeral_public_key = Some(public_key);
    }
}

#[cfg(test)]
impl TryFrom<super::initiator::Initiator> for Recipient {
    type Error = eyre::Error;

    fn try_from(initiator: super::initiator::Initiator) -> Result<Self> {
        let initiator_enode = initiator.enode()?;
        Self::new(initiator_enode)
    }
}
