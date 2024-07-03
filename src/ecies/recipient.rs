use eyre::Result;
use secp256k1::PublicKey;
use std::net::SocketAddr;

use crate::enode::Enode;
use crate::utils::{id2pk, NodeId};

#[allow(unused)]
#[derive(Debug)]
pub struct Recipient {
    public_key: PublicKey,
    id: NodeId,
    address: SocketAddr,
}

impl Recipient {
    pub fn new(enode: Enode) -> Result<Self> {
        Ok(Self {
            public_key: id2pk(enode.node_id())?,
            id: enode.node_id(),
            address: enode.address(),
        })
    }
}

#[cfg(test)]
impl TryFrom<super::initiator::Initiator> for Recipient {
    type Error = eyre::Error;

    fn try_from(initiator: super::initiator::Initiator) -> Result<Self> {
        let initiator_enode = initiator.enode()?;
        Recipient::new(initiator_enode)
    }
}
