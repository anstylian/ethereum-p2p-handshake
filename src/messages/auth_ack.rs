use crate::utils::{NodeId, PROTOCOL_VERSION};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use eyre::Result;

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct AuthAck {
    id: [u8; 64],
    nonce: [u8; 32],
    protocol_version: u8,
}

impl AuthAck {
    pub fn new(id: [u8; 64], nonce: [u8; 32]) -> Result<Self> {
        Ok(Self {
            id,
            nonce,
            protocol_version: PROTOCOL_VERSION.try_into()?,
        })
    }

    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub fn id(&self) -> [u8; 64] {
        self.id
    }
}
