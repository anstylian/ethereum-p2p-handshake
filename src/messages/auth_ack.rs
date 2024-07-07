use std::fmt::Display;

// use crate::utils::PROTOCOL_VERSION;
use alloy_rlp::{RlpDecodable, RlpEncodable};
// use eyre::Result;

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct AuthAck {
    id: [u8; 64],
    nonce: [u8; 32],
    protocol_version: u8,
}

impl AuthAck {
    // pub fn new(id: [u8; 64], nonce: [u8; 32]) -> Result<Self> {
    //     Ok(Self {
    //         id,
    //         nonce,
    //         protocol_version: PROTOCOL_VERSION.try_into()?,
    //     })
    // }

    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub fn id(&self) -> [u8; 64] {
        self.id
    }
}

impl Display for AuthAck {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_fmt(format_args!(
            "AuthAck {{ id: 0x{}, nonce: 0x{}, protocol_version: {:02x}}}",
            hex::encode(self.id),
            hex::encode(self.nonce),
            self.protocol_version
        ))
    }
}
