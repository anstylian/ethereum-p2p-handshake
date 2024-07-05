use crate::utils::PROTOCOL_VERSION;
use alloy_rlp::{RlpDecodable, RlpEncodable};

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct Hello {
    protocol_version: usize,
    client_version: String,
    capabilities: Vec<Capability>,
    port: u16,
    id: [u8; 64],
}

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct Capability {
    pub name: String,
    pub version: usize,
}

impl Hello {
    pub fn new(
        client_version: String,
        capabilities: Vec<Capability>,
        port: u16,
        id: [u8; 64],
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            client_version,
            capabilities,
            port,
            id,
        }
    }
}

impl Capability {
    pub fn new(name: String, version: usize) -> Self {
        Self { name, version }
    }
}
