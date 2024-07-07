use crate::utils::PROTOCOL_VERSION;
use alloy_rlp::{RlpDecodable, RlpEncodable};

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct Hello {
    protocol_version: u8,
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
            protocol_version: PROTOCOL_VERSION as u8,
            client_version,
            capabilities,
            port,
            id,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Capability {
    pub fn new(name: String, version: usize) -> Self {
        Self { name, version }
    }
}

#[cfg(test)]
mod tests {
    use alloy_rlp::Decodable;

    use super::Hello;

    #[test]
    fn parse_hello() {
        let hx = "f857058b746573742d636c69656e74c6c5836574684480b840a6067e7a0ec8287335252e10fdc83ea98f83c41b86842e34a98674cad491f5a7fecb2e675527f10d7981488a17cfe3f4e560008b4d113e8263703968869f4b45";
        let mut h = hex::decode(hx).unwrap();
        let hello = Hello::decode(&mut h.as_slice());
        println!("{hello:?}");
        println!("{h:02x?}");
    }
}
