use std::fmt::Display;

use crate::utils::PROTOCOL_VERSION;
use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use bytes::BytesMut;

pub const ID: u8 = 0x0;

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq, Clone)]
pub struct Hello {
    protocol_version: u8,
    client_version: String,
    capabilities: Vec<Capability>,
    port: u16,
    id: [u8; 64],
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq, Clone)]
pub struct Capability {
    pub name: String,
    pub version: usize,
}

impl Hello {
    pub fn new_default_values(id: [u8; 64]) -> Self {
        let capabilities = vec![Capability::new("eth".to_string(), 68)];
        Hello::new("test-client".to_string(), capabilities, 0, id)
    }

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

    pub fn encoded(self) -> BytesMut {
        let mut hello = BytesMut::new();
        ID.encode(&mut hello);
        self.encode(&mut hello);

        hello
    }
}

impl Capability {
    pub fn new(name: String, version: usize) -> Self {
        Self { name, version }
    }
}

impl Display for Hello {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_fmt(format_args!(
            "Hello {{ protocol_version: {}, client_version: {}, capabilities: {:?}, port: {}, id: 0x{} }}",
            self.protocol_version,
            self.client_version,
            self.capabilities,
            self.port,
            hex::encode(self.id),
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloy_rlp::{Decodable, Encodable};

    use crate::{
        messages::hello::Capability, parties::initiator::Initiator, tests::static_random_generator,
        utils::pk2id,
    };

    use super::Hello;

    #[tokio::test]
    async fn parse_hello() {
        let random_generator1 = &mut static_random_generator();
        let initiator = Initiator::new(random_generator1)
            .await
            .expect("Failed to create initiator");
        let hello_left = Hello::new(
            "test-client".to_owned(),
            vec![Capability::new("eth".to_owned(), 68)],
            30303,
            *pk2id(initiator.public_key()),
        );

        let mut buf = vec![];
        hello_left.encode(&mut buf);
        let hello_right = Hello::decode(&mut buf.as_slice()).expect("Hello decode failed");

        assert_eq!(hello_left, hello_right);
    }
}
