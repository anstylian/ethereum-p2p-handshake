use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use bytes::BytesMut;

pub const ID: u8 = 0;

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct ForkId {
    hash: u32,
    next: u64,
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct EthStatus {
    version: u8,
    networkid: u64,
    td: u128,
    blockhash: [u8; 32],
    genesis: [u8; 32],
    forkid: ForkId,
}

impl EthStatus {
    pub fn encoded(self) -> BytesMut {
        let mut status_rlp = BytesMut::new();
        ID.encode(&mut status_rlp);
        self.encode(&mut status_rlp);

        status_rlp
    }
}
