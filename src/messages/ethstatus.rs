use alloy_rlp::{RlpDecodable, RlpEncodable};

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
