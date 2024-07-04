use alloy_rlp::{RlpDecodable, RlpEncodable};

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct Disconnect {
    pub reason: usize,
}

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct Ping {}

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct Pong {}
