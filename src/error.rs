use std::net::SocketAddr;

use alloy_primitives::B128;
use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Rlp Decode Failed: {0:?}")]
    RlpDecodeFailed(#[from] alloy_rlp::Error),

    #[error("secp256k1: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    #[error("Snap: {0}")]
    Snap(#[from] snap::Error),

    #[error("IO: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Str(&'static str),

    #[error("The encrypted message size({0}) does not match the expected size({1}).")]
    AuthEncryptSizeFailed(usize, u16),

    #[error("Failed to decode frame header: {0}")]
    FrameHeader(&'static str),

    #[error("Header MAC checked failed: {0:02x} != {1:02x}")]
    HeaderMac(B128, B128),

    #[error("Body MAC checked failed: {0:02x} != {1:02x}")]
    BodyMac(B128, B128),

    #[error("Message Decryption: {0}")]
    MessageDecryption(&'static str),

    #[error("Enode: {0}")]
    EnodeParse(String),

    #[error("FlowError: {0}")]
    Flow(&'static str),

    #[error("({0}) Handshake failed: {1}")]
    Handshake(SocketAddr, &'static str),

    #[error("Key derivation function failed: {0}")]
    Kdf(concat_kdf::Error),

    #[error("Tokio: {0}")]
    Tokio(tokio::io::Error),

    #[error("{0}")]
    UsizeTryInto(#[from] std::num::TryFromIntError),

    #[error("Timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Decoding Disconnect failed: {0}")]
    DecodeDisconnect(alloy_rlp::Error),

    #[error("Decoding Ping failed")]
    DecodePing,

    #[error("Decoding Pong failed")]
    DecodePong,
}
