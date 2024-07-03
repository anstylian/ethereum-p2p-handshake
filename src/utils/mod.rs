use eyre::Result;
use secp256k1::PublicKey;

pub mod secrets;
pub use alloy_primitives::B512 as NodeId;

pub const SECP256K1_TAG_PUBKEY_UNCOMPRESSED: u8 = 4;

/// Converts a [`PeerId`] to a [`secp256k1::PublicKey`] by prepending the [`PeerId`] bytes with the
/// `SECP256K1_TAG_PUBKEY_UNCOMPRESSED` tag.
pub fn id2pk(id: NodeId) -> Result<PublicKey> {
    // NOTE: B512 is used as a NodeId because 512 bits is enough to represent an uncompressed
    // public key.
    let mut s = [0u8; secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
    s[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
    s[1..].copy_from_slice(id.as_slice());
    Ok(PublicKey::from_slice(&s)?)
}

#[allow(unused)]
pub fn pk2id(pk: &PublicKey) -> NodeId {
    NodeId::from_slice(&pk.serialize_uncompressed()[1..])
}
