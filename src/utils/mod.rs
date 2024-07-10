use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes128,
};
use alloy_primitives::{B128, B256};
use ctr::Ctr64BE;
use eyre::{eyre, Result};
use hmac::{Hmac, Mac};
use secp256k1::PublicKey;

pub mod secrets;
pub use alloy_primitives::{B256 as Nonce, B512 as NodeId};
use secp256k1::SecretKey;
use sha2::{Digest, Sha256};

pub const SECP256K1_TAG_PUBKEY_UNCOMPRESSED: u8 = 4;

pub const PROTOCOL_VERSION: usize = 5;

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

pub fn pk2id(pk: &PublicKey) -> NodeId {
    NodeId::from_slice(&pk.serialize_uncompressed()[1..])
}

/// Agree for a secret. Secret is only the X of of the point.
pub fn ecdh_x(public_key: &PublicKey, secret_key: &SecretKey) -> B256 {
    B256::from_slice(&secp256k1::ecdh::shared_secret_point(public_key, secret_key)[..32])
}

pub fn kdf(secret: B256, dest: &mut [u8]) -> Result<()> {
    concat_kdf::derive_key_into::<Sha256>(secret.as_slice(), &[], dest)
        .map_err(|e| eyre!("Key derivation function failed: {e:?}"))?;

    Ok(())
}

pub fn hmac_sha256(key: &[u8], input: &[&[u8]], auth_data: &[u8]) -> B256 {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for input in input {
        hmac.update(input);
    }
    hmac.update(auth_data);
    B256::from_slice(&hmac.finalize().into_bytes())
}

pub fn key_material(shared_secret: B256) -> Result<(B128, B256)> {
    let mut key = [0u8; 32];
    kdf(shared_secret, &mut key)?;

    let encryption_key: B128 = B128::from_slice(&key[..16]);
    let authentication_key = B256::from(Sha256::digest(&key[16..32]).as_ref());

    Ok((encryption_key, authentication_key))
}

pub fn aes_encrypt(encryption_key: B128, message: &mut [u8], iv: B128) {
    let mut cipher = Ctr64BE::<Aes128>::new(&encryption_key.0.into(), &iv.0.into());
    cipher.apply_keystream(message);
}

pub fn aes_decrypt(encryption_key: B128, message: &mut [u8], iv: B128) {
    let mut decryptor = Ctr64BE::<Aes128>::new(&encryption_key.0.into(), &iv.0.into());
    decryptor.apply_keystream(message);
}
