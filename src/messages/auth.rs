use alloy_rlp::{Encodable, RlpEncodable};
use bytes::BytesMut;
use secp256k1::SECP256K1;

use crate::{
    parties::{initiator::Initiator, recipient::ConnectedRecipient},
    utils::{ecdh_x, pk2id, PROTOCOL_VERSION},
};

/// From the documentation the message Auth body has the following structure
/// NOTE: this is not the full message, is only the unenrypted body
///
/// auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
/// More detail description on how to construct the auth messeage can be found here:
/// https://github.com/ethereum/devp2p/blob/readme-spec-links/rlpx.md
/// auth -> E(remote-pubk, S(ephemeral-privk, static-shared-secret ^ nonce) || H(ephemeral-pubk) || pubk || nonce || 0x0)
/// static-shared-secret = ecdh.agree(privkey, remote-pubk)
#[derive(Debug, RlpEncodable)]
pub struct AuthBody<'a> {
    signature: &'a [u8; 65],
    initiator_public_key: &'a [u8; 64],
    initiator_nonde: &'a [u8; 32],
    auth_version: usize,
}

impl<'a> AuthBody<'a> {
    /// Add message to buffer
    pub fn message(recipient: &ConnectedRecipient, initiator: &Initiator) -> BytesMut {
        //generate signiture
        let static_shared_secret = ecdh_x(recipient.public_key(), initiator.secret_key());
        let message = static_shared_secret ^ *initiator.nonce();

        let (recovery_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest(message.0),
                initiator.ephemeral_secret_key(),
            )
            .serialize_compact();

        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&sig);
        signature[64] = recovery_id.to_i32() as u8;

        let id = pk2id(initiator.public_key());

        let mut buf = BytesMut::new();
        AuthBody {
            signature: &signature,
            initiator_public_key: &id,
            initiator_nonde: initiator.nonce(),
            auth_version: PROTOCOL_VERSION,
        }
        .encode(&mut buf);

        buf
    }
}
