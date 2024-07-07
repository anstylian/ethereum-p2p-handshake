use alloy_primitives::{B128, B256};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use eyre::Result;
use secp256k1::{PublicKey, SecretKey};

use crate::utils::{aes_decrypt, ecdh_x, hmac_sha256, key_material};

use self::hello::Hello;

pub mod auth;
pub mod auth_ack;
pub mod hello;

#[derive(Debug)]
pub enum FrameMessage {
    Hello(Hello),
    Disconnect(Disconnect),
    Ping(Ping),
    Pong(Pong),
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Disconnect {
    pub reason: usize,
}

impl std::fmt::Display for Disconnect {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let reason = match self.reason {
            0x0 => "Disconnected requested",
            0x1 => "TCP sub-system error",
            0x2 => "Breach of protocol, e.g. a malformed message, bad RLP, ...",
            0x3 => "Useless peer",
            0x4 => "Too many peers",
            0x5 => "Already connected",
            0x6 => "Incompatible P2P protocol version",
            0x7 => "Null node identity received - this is automatically invalid",
            0x8 => "Client quitting",
            0x9 => "Unexpected identity in handshake",
            0xa => "Identity is the same as this node (i.e. connected to itself)",
            0xb => "Ping timeout",
            0x10 => "Some other reason specific to a subprotocol",
            _ => unreachable!(),
        };

        write!(f, "Disconnect {{ reason: {reason} }}")
    }
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Ping {}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Pong {}

pub struct MessageDecryptor<'a> {
    // Message size after auth-data (2 bytes)
    auth_data: [u8; 2],
    // 65 bytes
    public_key: PublicKey,
    // 16 bytes
    iv: B128,
    encrypted_message: &'a mut [u8],
    // 32 bytes
    tag: B256,
}

impl<'a> MessageDecryptor<'a> {
    pub fn new(message: &'a mut [u8]) -> Result<Self> {
        if message.len() < (65 + 2 + 16) {
            return Err(eyre::eyre!("Received message is too small"));
        }

        let (auth_data, remaining) = message.split_at_mut(2);
        let auth_data: [u8; 2] = [auth_data[0], auth_data[1]];
        println!("auth: {:02x?}", auth_data);
        let message_len: i16 = i16::from_be_bytes(auth_data);

        let (public_key, remaining) = remaining.split_at_mut(65);
        let (iv, remaining) = remaining.split_at_mut(16);
        let (encrypted_message, remaining) =
            remaining.split_at_mut((message_len as usize - 65 - 16) - 32);

        let (tag, _encrypted) = remaining.split_at(32);

        Ok(MessageDecryptor {
            auth_data,
            public_key: PublicKey::from_slice(public_key)?,
            iv: B128::from_slice(iv),
            encrypted_message,
            tag: B256::from_slice(tag),
        })
    }

    pub fn derive_keys(&self, secret_key: &SecretKey) -> Result<(B128, B256)> {
        let shared_secret = ecdh_x(&self.public_key, secret_key);

        key_material(shared_secret)
    }

    pub fn check_integrity(&self, authentication_key: B256) -> Result<()> {
        let check_tag = hmac_sha256(
            authentication_key.as_slice(),
            &[self.iv.as_slice(), self.encrypted_message],
            &self.auth_data,
        );

        if check_tag == self.tag {
            Ok(())
        } else {
            Err(eyre::eyre!("Integrity check failed"))
        }
    }

    pub fn decrypt(self, encryption_key: B128) -> &'a mut [u8] {
        let iv = self.iv;
        let decrypted_data = self.encrypted_message;
        aes_decrypt(encryption_key, decrypted_data, iv);
        decrypted_data
    }
}
