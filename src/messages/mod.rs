use crate::utils::NodeId;
use alloy_primitives::{B128, B256};
use eyre::Result;
use secp256k1::{PublicKey, SecretKey};

use crate::utils::{aes_decrypt, ecdh_x, hmac_sha256, id2pk, key_material};

pub mod auth;

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

// pub struct Message<'a> {
//     public_key: &'a [u8; 65],
//     iv: B128,
//     message: &'a [u8],
//     tag: B256,
// }
//
// impl<'a> Message<'a> {
//     fn new(
//         message: &'a mut [u8],
//         recipient_public_key: PublicKey,
//         random_generator: &mut impl Rng,
//     ) -> Result<Self> {
//         let total_size: u16 = u16::try_from(
//             secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE  // Public key size
//                 + 16                                            // Size of iv
//                 + message.len()                                 // Unencrypted message
//                 + 32, // Tag Size
//         )
//         .unwrap();
//
//         let secret_key = SecretKey::new(random_generator);
//         let shared_secret = ecdh_x(&recipient_public_key, &secret_key);
//
//         let (encryption_key, authentication_key) = key_material(shared_secret)?;
//
//         let iv: B128 = random_generator.gen::<[u8; 16]>().into();
//
//         // encrypt message
//         let encrypted_message: &mut [u8] = message;
//         aes_encrypt(encryption_key, &mut encrypted_message[..], iv);
//         // from here and on message is encrypted
//
//         let d = hmac_sha256(
//             &authentication_key.0,
//             &[&iv.0, &encrypted_message],
//             &total_size.to_be_bytes(),
//         );
//
//         Ok(Self {
//             public_key: &PublicKey::from_secret_key(SECP256K1, &secret_key)
//                 .serialize_uncompressed(),
//             iv,
//             message: encrypted_message,
//             tag: d,
//         })
//     }
// }
//
// fn key_material(shared_secret: B256) -> Result<(B128, B256)> {
//     let mut key = [0u8; 32];
//     kdf(shared_secret, &mut key)?;
//
//     let encryption_key: B128 = B128::from_slice(&key[..16]);
//     let authentication_key = B256::from(Sha256::digest(&key[16..32]).as_ref());
//
//     Ok((encryption_key, authentication_key))
// }
//
// fn aes_encrypt(encryption_key: B128, message: &mut [u8], iv: B128) {
//     let mut cipher = Ctr64BE::<Aes128>::new(&encryption_key.0.into(), &iv.0.into());
//     cipher.apply_keystream(message);
// }
