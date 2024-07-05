//! THIS file is copied from reth
//!
//! # Ethereum MAC Module
//!
//! This module provides the implementation of the Ethereum MAC (Message Authentication Code)
//! construction, as specified in the Ethereum `RLPx` protocol.
//!
//! The Ethereum MAC is a nonstandard MAC construction that utilizes AES-256 (as a block cipher)
//! and Keccak-256. It is specifically designed for messages of 128 bits in length and is not
//! intended for general MAC use.
//!
//! For more information, refer to the [Ethereum MAC specification](https://github.com/ethereum/devp2p/blob/master/rlpx.md#mac).

use aes::Aes256Enc;
use alloy_primitives::{B128, B256};
use block_padding::NoPadding;
use cipher::BlockEncrypt;
use digest::KeyInit;
use sha3::{Digest, Keccak256};

/// [`Ethereum MAC`](https://github.com/ethereum/devp2p/blob/master/rlpx.md#mac) state.
///
/// The ethereum MAC is a cursed MAC construction.
///
/// The ethereum MAC is a nonstandard MAC construction that uses AES-256 (without a mode, as a
/// block cipher) and Keccak-256. However, it only ever encrypts messages that are 128 bits long,
/// and is not defined as a general MAC.
#[derive(Debug)]
pub struct Mac {
    secret: B256,
    hasher: Keccak256,
}

impl Mac {
    /// Initialize the MAC with the given secret
    pub fn new(secret: B256) -> Self {
        Self {
            secret,
            hasher: Keccak256::new(),
        }
    }

    /// Update the internal keccak256 hasher with the given data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data)
    }

    /// Accumulate the given [`HeaderBytes`] into the MAC's internal state.
    pub fn update_header(&mut self, data: &B128) {
        let aes = Aes256Enc::new_from_slice(self.secret.as_ref()).unwrap();
        let mut encrypted = self.digest().0;

        aes.encrypt_padded::<NoPadding>(&mut encrypted, B128::len_bytes())
            .unwrap();
        for i in 0..data.len() {
            encrypted[i] ^= data[i];
        }
        self.hasher.update(encrypted);
    }

    /// Accumulate the given message body into the MAC's internal state.
    pub fn update_body(&mut self, data: &[u8]) {
        self.hasher.update(data);
        let prev = self.digest();
        let aes = Aes256Enc::new_from_slice(self.secret.as_ref()).unwrap();
        let mut encrypted = self.digest().0;

        aes.encrypt_padded::<NoPadding>(&mut encrypted, B128::len_bytes())
            .unwrap();
        for i in 0..16 {
            encrypted[i] ^= prev[i];
        }
        self.hasher.update(encrypted);
    }

    /// Produce a digest by finalizing the internal keccak256 hasher and returning the first 128
    /// bits.
    pub fn digest(&self) -> B128 {
        B128::from_slice(&self.hasher.clone().finalize()[..16])
    }
}