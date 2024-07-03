use alloy_primitives::B256;
use eyre::Result;
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::utils::secrets::generate_restorable_secret;

const NODE_KEY: &str = "eth-node-key";

#[allow(dead_code)]
#[derive(Debug)]
pub struct Initiator {
    pub(crate) secret_key: SecretKey,
    pub(crate) public_key: PublicKey,
    pub(crate) ephemeral_secret_key: SecretKey,
    pub(crate) ephemeral_public_key: PublicKey,
    pub(crate) nonce: B256,
}

impl Initiator {
    pub async fn new<R: Rng>(random_generator: &mut R) -> Result<Self> {
        let secret_key = generate_restorable_secret(random_generator, NODE_KEY).await?;

        Ok(Self::new_inner(secret_key, random_generator))
    }

    fn new_inner<R: Rng>(secret_key: SecretKey, random_generator: &mut R) -> Self {
        let ephemeral_secret_key = SecretKey::new(random_generator);
        let secp = Secp256k1::new();
        let nonce = B256::new(random_generator.gen::<[u8; 32]>());

        Self {
            secret_key,
            public_key: PublicKey::from_secret_key(&secp, &secret_key),
            ephemeral_secret_key,
            ephemeral_public_key: PublicKey::from_secret_key(&secp, &ephemeral_secret_key),
            nonce,
        }
    }

    #[cfg(test)]
    pub async fn test_new<R: Rng, P: AsRef<std::path::Path>>(
        random_generator: &mut R,
        secret_backup: P,
    ) -> Result<Self> {
        let secret_key = generate_restorable_secret(random_generator, secret_backup).await?;
        Ok(Self::new_inner(secret_key, random_generator))
    }
}
