use eyre::Result;
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::utils::secrets::generate_restorable_secret;
use crate::utils::{pk2id, NodeId, Nonce};

const NODE_KEY: &str = "eth-node-key";

// TODO: use  ephemeral_public_key: PublicKey,

#[derive(Debug, Clone)]
pub struct Initiator {
    secret_key: SecretKey,
    public_key: PublicKey,
    ephemeral_secret_key: SecretKey,
    nonce: Nonce,
}

impl Initiator {
    pub async fn new<R: Rng>(random_generator: &mut R) -> Result<Self> {
        let secret_key = generate_restorable_secret(random_generator, NODE_KEY).await?;

        Ok(Self::new_inner(secret_key, random_generator))
    }

    fn new_inner<R: Rng>(secret_key: SecretKey, random_generator: &mut R) -> Self {
        let ephemeral_secret_key = SecretKey::new(random_generator);
        let secp = Secp256k1::new();
        let nonce = Nonce::new(random_generator.gen::<[u8; 32]>());

        Self {
            secret_key,
            public_key: PublicKey::from_secret_key(&secp, &secret_key),
            ephemeral_secret_key,
            nonce,
        }
    }

    pub fn node_id(&self) -> NodeId {
        pk2id(&self.public_key)
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn ephemeral_secret_key(&self) -> &SecretKey {
        &self.ephemeral_secret_key
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    // #[cfg(test)]
    // pub async fn test_new<R: Rng, P: AsRef<std::path::Path>>(
    //     random_generator: &mut R,
    //     secret_backup: P,
    // ) -> Result<Self> {
    //     let secret_key = generate_restorable_secret(random_generator, secret_backup).await?;
    //     Ok(Self::new_inner(secret_key, random_generator))
    // }

    #[cfg(test)]
    pub fn enode(&self) -> Result<crate::enode::Enode> {
        let id = pk2id(&self.public_key);

        format!("enode://{}@127.0.0.1:40404", id).as_str().parse()
    }
}
