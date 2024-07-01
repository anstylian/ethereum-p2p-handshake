use alloy_primitives::B256;
use eyre::Result;
use rand::{rngs::ThreadRng, thread_rng, Rng};
use secp256k1::{constants::SECRET_KEY_SIZE, PublicKey, Secp256k1, SecretKey};
use tokio::{
    fs::OpenOptions,
    io::{AsyncReadExt, AsyncWriteExt},
};
use tracing::{debug, info};

const NODE_KEY: &str = "eth-node-key";

#[derive(Debug)]
pub struct Initiator {
    pub(crate) secret_key: SecretKey,
    pub(crate) public_key: PublicKey,
    pub(crate) ephemeral_secret_key: SecretKey,
    pub(crate) ephemeral_public_key: PublicKey,
    pub(crate) nonce: B256,
}

impl Initiator {
    pub async fn new() -> Result<Self> {
        let random_generator = &mut thread_rng();
        let secret_key = match Self::load_secret_key().await {
            Some(secret) => {
                debug!("Load initator node secret from file.");
                secret
            }
            None => {
                debug!("Failed to load initator node secret from file.");
                info!("Generate initator node secret");
                Self::generate_secret_key(random_generator).await?
            }
        };
        let ephemeral_secret_key = SecretKey::new(random_generator);
        let secp = Secp256k1::new();
        let bytes: [u8; 32] = random_generator.gen();
        let nonce = B256::new(bytes);

        Ok(Self {
            secret_key,
            public_key: PublicKey::from_secret_key(&secp, &secret_key),
            ephemeral_secret_key,
            ephemeral_public_key: PublicKey::from_secret_key(&secp, &ephemeral_secret_key),
            nonce,
        })
    }

    async fn load_secret_key() -> Option<SecretKey> {
        let mut file = OpenOptions::new().read(true).open(NODE_KEY).await.ok()?;
        let buf = &mut [0u8; SECRET_KEY_SIZE];
        file.read(buf).await.ok()?;
        let secret = SecretKey::from_slice(buf).ok()?;
        Some(secret)
    }

    async fn generate_secret_key(random_generator: &mut ThreadRng) -> Result<SecretKey> {
        let secret = SecretKey::new(random_generator);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(NODE_KEY)
            .await?;
        file.write(secret.as_ref()).await?;
        file.flush().await?;

        Ok(secret)
    }
}
