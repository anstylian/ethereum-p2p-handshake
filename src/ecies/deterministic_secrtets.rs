use alloy_primitives::B256;
use eyre::Result;
use rand::{rngs::ThreadRng, thread_rng, Rng};
use secp256k1::{constants::SECRET_KEY_SIZE, PublicKey, Secp256k1, SecretKey};
use tokio::{
    fs::OpenOptions,
    io::{AsyncReadExt, AsyncWriteExt},
};
use tracing::{debug, info};

use super::initiator::Initiator;

const INITATOR_KEY: &str = "deterministic-keys/initator";
const EPHEMERAL_INITATOR_KEY: &str = "deterministic-keys/ephemeral-initator";
const INITATOR_NONCE: &str = "deterministic-keys/initator-nonce";

pub struct DeterministicInitiator(Initiator);

impl DeterministicInitiator {
    pub async fn new() -> Result<Self> {
        let random_generator = &mut thread_rng();
        let secret_key = match Self::load_secret_key(INITATOR_KEY).await {
            Some(secret) => {
                debug!("Load initator node secret from file.");
                secret
            }
            None => {
                debug!("Failed to load initator node secret from file.");
                info!("Generate initator node secret");
                Self::generate_secret_key(INITATOR_KEY, random_generator).await?
            }
        };

        let ephemeral_secret_key = match Self::load_secret_key(EPHEMERAL_INITATOR_KEY).await {
            Some(secret) => {
                debug!("Load initator node secret from file.");
                secret
            }
            None => {
                debug!("Failed to load initator node secret from file.");
                info!("Generate initator node secret");
                Self::generate_secret_key(INITATOR_KEY, random_generator).await?
            }
        };

        let nonce = match Self::load_nonce(INITATOR_NONCE).await {
            Some(secret) => {
                debug!("Load initator node secret from file.");
                secret
            }
            None => {
                debug!("Failed to load initator node secret from file.");
                info!("Generate initator node secret");
                Self::generate_nonce(INITATOR_NONCE, random_generator).await?
            }
        };

        let secp = Secp256k1::new();

        Ok(Self {
            0: Initiator {
                secret_key,
                public_key: PublicKey::from_secret_key(&secp, &secret_key),
                ephemeral_secret_key,
                ephemeral_public_key: PublicKey::from_secret_key(&secp, &ephemeral_secret_key),
                nonce,
            },
        })
    }

    async fn load_secret_key(filename: &str) -> Option<SecretKey> {
        let mut file = OpenOptions::new().read(true).open(filename).await.ok()?;
        let buf = &mut [0u8; SECRET_KEY_SIZE];
        file.read(buf).await.ok()?;
        let secret = SecretKey::from_slice(buf).ok()?;
        Some(secret)
    }

    async fn generate_secret_key(
        filename: &str,
        random_generator: &mut ThreadRng,
    ) -> Result<SecretKey> {
        let secret = SecretKey::new(random_generator);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(filename)
            .await?;
        file.write(secret.as_ref()).await?;
        file.flush().await?;

        Ok(secret)
    }

    async fn load_nonce(filename: &str) -> Option<B256> {
        let mut file = OpenOptions::new().read(true).open(filename).await.ok()?;
        let buf = &mut [0u8; 32];
        file.read(buf).await.ok()?;
        Some(B256::from_slice(buf))
    }

    async fn generate_nonce(filename: &str, random_generator: &mut ThreadRng) -> Result<B256> {
        let bytes: [u8; 32] = random_generator.gen();
        let nonce = B256::new(bytes);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(filename)
            .await?;
        file.write(nonce.as_ref()).await?;
        file.flush().await?;

        Ok(nonce)
    }
}
