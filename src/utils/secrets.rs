//! This module containes secrets generation related functionality.
//! The perpose of this module is to be able to generate random secrets,
//! but also deterministic secrets. Deterministic secrets are needed for testing.

use rand::Rng;
use secp256k1::{constants::SECRET_KEY_SIZE, SecretKey};
use std::path::Path;
use tokio::{
    fs::{create_dir_all, OpenOptions},
    io::{AsyncReadExt as _, AsyncWriteExt as _},
};

use crate::{error::Error, Result};

/// Returns a secret key and backup for reuse in later runs.
/// This is needed for the Node Identity.
/// Is described at Node Idenetiry section of [The RLPx Transport Protocol](https://github.com/ethereum/devp2p/blob/5713591d0366da78a913a811c7502d9ca91d29a8/rlpx.md?plain=1#L62)
pub async fn generate_restorable_secret<R: Rng, P: AsRef<Path>>(
    random_generator: &mut R,
    secret_backup: P,
) -> Result<SecretKey> {
    if secret_backup.as_ref().is_file() {
        let mut file = OpenOptions::new().read(true).open(secret_backup).await?;
        let buf = &mut [0u8; SECRET_KEY_SIZE];
        let n = file.read(buf).await?;

        if n != SECRET_KEY_SIZE {
            return Err(Error::Str("Failed to read full key"));
        }

        let secret = SecretKey::from_slice(buf)?;
        Ok(secret)
    } else {
        if let Some(parent) = secret_backup.as_ref().parent() {
            create_dir_all(parent).await?;
        }

        let secret = SecretKey::new(random_generator);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(secret_backup)
            .await?;

        let n = file.write(secret.as_ref()).await?;
        if n != SECRET_KEY_SIZE {
            return Err(Error::Str("Failed to write full key"));
        }

        file.flush().await?;

        Ok(secret)
    }
}
