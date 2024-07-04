use alloy_primitives::B128;
use alloy_rlp::Decodable;
use bytes::{BufMut, Bytes, BytesMut};
use eyre::{eyre, Result};
use rand::Rng;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use tracing::{instrument, trace};

use crate::messages::auth_ack::AuthAck;
use crate::messages::MessageDecryptor;
use crate::utils::{aes_encrypt, hmac_sha256, key_material, pk2id};
use crate::{
    ecies::parties::{initiator::Initiator, recipient::ConnectedRecipient},
    messages::auth::AuthBody,
    utils::ecdh_x,
};

/// This is handling the communication between the initiator and the recipient
pub struct Connection<'a> {
    initiator: &'a Initiator,
    recipient: ConnectedRecipient,

    outbound_message: Option<Bytes>,
    inbound_message: Option<Bytes>,
}

impl<'a> Connection<'a> {
    pub fn new(initiator: &'a Initiator, recipient: ConnectedRecipient) -> Self {
        Self {
            initiator,
            recipient,
            outbound_message: None,
            inbound_message: None,
        }
    }

    /// send the auth message
    /// Steps:
    /// 1. Prepare the raw message
    /// 2. Encrypt the message
    /// 3. Send it
    #[instrument(skip_all)]
    pub async fn send_auth_message(&mut self, random_generator: &mut impl Rng) -> Result<()> {
        let buf = self.generate_auth_message(random_generator)?;

        self.recipient.send(buf).await?;

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn receive_auth_ack(&mut self) -> Result<()> {
        let mut msg = self
            .recipient
            .recv()
            .await
            .ok_or(eyre!("No message received"))?;

        self.inbound_message = Some(Bytes::copy_from_slice(&msg[..]));
        trace!("received auth ack {:02x}", msg);

        self.read_auth_ack(&mut msg)?;

        Ok(())
    }

    // TODO: pub here is only needed fo testing
    #[instrument(skip_all)]
    pub fn generate_auth_message(&mut self, random_generator: &mut impl Rng) -> Result<BytesMut> {
        let mut auth_body = AuthBody::message(&self.recipient, self.initiator);
        // add pading
        auth_body.resize(auth_body.len() + random_generator.gen_range(100..=300), 0);

        trace!(
            "Created auth-body unencrypted (this is RLP format): {:02x}",
            auth_body
        );

        let mut encrypted = BytesMut::new();

        // encrypt buffer
        self.encrypt(&mut auth_body[..], random_generator, &mut encrypted)?;
        // buf.put_slice(&len.to_be_bytes());

        // buf.unsplit(encrypted);

        self.outbound_message = Some(Bytes::copy_from_slice(&encrypted));

        Ok(encrypted)
    }

    pub fn abort(&mut self) {
        self.recipient.abort();
    }

    /// documentation fomr RLPx: https://github.com/ethereum/devp2p/blob/master/rlpx.md
    /// Alice wants to send an encrypted message that can be decrypted by Bobs static private key kB.
    /// Alice knows about Bobs static public key KB.
    ///
    /// To encrypt the message m,
    /// 1. Alice generates a random number r and corresponding elliptic curve public key R = r * G
    ///     and computes the shared secret S = Px where (Px, Py) = r * KB.
    ///
    /// 2. She derives key material for encryption and authentication as kE || kM = KDF(S, 32)
    /// 3. as well as a random initialization vector iv.
    /// 4. Alice sends the encrypted message R || iv || c || d where
    ///     c = AES(kE, iv , m)
    ///     d = MAC(sha256(kM), iv || c)
    ///     to Bob.
    fn encrypt(
        &self,
        message: &mut [u8],
        random_generator: &mut impl Rng,
        out: &mut BytesMut,
    ) -> Result<u16> {
        let total_size: u16 = u16::try_from(
            secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE  // Public key size
                + 16                                            // Size of iv
                + message.len()                                 // Unencrypted message
                + 32, // Tag Size
        )
        .unwrap();

        let secret_key = SecretKey::new(random_generator);
        let shared_secret = ecdh_x(self.recipient.public_key(), &secret_key);

        let (encryption_key, authentication_key) = key_material(shared_secret)?;

        let iv: B128 = random_generator.gen::<[u8; 16]>().into();

        // encrypt message
        let encrypted_message: &mut [u8] = message;
        aes_encrypt(encryption_key, &mut encrypted_message[..], iv);
        // from here and on message is encrypted

        // TODO: add pading

        let d = hmac_sha256(
            &authentication_key.0,
            &[&iv.0, encrypted_message],
            &total_size.to_be_bytes(),
        );

        let public_key =
            &PublicKey::from_secret_key(SECP256K1, &secret_key).serialize_uncompressed();

        out.extend_from_slice(&u16::try_from(total_size)?.to_be_bytes());
        out.extend_from_slice(public_key);
        out.extend_from_slice(iv.as_slice());
        out.extend_from_slice(encrypted_message);
        out.extend_from_slice(d.as_ref());

        if out.len() == total_size.into() {
            eyre::bail!("The encrypted message size({:?}) does not match the expected size({total_size:?}).", out.len());
        }

        Ok(total_size)
    }

    // auth-ack -> E(remote-pubk, remote-ephemeral-pubk || nonce || 0x0)
    pub fn read_auth_ack(&mut self, message: &mut BytesMut) -> Result<AuthAck> {
        let decrypt_message = self.decrypt_message(message)?;
        trace!("decrypted AuthAck: {decrypt_message:02x?}");

        let auth_ack = AuthAck::decode(&mut decrypt_message.as_ref())?;
        trace!("received auth ack {:02x?}", auth_ack);

        Ok(auth_ack)
    }

    fn decrypt_message(&self, message: &'a mut [u8]) -> Result<&'a mut [u8]> {
        let unencrypted_auth = MessageDecryptor::new(message)?;
        let (encryption_key, authentication_key) =
            unencrypted_auth.derive_keys(self.initiator.secret_key())?;
        unencrypted_auth.check_integrity(authentication_key)?;
        let m = unencrypted_auth.decrypt(encryption_key);

        Ok(m)
    }

    #[cfg(test)]
    pub fn decrypt_message_auth(&mut self, message: &'a mut BytesMut) -> Result<&'a mut [u8]> {
        let auth_message = self.decrypt_message(message)?;

        Ok(auth_message)
        // Ok(auth_message)
    }
}
