use aes::Aes256;
use alloy_primitives::{B128, B256};
use alloy_rlp::{Decodable, Encodable};
use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr64BE;
use eyre::{eyre, Result};
use rand::Rng;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::Digest;
use tracing::{instrument, trace};

use crate::{
    mac::Mac,
    messages::{
        auth::AuthBody,
        auth_ack::AuthAck,
        hello::{Capability, Hello},
        Disconnect, MessageDecryptor, Ping, Pong,
    },
    parties::{initiator::Initiator, recipient::ConnectedRecipient},
    utils::{aes_encrypt, ecdh_x, hmac_sha256, id2pk, key_material, pk2id},
};

/// This is handling the communication between the initiator and the recipient
pub struct Connection<'a, R: rand::Rng> {
    initiator: &'a Initiator,
    recipient: ConnectedRecipient,

    outbound_message: Option<Bytes>,
    inbound_message: Option<Bytes>,

    ephemeral_shared_secret: Option<B256>,

    ingress_aes: Option<Ctr64BE<Aes256>>,
    egress_aes: Option<Ctr64BE<Aes256>>,

    ingress_mac: Option<Mac>,
    egress_mac: Option<Mac>,

    random_generator: R,
    body_size: Option<usize>,
}

impl<'a, R: Rng> Connection<'a, R> {
    pub fn new(
        initiator: &'a Initiator,
        recipient: ConnectedRecipient,
        random_generator: R,
    ) -> Self {
        Self {
            initiator,
            recipient,
            outbound_message: None,
            inbound_message: None,
            ephemeral_shared_secret: None,
            ingress_aes: None,
            egress_aes: None,
            ingress_mac: None,
            egress_mac: None,
            random_generator,
            body_size: None,
        }
    }

    /// send the auth message
    /// Steps:
    /// 1. Prepare the raw message
    /// 2. Encrypt the message
    /// 3. Send it
    #[instrument(skip_all)]
    pub async fn send_auth_message(&mut self) -> Result<()> {
        let buf = self.generate_auth_message()?;

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

        trace!("received auth ack {:02x}", msg);

        self.read_auth_ack(&mut msg)?;

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<()> {
        let mut msg = self
            .recipient
            .recv()
            .await
            .ok_or(eyre!("No message received"))?;

        self.inbound_message = Some(Bytes::copy_from_slice(&msg[..]));
        trace!("received auth ack {:02x}", msg);

        self.read_message(&mut msg)?;
        Ok(())
    }

    pub async fn sent_hello(&mut self) -> Result<()> {
        let mut hello = self.create_hello();
        let buf = self.write_frame(hello.as_mut());

        self.recipient.send(buf).await?;

        Ok(())
    }

    pub async fn sent_ping(&mut self) -> Result<()> {
        let mut ping = self.create_ping();
        let buf = self.write_frame(ping.as_mut());

        self.recipient.send(buf).await?;

        Ok(())
    }

    // TODO: pub here is only needed fo testing
    #[instrument(skip_all)]
    pub fn generate_auth_message(&mut self) -> Result<BytesMut> {
        let mut auth_body = AuthBody::message(&self.recipient, self.initiator);
        // add pading
        auth_body.resize(
            auth_body.len() + self.random_generator.gen_range(100..=300),
            0,
        );

        trace!(
            "Created auth-body unencrypted (this is RLP format): {:02x}",
            auth_body
        );

        let mut encrypted = BytesMut::new();

        // encrypt buffer
        self.encrypt(&mut auth_body[..], &mut encrypted)?;

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
    fn encrypt(&mut self, message: &mut [u8], out: &mut BytesMut) -> Result<u16> {
        let total_size: u16 = u16::try_from(
            secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE  // Public key size
                + 16                                            // Size of iv
                + message.len()                                 // Unencrypted message
                + 32, // Tag Size
        )
        .unwrap();

        let secret_key = SecretKey::new(&mut self.random_generator);
        let shared_secret = ecdh_x(self.recipient.public_key(), &secret_key);

        let (encryption_key, authentication_key) = key_material(shared_secret)?;

        let iv: B128 = self.random_generator.gen::<[u8; 16]>().into();

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

        out.extend_from_slice(&total_size.to_be_bytes());
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
        self.inbound_message = Some(Bytes::copy_from_slice(&message[..]));

        let decrypt_message = self.decrypt_message(message)?;
        trace!("decrypted AuthAck: {decrypt_message:02x?}");

        let auth_ack = AuthAck::decode(&mut decrypt_message.as_ref())?;
        trace!("received auth ack {:02x?}", auth_ack);

        self.recipient.set_nonce(auth_ack.nonce().into());

        self.recipient
            .set_ephemeral_public_key(id2pk(auth_ack.id().into())?);

        self.ephemeral_shared_secret = Some(ecdh_x(
            self.recipient.ephemeral_public_key()?,
            self.initiator.ephemeral_secret_key(),
        ));

        self.setup_frame(false)?;
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

    fn read_message(&mut self, message: &mut BytesMut) -> Result<()> {
        // read header
        trace!("Message: {:02x}", message);
        self.read_header(message)?;
        let _header = message.split_to(32);
        trace!("Message body: {:02x}", message);
        let frame = self.read_body(message, self.body_size.unwrap())?;
        trace!("{:02x?}", frame);

        let (mut message_id, mut message) = frame.split_at(1);

        let message_id: u8 = u8::decode(&mut message_id)?;
        trace!("message_id: {:?}", message_id);

        match message_id {
            0 => {
                trace!("Hello: {message:02x?}");
                let hello: Hello = Hello::decode(&mut message)?;
                trace!("Hello message from target node: {:?}", hello);
            }
            1 => {
                trace!("Disconnect: {message:02x?}");
                let disconnect = Disconnect::decode(&mut message)?;
                trace!("Disconnect: {:?}", disconnect);
            }
            2 => {
                trace!("Ping: {message:02x?}");
                let ping = Ping::decode(&mut message)?;
                trace!("Ping: {:?}", ping);
            }
            3 => {
                trace!("Pong: {message:02x?}");
                let pong = Pong::decode(&mut message)?;
                trace!("Pong: {:?}", pong);
            }
            _ => todo!(),
        }

        println!("remaining message: {:02x?}", message);

        Ok(())
    }

    fn create_hello(&self) -> BytesMut {
        let mut hello = BytesMut::new();
        let capabilities = vec![Capability::new("eth".to_string(), 68)];
        Hello::new(
            "test-client".to_string(),
            capabilities,
            0,
            *pk2id(self.initiator.public_key()),
        )
        .encode(&mut hello);

        hello
    }

    fn create_ping(&self) -> BytesMut {
        let mut ping = BytesMut::new();
        Ping {}.encode(&mut ping);

        ping
    }

    fn write_frame(&mut self, message: &mut [u8]) -> BytesMut {
        let mut out = BytesMut::new();
        let mut buf = [0u8; 8];

        BigEndian::write_uint(&mut buf, message.len() as u64, 3);
        let mut header = [0u8; 16];
        header[..3].copy_from_slice(&buf[..3]);
        header[3..6].copy_from_slice(&[194, 128, 128]);

        self.egress_aes
            .as_mut()
            .unwrap()
            .apply_keystream(&mut header);
        self.egress_mac
            .as_mut()
            .unwrap()
            .update_header(&B128::from_slice(&header));
        let tag = self.egress_mac.as_mut().unwrap().digest();

        out.reserve(32);
        out.extend_from_slice(&header[..]);
        out.extend_from_slice(tag.as_slice());

        let len = if message.len() % 16 == 0 {
            message.len()
        } else {
            (message.len() / 16 + 1) * 16
        };
        let old_len = out.len();
        out.resize(old_len + len, 0);

        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..message.len()].copy_from_slice(message);

        self.egress_aes.as_mut().unwrap().apply_keystream(encrypted);
        self.egress_mac.as_mut().unwrap().update_body(encrypted); // TODO: check this
        let tag = self.egress_mac.as_mut().unwrap().digest();

        out.extend_from_slice(tag.as_slice());

        out
    }

    pub fn read_header(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < 32 {
            return Err(eyre::eyre!(
                "Header is too small. Needs at lease 32 bytes for header + mac"
            ));
        }

        let (header, rest) = buf.split_at_mut(16);
        let mut header: B128 = B128::from_slice(header);

        let (mac_bytes, _rest) = rest.split_at_mut(16);
        let mac = B128::from_slice(mac_bytes);

        self.ingress_mac.as_mut().unwrap().update_header(&header);
        let current_mac = self.ingress_mac.as_mut().unwrap().digest();
        if current_mac != mac {
            return Err(eyre!("Header MAC check failed"));
        }

        self.ingress_aes
            .as_mut()
            .unwrap()
            .apply_keystream(header.as_mut_slice());
        if header.as_slice().len() < 3 {
            return Err(eyre!("Invalid header"));
        }

        let mut frame_size = (BigEndian::read_uint(header.as_ref(), 3) + 16) as usize; // frame size + 16 bytes Frame MAC
        let padding = frame_size % 16;
        if padding > 0 {
            frame_size += 16 - padding;
        }
        trace!("Body size: {:?}", frame_size);

        self.body_size = Some(frame_size);

        Ok(())
    }

    pub fn read_body(&mut self, buf: &mut [u8], frame_size: usize) -> Result<Vec<u8>> {
        let (frame, _rest) = buf.split_at_mut(frame_size as usize);

        let (frame, frame_mac) = frame.split_at_mut(frame_size.checked_sub(16).unwrap());
        let frame_mac = B128::from_slice(frame_mac);
        self.ingress_mac.as_mut().unwrap().update_body(frame);
        let current_mac = self.ingress_mac.as_mut().unwrap().digest();
        trace!("current_mac: {:02x}", current_mac);
        trace!("frame_mac: {:02x}", frame_mac);
        if current_mac != frame_mac {
            return Err(eyre!("Frame MAC check failed"));
        }

        self.ingress_aes.as_mut().unwrap().apply_keystream(frame);

        Ok(frame.to_vec())
    }

    pub fn body_size(&self) -> usize {
        self.body_size.unwrap()
    }

    #[cfg(test)]
    pub fn decrypt_message_auth(&mut self, message: &'a mut BytesMut) -> Result<&'a mut [u8]> {
        let auth_message = self.decrypt_message(message)?;

        Ok(auth_message)
        // Ok(auth_message)
    }

    fn setup_frame(&mut self, incoming: bool) -> Result<()> {
        let mut hasher = sha3::Keccak256::new();
        if incoming {
            for e in [self.initiator.nonce(), self.recipient.nonce()?] {
                hasher.update(e);
            }
        } else {
            for e in [self.recipient.nonce()?, self.initiator.nonce()] {
                hasher.update(e);
            }
        }

        let h_nonce = alloy_primitives::B256::from(hasher.finalize().as_ref());

        let iv = B128::default();
        let shared_secret: B256 = {
            let mut hasher = sha3::Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0);
            hasher.update(h_nonce.0.as_ref());
            B256::from(hasher.finalize().as_ref())
        };

        let aes_secret: B256 = {
            let mut hasher = sha3::Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(shared_secret.0.as_ref());
            B256::from(hasher.finalize().as_ref())
        };

        self.ingress_aes = Some(ctr::Ctr64BE::<aes::Aes256>::new(
            (&aes_secret.0).into(),
            (&iv.0).into(),
        ));
        self.egress_aes = Some(ctr::Ctr64BE::<aes::Aes256>::new(
            (&aes_secret.0).into(),
            (&iv.0).into(),
        ));

        let mac_secret: B256 = {
            let mut hasher = sha3::Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(aes_secret.0.as_ref());
            B256::from(hasher.finalize().as_ref())
        };
        self.ingress_mac = Some(crate::mac::Mac::new(mac_secret));
        self.ingress_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ *self.initiator.nonce()).as_ref());
        self.ingress_mac
            .as_mut()
            .unwrap()
            .update(self.inbound_message.as_ref().unwrap());
        self.egress_mac = Some(Mac::new(mac_secret));
        self.egress_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ *self.recipient.nonce().unwrap()).as_ref());
        self.egress_mac
            .as_mut()
            .unwrap()
            .update(self.outbound_message.as_ref().unwrap());

        Ok(())
    }
}
