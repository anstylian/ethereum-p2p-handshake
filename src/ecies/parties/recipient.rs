use alloy_primitives::B256;
use bytes::{BufMut, BytesMut};
use eyre::{eyre, Result};
use secp256k1::PublicKey;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::timeout;
use tracing::{error, instrument, trace, warn};

use crate::enode::Enode;
use crate::utils::{id2pk, NodeId};

/// Connection timeout in seconds
const CONNECTION_TIMEOUT: u64 = 30;

pub struct StreamMessage(BytesMut);

#[derive(Debug)]
pub struct RecipientDefinition {
    public_key: PublicKey,
    id: NodeId,
    address: SocketAddr,
}

impl RecipientDefinition {
    pub fn new(enode: Enode) -> Result<Self> {
        Ok(Self {
            public_key: id2pk(enode.node_id())?,
            id: enode.node_id(),
            address: enode.address(),
        })
    }

    #[instrument(skip_all)]
    pub async fn connect(self) -> Result<ConnectedRecipient> {
        trace!("Connecting to {}", self.address);
        let stream = timeout(
            Duration::from_secs(CONNECTION_TIMEOUT),
            TcpStream::connect(self.address),
        )
        .await??;

        Ok(ConnectedRecipient::new(self.public_key, self.id, stream))
    }

    #[cfg(test)]
    pub fn port(&mut self, port: u16) {
        use std::net::{IpAddr, Ipv4Addr};

        self.address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    }
}

#[allow(unused)]
pub struct ConnectedRecipient {
    public_key: PublicKey,
    id: NodeId,
    tx: UnboundedSender<StreamMessage>,
    rx: UnboundedReceiver<StreamMessage>,
    read_task: tokio::task::JoinHandle<Result<()>>,
    write_task: tokio::task::JoinHandle<Result<()>>,
    ephemeral_public_key: Option<PublicKey>,
    nonce: Option<B256>,
}

impl ConnectedRecipient {
    pub fn new(public_key: PublicKey, id: NodeId, stream: TcpStream) -> ConnectedRecipient {
        let (reader_tx, reader_rx) = mpsc::unbounded_channel();
        let (writer_tx, writer_rx) = mpsc::unbounded_channel();

        let (reader, writer) = stream.into_split();

        let read_task = tokio::task::spawn(stream_reader(reader, reader_tx));
        let write_task = tokio::task::spawn(stream_writer(writer, writer_rx));

        Self {
            public_key,
            id,
            tx: writer_tx,
            rx: reader_rx,
            read_task,
            write_task,
            ephemeral_public_key: None,
            nonce: None,
        }
    }

    pub fn abort(&mut self) {
        self.read_task.abort();
        self.write_task.abort();
    }

    pub async fn send(&self, buf: BytesMut) -> Result<()> {
        self.tx.send(StreamMessage(buf))?;
        Ok(())
    }

    pub(crate) async fn recv(&mut self) -> Option<BytesMut> {
        // Ok(self.rx.recv().await?.0)
        self.rx.recv().await.map(|m| m.0)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn id(&self) -> &NodeId {
        &self.id
    }

    pub fn ephemeral_public_key(&self) -> Result<&PublicKey> {
        self.ephemeral_public_key
            .as_ref()
            .ok_or(eyre!("Recipient public key is not initialized"))
    }

    pub fn nonce(&self) -> Result<&B256> {
        self.nonce
            .as_ref()
            .ok_or(eyre!("Recipient public key is not initialized"))
    }

    pub fn set_nonce(&mut self, nonce: B256) {
        self.nonce = Some(nonce);
    }

    pub fn set_ephemeral_public_key(&mut self, public_key: PublicKey) {
        self.ephemeral_public_key = Some(public_key);
    }
}
// TODO: reading packages needs refactor. There are possible errors
// TODO: close the streams

#[instrument(skip_all)]
pub async fn stream_reader(
    reader: OwnedReadHalf,
    reader_tx: UnboundedSender<StreamMessage>,
) -> Result<()> {
    let mut buf = BytesMut::with_capacity(1024 * 8); // 8KB
    let mut first = true;
    loop {
        let ready = reader.ready(Interest::READABLE).await?;
        if ready.is_readable() {
            // Try to read data, this may still fail with `WouldBlock`
            // if the readiness event is a false positive.
            match reader.try_read_buf(&mut buf) {
                Ok(0) => {
                    error!("TCP stream closed"); // TODO: remove this
                    std::process::exit(-1);
                }
                Ok(n) => {
                    warn!("-->Bytes read {n}");

                    let mut total_read = 0;
                    if first {
                        let len =
                            u16::from_be_bytes([buf[total_read], buf[total_read + 1]]) as usize + 2;
                        trace!("Received first package of len {:?}", len);
                        let mut m = BytesMut::new();
                        m.put(&buf[total_read..(total_read + len)]);

                        total_read += len;

                        reader_tx.send(StreamMessage(m))?;
                        // let m = BytesMut::new(message[total_read..(total_read + len)]);
                    }

                    first = false;

                    let mut m = BytesMut::new();
                    m.put(&buf[total_read..]);
                    reader_tx.send(StreamMessage(m))?;

                    buf.clear();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    error!("Read failed with: {e:?}");
                    return Err(e.into());
                }
            }
        }
    }
}

/// Handle outcoming messages to the connection.
#[instrument(skip_all)]
pub async fn stream_writer(
    writer: OwnedWriteHalf,
    writer_rx: UnboundedReceiver<StreamMessage>,
) -> Result<()> {
    let mut writer = writer;
    let mut writer_rx = writer_rx;
    while let Some(msg) = writer_rx.recv().await {
        let buf = msg;
        let ready = writer.ready(Interest::WRITABLE).await?;
        if ready.is_writable() {
            loop {
                match writer.try_write(&buf.0) {
                    Ok(n) if n < buf.0.len() => {
                        // TODO: this should be handle
                        warn!("Only a part of the buffer is send. Data will be missing");
                        break;
                    }
                    Ok(_) => {
                        trace!("Bytes writter ok to stream");
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => {
                        error!("Write failed with: {e:?}");
                        return Err(e.into());
                    }
                }
            }
            writer.flush().await?;
        }
    }

    Ok(())
}

#[cfg(test)]
impl TryFrom<super::initiator::Initiator> for RecipientDefinition {
    type Error = eyre::Error;

    fn try_from(initiator: super::initiator::Initiator) -> Result<Self> {
        let initiator_enode = initiator.enode()?;
        Self::new(initiator_enode)
    }
}

// #[cfg(test)]
// pub struct TestRecipient {
//     public_key: PublicKey,
//     id: NodeId,
// }
//
// #[cfg(test)]
// impl TestRecipient {
//     pub fn new(definition: RecipientDefinition) -> Self {
//         Self {
//             public_key: definition.public_key,
//             id: definition.id,
//         }
//     }
// }
//
// #[cfg(test)]
// impl Recipient for TestRecipient {
//     fn public_key(&self) -> &PublicKey {
//         &self.public_key
//     }
//
//     fn id(&self) -> &NodeId {
//         &self.id
//     }
// }
