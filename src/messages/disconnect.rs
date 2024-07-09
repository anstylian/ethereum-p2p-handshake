use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use bytes::BytesMut;

pub const ID: u8 = 0x1;

#[repr(u8)]
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    DisconnectReqiested = 0x0_u8,
    TcpSubSystemError = 0x1_u8,
    BreackOfProtocol = 0x2_u8,
    UselessPeers = 0x3_u8,
    TooManyPeers = 0x4_u8,
    AlreadyConnected = 0x5_u8,
    IncompatibleP2pProtocolVersion = 0x6_u8,
    NullNodeId = 0x7_u8,
    ClientQuitting = 0x8_u8,
    UnexpectedIdentityInHandshake = 0x9_u8,
    IdentityIsTheSameAsThisNode = 0xa_u8,
    PingTimeout = 0xb_u8,
    Other = 0x10u8,
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Disconnect {
    reason: usize,
}

impl Disconnect {
    pub fn new(reason: DisconnectReason) -> Self {
        Self {
            reason: reason as usize,
        }
    }

    pub fn encoded(self) -> BytesMut {
        let mut disconnect = BytesMut::new();
        ID.encode(&mut disconnect);
        self.encode(&mut disconnect);

        disconnect
    }
}

impl std::fmt::Display for Disconnect {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let reason = match self.reason {
            0x0 => "Disconnected requested",
            0x1 => "TCP sub-system error",
            0x2 => "Breach of protocol, e.g. a malformed message, bad RLP, ...",
            0x3 => "Useless peer",
            0x4 => "Too many peers",
            0x5 => "Already connected",
            0x6 => "Incompatible P2P protocol version",
            0x7 => "Null node identity received - this is automatically invalid",
            0x8 => "Client quitting",
            0x9 => "Unexpected identity in handshake",
            0xa => "Identity is the same as this node (i.e. connected to itself)",
            0xb => "Ping timeout",
            0x10 => "Some other reason specific to a subprotocol",
            _ => unreachable!(),
        };

        write!(f, "Disconnect {{ reason: {reason} }}")
    }
}
