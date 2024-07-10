use alloy_primitives::hex::FromHex;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use crate::{error::Result, utils::NodeId};

#[derive(Debug, PartialEq, Eq)]
pub struct Enode {
    node_id: NodeId,
    address: SocketAddr,
}

impl Enode {
    pub fn new(enode: &str) -> Result<Enode> {
        enode.parse()
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }
}

impl FromStr for Enode {
    type Err = crate::error::Error;

    fn from_str(input: &str) -> Result<Self> {
        enode_parser::parse(input)
    }
}

mod enode_parser {
    use crate::error::Error;

    use super::*;

    use nom::{
        bytes::complete::{tag, take_until},
        character::complete::digit1,
        combinator::{complete, map_res},
        sequence, IResult,
    };

    fn enode(input: &str) -> IResult<&str, &str> {
        tag("enode://")(input)
    }

    fn node_id(input: &str) -> IResult<&str, NodeId> {
        let (remaining, node_id) = take_until("@")(input)?;
        let node_id = NodeId::from_hex(node_id).map_err(|_| {
            nom::Err::Failure(nom::error::Error {
                input,
                code: nom::error::ErrorKind::Fail,
            })
        })?;

        Ok((remaining, node_id))
    }

    fn at(input: &str) -> IResult<&str, &str> {
        tag("@")(input)
    }

    fn numbers<T: FromStr>(input: &str) -> IResult<&str, T> {
        let mut parser = map_res(digit1, T::from_str);
        parser(input)
    }

    fn ip(input: &str) -> IResult<&str, SocketAddr> {
        let (remaining, (n1, _, n2, _, n3, _, n4, _, port)) = complete(sequence::tuple((
            numbers::<u8>,
            tag("."),
            numbers::<u8>,
            tag("."),
            numbers::<u8>,
            tag("."),
            numbers::<u8>,
            tag(":"),
            numbers::<u16>,
        )))(input)?;

        Ok((
            remaining,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(n1, n2, n3, n4)), port),
        ))
    }

    pub(crate) fn parse(input: &str) -> Result<Enode> {
        let (_remaining, (_, node_id, _, address)) =
            complete(sequence::tuple((enode, node_id, at, ip)))(input).map_err(|e| {
                Error::EnodeParse(format!(
                    "Failed to parse enode: {input:?}. nom error: {e:?}"
                ))
            })?;

        Ok(Enode { node_id, address })
    }
}

#[cfg(test)]
mod enode_test {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn parse_enode() {
        let enode_str = "enode://de9a20da2b93c827105c69b93537c95e602390d618ccb45a6c05bedcc1862751d661614db8871a72cd38505e192d02e59ec08fa7298af4dd035862b4d746c504@216.128.3.159:30404";
        let enode = Enode {
            node_id: NodeId::from_hex("de9a20da2b93c827105c69b93537c95e602390d618ccb45a6c05bedcc1862751d661614db8871a72cd38505e192d02e59ec08fa7298af4dd035862b4d746c504").expect("Failed to get node id"),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(216,128,3,159)), 30404),
        };

        let res = Enode::new(enode_str).expect("Failed to parse enode");
        assert_eq!(enode, res);
    }
}
