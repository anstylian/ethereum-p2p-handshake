use eyre::Result;
use std::net::SocketAddr;

use nom::{
    bytes::complete::{tag, take_until},
    IResult,
};

#[derive(Debug, PartialEq, Eq)]
pub struct Enode {
    node_id: String,
    address: SocketAddr,
}

impl Enode {
    pub fn new(enode: &str) -> Result<Enode> {
        parse(enode)
    }
}

fn eat_enode(input: &str) -> IResult<&str, &str> {
    tag("enode://")(input)
}

fn node_id(input: &str) -> IResult<&str, &str> {
    take_until("@")(input)
}

fn eat_at(input: &str) -> IResult<&str, &str> {
    tag("@")(input)
}

fn parse(input: &str) -> Result<Enode> {
    let (remaining, _) = eat_enode(input).unwrap();
    let (remaining, node_id) = node_id(remaining).unwrap();
    let (ip, _) = eat_at(remaining).unwrap();

    Ok(Enode {
        node_id: node_id.to_owned(),
        address: ip.parse()?,
    })
}

#[cfg(test)]
mod enode_test {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{parse, Enode};

    #[test]
    fn parse_enode() {
        let enode_str = "enode://de9a20da2b93c827105c69b93537c95e602390d618ccb45a6c05bedcc1862751d661614db8871a72cd38505e192d02e59ec08fa7298af4dd035862b4d746c504@216.128.3.159:30404";
        let enode = Enode {
            node_id: String::from("de9a20da2b93c827105c69b93537c95e602390d618ccb45a6c05bedcc1862751d661614db8871a72cd38505e192d02e59ec08fa7298af4dd035862b4d746c504"),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(216,128,3,159)), 30404),
        };

        let res = parse(enode_str).expect("Failed to parse enode");
        assert_eq!(enode, res);
    }
}
