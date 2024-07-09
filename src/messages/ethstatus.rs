use alloy_rlp::{RlpDecodable, RlpEncodable};
use rand::{thread_rng, Rng};

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct ForkId {
    hash: u32,
    next: u64,
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct EthStatus {
    version: u8,
    networkid: u64,
    td: u128,
    blockhash: [u8; 32],
    genesis: [u8; 32],
    forkid: ForkId,
}
// pub struct EthStatus {
//     version: u8,
//     networkid: u64,
//     td: [u8; 32],
//     blockhash: [u8; 32],
//     genesis: [u8; 32],
//     // forkid: Vec<ForkId>,
// }

impl EthStatus {
    pub fn new() -> Self {
        let mut genesis = [0u8; 32];
        hex::decode_to_slice(
            "2f980576711e3617a5e4d83dd539548ec0f7792007d505a3d2e9674833af2d7c",
            &mut genesis,
        )
        .unwrap();
        // hex::decode_to_slice(
        //     "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
        //     &mut genesis,
        // )
        // .unwrap();
        Self {
            version: 68,
            // networkid: 1,
            networkid: 1337,
            td: 0,
            blockhash: genesis,
            genesis,
            forkid: ForkId {
                hash: 0x45b83612,
                next: 0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_rlp::{Decodable, Encodable};

    use super::EthStatus;

    #[tokio::test]
    async fn parse_ethstatus() {
        // let eth_status_left = EthStatus::new();
        //
        // let mut buf = vec![];
        // eth_status_left.encode(&mut buf);
        // println!("encoded: {:02x?}", buf);
        // let eth_staths_right =
        //     EthStatus::decode(&mut buf.as_slice()).expect("EthStatus decode failed");
        //
        // assert_eq!(eth_status_left, eth_staths_right);

        let mut buf = hex::decode("f84e4482053980a02f980576711e3617a5e4d83dd539548ec0f7792007d505a3d2e9674833af2d7ca02f980576711e3617a5e4d83dd539548ec0f7792007d505a3d2e9674833af2d7cc68445b8361280").unwrap();
        // let mut buf = hex::decode("f8474482053980a02f980576711e3617a5e4d83dd539548ec0f7792007d505a3d2e9674833af2d7ca02f980576711e3617a5e4d83dd539548ec0f7792007d505a3d2e9674833af2d7c").unwrap();
        // let mut buf = hex::decode("c444820539").unwrap();
        // let mut buf = hex::decode("c54482053980").unwrap();
        // let mut buf = hex::decode(
        //     "e64482053980a02f980576711e3617a5e4d83dd539548ec0f7792007d505a3d2e9674833af2d7c",
        // )
        // .unwrap();
        // let mut buf = hex::decode(
        // "f8474482053980a02f980576711e3617a5e4d83dd539548ec0f7792007d505a3d2e9674833af2d7ca02f980576711e3617a5e4d83dd539548ec0f7792007d505a3d2e9674833af2d7c"
        // )
        // .unwrap();

        // let rlp = rlp::Rlp::new(&buf[..]);
        // let version: u8 = rlp.val_at(0).unwrap();
        // let twochain: u64 = rlp.val_at(1).unwrap();
        // let td: Vec<u8> = rlp.val_at(2).unwrap();
        // let hash: Vec<u8> = rlp.val_at(3).unwrap();
        // let genesis: Vec<u8> = rlp.val_at(4).unwrap();
        //
        // println!("{version:?}");
        // println!("{twochain:?}");
        // println!("{:?} {td:?}", td.len());
        // println!("{hash:?}");
        // println!("{genesis:?}");

        // let five: Vec<u8> = rlp.val_at(4).unwrap();
        //
        let eth_staths = EthStatus::decode(&mut buf.as_ref());
        println!("{:#?}", eth_staths);
    }
}
