# Ethereum P2P Handshake

## The Inital Handshake
(This information comes from: [The RLPx Transport Protocol](https://github.com/ethereum/devp2p/blob/master/rlpx.md#initial-handshake))
* Initiator: The node who opens a connection toward onother node.
* Recipient: The node who accepts the connection.
During this handshake the initiator and the recipient needs to agree on session keys to continue with encrypted and authenticated communication.

Steps:

1. Initiator connects to recipient.
2. Initiator sends an `auth` message.
3. Recipient accepts
4. Recipient decrypts and verifies `auth`.
5. Recipient derives secrets
6. Recipient sends is first encrypted frame containing the `Hello` message.
7. Initiator receives `auth-ack`.
8. Initiator derives secrects.
9. Initiator sends its first encrypted frame, contianing the `Hello` message.
10. Initiator receives and authenticates first encrypted frame(`Hello`).
11. Recipient receives and authenticates first encrypted frame(`Hello`).
12. Handshage is completed if MAC of the first encrypted frame is valid on both slides.

This implementation stops after the `Hello` Message is received, authenticated and decrypted succefully with means that the handshake is completed.

## How to run?
This crate provides two binaries the `handshake` and the `ping-pong` binary.

### The `handshake` binary

Connects to the specified nodes, performs the handshake and exits.

The program accepts a list of ethereum enode values. Enode is in this format: 
```text
enode://[Node Id]@[IP]:[Port]
```

To run the program, get your executable either with `cargo run --bin handshake`, `cargo build -p handshake` or `nix build` and provide the following argument:
```text
enode://c19700c990e87b12c14de8bc793f31783db88128edda1b3eb199ee962986768a743b9160d1630b22a16be564bd14bc4e529026a5843c7350567b0f6b1c7e786b@193.16.246.17:30303  enode://ca18afd8fe3fe3129dffad99f1ac0445f95cb5ce58c6fae51cea5b9b8ddc4264f25be0becd4bdba950488c6ae986a946f11c53f381fa037669c2d97bf39bfaf7@116.202.174.111:30304  enode://a2a3213adcca1bc739de08973056c6ba2a692de5f9d61c7d336668e70b860fd45d40e2194a121baa42c32991749497a92ef1db7b3a42b7c55fab5195de74f468@37.60.248.95:30303  enode://0ad90a4c36571672352b70d84b179f472c75d8aaa6ee286bd394eb33c476c7fa4406875731e2ea5de69df42313050109f7370c139e0a9c8c086c510ff98f0627@171.66.161.42:31404 enode://57daa54baefa66c9ef29ddb3c2e995fe7dee4bb8370436c39e97c5abbf4da84bb69d94ce8517ceb172f43caa9449469cced56994727a7409c72c307a5d078408@130.61.239.252:30303
```
Then the program will start a handshake process with each of the recipient nodes.
For each node that the handshake is completed succefully you will see the following log:
```text
INFO handshake: Handshake completed succesfully addr=[RECIPIENT SOCK ADDR]
```

FYI: I notice that if you try to handshake with a node too frquently then the handshake procedure will fail.

### The `handshake` binary

This binary goes one step further and performs 10 ping-pong's exchange with the recipient node.

The program accepts a list of ethereum enode values. Enode is in this format: 
```text
enode://[Node Id]@[IP]:[Port]
```

For this is better to use a local node of `reth`. 


## Nix Flake
If you are using `nix` you can create a development environment using `nix develop`.

To build the project using `nix` you can run `nix build`.

To generate the docs you can uses `nix build .#ethereum-p2p-handshake.doc`.
