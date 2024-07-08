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

## Nix Flake
If you are using `nix` you can create a development environment using `nix develop`.
To build the project using `nix` you can run `nix build`.
To generate the docs you can uses `nix build .#ethereum-p2p-handshake.doc`.
