# rust-miximus

This repo contains a MVP, WASM compatible zkSNARK of barrywhitehat's original [Miximus](https://github.com/barryWhiteHat/miximus). Details of the construction are as follows.

## Miximus
Miximus is an anonymous cryptocurrency mixer using zkSNARKs. A full implementation allows users to deposit coins into a smart contract as in Ethereum or blockchain runtime as in Substrate, create a leaf in a merkle tree with some secret data, and then withdraw these coins anonymously by providing a zkSNARK over data in the merkle tree. The proof allows a valid depositor to prove they deposited coins into the merkle tree without enforcing that the withdrawer show which leaf they are proving over.

## Double-spend protection
To use Miximus on a blockchain, one must ensure participants cannot double spend/withdraw coins. This is done by using a zkSNARK that proves knowledge of a preimage _P_ for a leaf _L_ in a merkle tree _T_ such that _P_ is the concatenation of a nullifier _N_ and a secret _S_.

The private inputs of the zkSNARK are:
1. The secret _S_.
2. The merkle authentication path _PATH_.

The public inputs of the zkSNARK are:
1. The nullifier _N_.
2. The merkle root _T_.

The zkSNARK ensures in zero-knowledge that _HASH(N|S)_ is a valid leaf by using it to reconstruct _T_ using an authentication path _PATH_.