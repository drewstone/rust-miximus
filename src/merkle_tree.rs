use MerkleTreeCircuit;
use std::error::Error;


use num_bigint::BigInt;
use num_traits::Num;

use rand::{ChaChaRng, SeedableRng};
use ff::{BitIterator, PrimeField, PrimeFieldRepr, Field};
use pairing::{bn256::{Bn256, Fr}};
use sapling_crypto::{
    babyjubjub::{
        fs::Fs,
        JubjubBn256,
        FixedGenerators,
        JubjubEngine,
        JubjubParams,
        edwards::Point
    },
    circuit::{
        baby_ecc::fixed_base_multiplication,
        boolean::{self, AllocatedBit, Boolean},
        num
    }
};



pub fn build_merkle_tree(mut leaves: Vec<pairing::bn256::Fr>, depth: usize) -> pairing::bn256::Fr {
	if leaves.len() == 2 {
		return hash_leaf_pair(depth, leaves[0], leaves[1]);
	}
	while (2 << depth) - leaves.len() > 0 {
		leaves.push(pairing::bn256::Fr::zero());
	}

	let mut new_leaves: Vec<pairing::bn256::Fr> = vec![];
    for i in 0..leaves.len() {
    	if i % 2 != 0 { continue }
        let lhs = leaves[i];
        let rhs = leaves[i+1];
        let cur = hash_leaf_pair(i, lhs, rhs);
        new_leaves.push(cur);
    }

	return build_merkle_tree(new_leaves, depth - 1);
}

fn hash_leaf_pair(index: usize, lhs: pairing::bn256::Fr, rhs: pairing::bn256::Fr) -> pairing::bn256::Fr {
	let params = &JubjubBn256::new();
    let mut lhs: Vec<bool> = BitIterator::new(lhs.into_repr()).collect();
    let mut rhs: Vec<bool> = BitIterator::new(rhs.into_repr()).collect();
    lhs.reverse();
    rhs.reverse();
	sapling_crypto::baby_pedersen_hash::pedersen_hash::<Bn256, _>(
        sapling_crypto::baby_pedersen_hash::Personalization::MerkleTree(index),
        lhs.into_iter()
           .take(Fr::NUM_BITS as usize)
           .chain(rhs.into_iter().take(Fr::NUM_BITS as usize)),
        params
    ).into_xy().0
}