use ff::{BitIterator, PrimeField, Field};
use pairing::{bn256::{Bn256, Fr}};
use sapling_crypto::{
    babyjubjub::{
        JubjubBn256,
    },
};

use tree::Tree;

#[derive(Debug)]
pub struct MerkleTree<T> {
    root: Tree<T>,
}

pub fn create_leaf_from_preimage<T>(nullifier: pairing::bn256::Fr, secret: pairing::bn256::Fr) -> Tree<T> {
    let params = &JubjubBn256::new();
    let mut lhs: Vec<bool> = BitIterator::new(nullifier.into_repr()).collect();
    let mut rhs: Vec<bool> = BitIterator::new(secret.into_repr()).collect();
    lhs.reverse();
    rhs.reverse();
    let hash = sapling_crypto::baby_pedersen_hash::pedersen_hash::<Bn256, _>(
        sapling_crypto::baby_pedersen_hash::Personalization::NoteCommitment,
        lhs.into_iter()
           .take(Fr::NUM_BITS as usize)
           .chain(rhs.into_iter().take(Fr::NUM_BITS as usize)),
        params
    ).into_xy().0;
    return Tree::Empty {
        hash: hash,
    };
}

pub fn build_merkle_tree<T>(mut leaves: Vec<Tree<T>>, depth: usize) -> MerkleTree<T> {
    if leaves.len() == 2 {
        let left = leaves.remove(0);
        let right = leaves.remove(0);
        return MerkleTree {
            root: hash_leaf_pair(depth, left, right),
        };
    }
    while (2 << depth) - leaves.len() > 0 {
        leaves.push(Tree::Empty {
            hash: <pairing::bn256::Fr>::zero(),
        });
    }

    let mut new_leaves: Vec<Tree<T>> = vec![];
    for i in 0..leaves.len() {
        if i % 2 != 0 { continue }
        let left = leaves.remove(0);
        let right = leaves.remove(0);
        let cur = hash_leaf_pair(i, left, right);
        new_leaves.push(cur);
    }

    return build_merkle_tree(new_leaves, depth - 1);
}

fn hash_leaf_pair<T>(index: usize, lhs: Tree<T>, rhs: Tree<T>) -> Tree<T> {
    let params = &JubjubBn256::new();
    let mut lhs_bool: Vec<bool> = BitIterator::new(lhs.hash().into_repr()).collect();
    let mut rhs_bool: Vec<bool> = BitIterator::new(rhs.hash().into_repr()).collect();
    lhs_bool.reverse();
    rhs_bool.reverse();
    let hash = sapling_crypto::baby_pedersen_hash::pedersen_hash::<Bn256, _>(
        sapling_crypto::baby_pedersen_hash::Personalization::MerkleTree(index),
        lhs_bool.into_iter()
           .take(Fr::NUM_BITS as usize)
           .chain(rhs_bool.into_iter().take(Fr::NUM_BITS as usize)),
        params
    ).into_xy().0;
    return Tree::Node {
        hash: hash,
        left: Box::new(lhs),
        right: Box::new(rhs),
    }
}

fn print_merkle_tree<T>(tree: &Tree<T>) {
    println!("{:?}", tree.hash());
    match tree {
        Tree::Node { hash: _, ref left, ref right } => {
            print_merkle_tree(left);
            print_merkle_tree(right);   
        },
        _ => { return },
    }
}

#[cfg(test)]
mod test {
    use merkle_tree::print_merkle_tree;
    use tree::Tree;
    use super::build_merkle_tree;
    #[test]
    fn test_merkle_tree() {
        let r: Tree<u32> = build_merkle_tree(vec![], 3).root;
        print_merkle_tree(&r)
    }
}