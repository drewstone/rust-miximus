use ff::{BitIterator, PrimeField, Field};
use pairing::{bn256::{Bn256, Fr}};
use sapling_crypto::{
    babyjubjub::{
        JubjubBn256,
    },
};

use tree::Tree;

#[derive(Debug)]
pub struct MerkleTree {
    pub root: Tree,
}

pub fn create_leaf_from_preimage(nullifier: pairing::bn256::Fr, secret: pairing::bn256::Fr) -> Tree {
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
        parent: None,
    };
}

pub fn create_leaf_list(mut nodes: Vec<pairing::bn256::Fr>, depth: usize) -> Vec<Box<Tree>> {
    for _ in 0..((2 << (depth - 1)) - nodes.len()) {
        nodes.push(<pairing::bn256::Fr>::zero());
    }

    let mut tree_nodes: Vec<Box<Tree>> = vec![];
    for i in 0..nodes.len() {
        tree_nodes.push(Box::new(Tree::Empty {
            hash: nodes[i],
            parent: None,
        }));
    }

    return tree_nodes;
}

pub fn build_merkle_tree(mut nodes: Vec<Box<Tree>>, depth: usize) -> MerkleTree {
    if nodes.len() == 2 {
        let left = nodes.remove(0);
        let right = nodes.remove(0);
        return MerkleTree {
            root: *hash_leaf_pair(depth, *left, *right),
        };
    }

    for _ in 0..((2 << (depth - 1)) - nodes.len()) {
        nodes.push(Box::new(Tree::Empty {
            hash: <pairing::bn256::Fr>::zero(),
            parent: None
        }));
    }

    let mut next_nodes: Vec<Box<Tree>> = vec![];
    for i in 0..nodes.len() {
        if i % 2 != 0 { continue }
        let left = nodes.remove(0);
        let right = nodes.remove(0);
        let cur = hash_leaf_pair(i, *left, *right);
        next_nodes.push(cur);
    }

    return build_merkle_tree(next_nodes, depth - 1);
}

pub fn build_merkle_tree_with_proof(
    mut nodes: Vec<Box<Tree>>,
    depth: usize,
    mut target_node: pairing::bn256::Fr,
    mut curr_list: Vec<Option<(bool, pairing::bn256::Fr)>>
) -> (MerkleTree, Vec<Option<(bool, pairing::bn256::Fr)>>) {
    if nodes.len() == 2 {
        let left = nodes.remove(0);
        let right = nodes.remove(0);
        if target_node == *left.hash() {
            curr_list.push(Some((true, *right.hash())));
        } else {
            curr_list.push(Some((false, *left.hash())));
        }

        return (
            MerkleTree { root: *hash_leaf_pair(depth, *left, *right) },
            curr_list,
        );
    }

    for _ in 0..((2 << (depth - 1)) - nodes.len()) {
        nodes.push(Box::new(Tree::Empty {
            hash: <pairing::bn256::Fr>::zero(),
            parent: None,
        }));
    }

    let mut new_nodes: Vec<Box<Tree>> = vec![];
    for i in 0..nodes.len() {
        if i % 2 != 0 { continue }
        let left = nodes.remove(0);
        let right = nodes.remove(0);
        let mut temp_bool = false;
        if target_node == *left.hash() {
            curr_list.push(Some((true, *right.hash())));
            temp_bool = true;

        }

        if target_node == *right.hash() {
            curr_list.push(Some((false, *left.hash())));
            temp_bool = true;
        }

        let cur = hash_leaf_pair(depth, *left, *right);
        if temp_bool {
            target_node = *cur.hash();
        }
        new_nodes.push(cur);
    }

    return build_merkle_tree_with_proof(new_nodes, depth - 1, target_node, curr_list);
}

pub fn hash_leaf_pair(index: usize, lhs: Tree, rhs: Tree) -> Box<Tree> {
    let params = &JubjubBn256::new();
    let mut lhs_bool: Vec<bool> = BitIterator::new((lhs).hash().into_repr()).collect();
    let mut rhs_bool: Vec<bool> = BitIterator::new((rhs).hash().into_repr()).collect();
    lhs_bool.reverse();
    rhs_bool.reverse();
    let hash = sapling_crypto::baby_pedersen_hash::pedersen_hash::<Bn256, _>(
        sapling_crypto::baby_pedersen_hash::Personalization::MerkleTree(index),
        lhs_bool.clone().into_iter()
           .take(Fr::NUM_BITS as usize)
           .chain(rhs_bool.clone().into_iter().take(Fr::NUM_BITS as usize)),
        params
    ).into_xy().0;
    return Box::new(Tree::Node {
        hash: hash,
        left: Box::new(lhs),
        right: Box::new(rhs),
        parent: None,
    });
}

pub fn compute_root_from_proof(leaf: pairing::bn256::Fr, path: Vec<Option<(bool, pairing::bn256::Fr)>>) -> pairing::bn256::Fr {
    let mut hash = leaf;
    for i in 0..path.len() {
        match path[i] {
            Some((right_side, pt)) => {
                if right_side {
                    hash = *hash_leaf_pair(
                        path.len() - i,
                        Tree::Empty { hash: hash, parent: None },
                        Tree::Empty { hash: pt, parent: None })
                    .hash();
                } else {
                    hash = *hash_leaf_pair(
                        path.len() - i,
                        Tree::Empty { hash: pt, parent: None },
                        Tree::Empty { hash: hash, parent: None })
                    .hash();
                }
            },
            None => {},
        }
    }

    return hash;
}

pub fn print_merkle_tree(tree: &Tree) {
    match tree {
        Tree::Node { hash: _, ref left, ref right, parent: _ } => {
            print_merkle_tree(left);
            print_merkle_tree(right);
            println!("{:?}, {:?}, {:?}", left.hash(), right.hash(), tree.hash());
        },
        _ => { return },
    }
}

#[cfg(test)]
mod test {
    use merkle_tree::compute_root_from_proof;
    use merkle_tree::create_leaf_list;
    use merkle_tree::build_merkle_tree_with_proof;
    use merkle_tree::print_merkle_tree;
    use tree::Tree;
    use rand::Rand;
    use super::build_merkle_tree;
    use pairing::{bn256::{Fr}};
    use rand::{XorShiftRng, SeedableRng};
    use time::PreciseTime;

    #[test]
    fn test_merkle_tree() {
        let _r: Tree = build_merkle_tree(vec![], 3).root;
    }

    #[test]
    fn test_proof_creation() {
        let mut seed : [u32; 4] = [0; 4];
        seed.copy_from_slice(&[1u32, 1u32, 1u32, 1u32]);
        let start = PreciseTime::now();    
        let rng = &mut XorShiftRng::from_seed(seed);
        println!("\nsetup generated in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);

        let target_leaf = Fr::rand(rng);
        println!("\nrandom target created in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        let mut leaves: Vec<pairing::bn256::Fr> = vec![1,2,3,4,5,6,7].iter().map(|_| Fr::rand(rng)).collect();
        println!("\nleaves created in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        leaves.push(target_leaf);
        println!("\nleaves pushed in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        let tree_nodes = create_leaf_list(leaves, 3);
        println!("\nleaf list generated in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        let (_r, proof) = build_merkle_tree_with_proof(tree_nodes, 3, target_leaf, vec![]);
        println!("\ntree proof generated in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        print_merkle_tree(&_r.root);
        let _computed_root = compute_root_from_proof(target_leaf, proof);
        println!("\ncomputed root generated in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        assert!(_computed_root == *_r.root.hash())
    }
}