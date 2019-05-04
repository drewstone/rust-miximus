use blake2_rfc::blake2s::{blake2s};
/// Binary Tree where leaves hold a stand-alone value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tree {
    Empty {
        hash: [u8; 32],
        parent: Option<Box<Tree>>,
    },
    Node {
        hash: [u8; 32],
        left: Box<Tree>,
        right: Box<Tree>,
        parent: Option<Box<Tree>>,
    },
}

impl Tree {
    /// Returns a hash from the tree.
    pub fn hash(&self) -> &[u8; 32] {
        match *self {
            Tree::Empty { ref hash, .. } => hash,
            Tree::Node { ref hash, .. } => hash,
        }
    }
}

#[derive(Debug)]
pub struct MerkleTree {
    pub root: Tree,
}

static ZERO_BYTES: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
pub const SUBSTRATE_BLAKE2_PERSONALIZATION: &'static [u8; 8]
          = b"TFWTFWTF";

pub fn create_leaf_from_preimage(nullifier: [u8; 32], secret: [u8; 32]) -> Tree {
    let mut hash: [u8; 32] = ZERO_BYTES;
    let mut preimage: Vec<u8> = vec![];
    preimage.extend(nullifier.into_iter());
    preimage.extend(secret.into_iter());

    hash.copy_from_slice(&blake2s(32, SUBSTRATE_BLAKE2_PERSONALIZATION, &preimage[..]).as_bytes()[0..32]);
    return Tree::Empty {
        hash: hash,
        parent: None,
    };
}

pub fn create_leaf_list(mut nodes: Vec<[u8; 32]>, depth: usize) -> Vec<Box<Tree>> {
    for _ in 0..((2 << (depth - 1)) - nodes.len()) {
        nodes.push(ZERO_BYTES.clone());
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

#[allow(dead_code)]
pub fn build_merkle_tree_with_proof(
    nodes: Vec<Box<Tree>>,
    depth: usize,
    top_depth: usize,
    target_node: [u8; 32],
    curr_list: Vec<Option<(bool, [u8; 32])>>,
) -> (MerkleTree, Vec<Option<(bool, [u8; 32])>>) {
    let ( mut new_nodes, target_node, new_curr_list ) = hash_nodes_rec(nodes, depth, top_depth, target_node, curr_list);
    if new_nodes.len() == 1 {
        let root = new_nodes.remove(0);
        return (
            MerkleTree { root: *root },
            new_curr_list,
        );
    } else {
        return build_merkle_tree_with_proof(
            new_nodes,
            depth - 1,
            top_depth,
            target_node,
            new_curr_list,
        );
    }
}

#[allow(dead_code)]
pub fn hash_nodes_rec(
    mut nodes: Vec<Box<Tree>>,
    depth: usize,
    top_depth: usize,
    mut target_node: [u8; 32],
    mut curr_list: Vec<Option<(bool, [u8; 32])>>
) -> (Vec<Box<Tree>>, [u8; 32], Vec<Option<(bool, [u8; 32])>>) {
    if nodes.len() == 2 {
        let left = nodes.remove(0);
        let right = nodes.remove(0);
        let temp_bool = target_node == *left.hash() || target_node == *right.hash();
        let mut val = vec![];
        if target_node == *left.hash() {
            val.push(Some((true, *right.hash())));
        }

        if target_node == *right.hash() {
            val.push(Some((false, *left.hash())));
        }

        let cur = hash_leaf_pair(top_depth - depth, *left, *right);
        if temp_bool {
            target_node = *cur.hash();
        }
        if depth == 1 {
            curr_list.append(&mut val);
            return (
                vec![cur],
                target_node,
                curr_list,
            );
        } else {
            return (
                vec![cur],
                target_node,
                val,
            );
        }
    } else {
        let ( mut left_new_nodes, left_target_node, mut left_new_curr_list ) = hash_nodes_rec(
            nodes[..(nodes.len() / 2)].to_vec(),
            depth,
            top_depth,
            target_node,
            curr_list.clone(),
        );
        let ( mut right_new_nodes, right_target_node, mut right_new_curr_list ) = hash_nodes_rec(
            nodes[(nodes.len() / 2)..].to_vec(),
            depth,
            top_depth,
            target_node,
            curr_list.clone(),
        );

        if left_target_node == target_node {
            target_node = right_target_node;
        } else {
            target_node = left_target_node;
        }

        left_new_nodes.append(&mut right_new_nodes);
        curr_list.append(&mut left_new_curr_list);
        curr_list.append(&mut right_new_curr_list);
        
        return (
            left_new_nodes,
            target_node,
            curr_list,
        );
    }
}

pub fn hash_leaf_pair(_index: usize, lhs: Tree, rhs: Tree) -> Box<Tree> {
    let mut hash: [u8; 32] = ZERO_BYTES;
    let mut preimage: Vec<u8> = vec![];
    preimage.extend(lhs.hash().into_iter());
    preimage.extend(rhs.hash().into_iter());
    hash.copy_from_slice(&blake2s(32, SUBSTRATE_BLAKE2_PERSONALIZATION, &preimage[..]).as_bytes()[0..32]);
    return Box::new(Tree::Node {
        hash: hash,
        left: Box::new(lhs),
        right: Box::new(rhs),
        parent: None,
    });
}

pub fn compute_root_from_proof(leaf: [u8; 32], path: Vec<Option<(bool, [u8; 32])>>) -> [u8; 32] {
    let mut hash = leaf;
    for i in 0..path.len() {
        match path[i] {
            Some((right_side, pt)) => {
                if right_side {
                    hash = *hash_leaf_pair(
                        i,
                        Tree::Empty { hash: hash, parent: None },
                        Tree::Empty { hash: pt, parent: None })
                    .hash();
                } else {
                    hash = *hash_leaf_pair(
                        i,
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
