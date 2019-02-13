/// Binary Tree where leaves hold a stand-alone value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tree {
    Empty {
        hash: pairing::bn256::Fr,
        parent: Option<Box<Tree>>,
    },
    Node {
        hash: pairing::bn256::Fr,
        left: &Tree,
        right: &Tree,
        parent: &Tree,
    },
}

impl Tree {
    /// Returns a hash from the tree.
    pub fn hash(&self) -> &pairing::bn256::Fr {
        match *self {
            Tree::Empty { ref hash, .. } => hash,
            Tree::Node { ref hash, .. } => hash,
        }
    }
}