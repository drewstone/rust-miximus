extern crate sapling_crypto;
extern crate bellman;
extern crate pairing;
extern crate ff;
extern crate num_bigint;
extern crate num_traits;
extern crate rand;
extern crate time;
extern crate wasm_bindgen;

#[macro_use]
extern crate serde_derive;

use wasm_bindgen::prelude::*;

use bellman::{
    Circuit,
    SynthesisError,
    ConstraintSystem,
};

use ff::{Field, PrimeField};
use sapling_crypto::{
    babyjubjub::{
        JubjubEngine,
    },
    circuit::{
        num::{AllocatedNum},
        baby_pedersen_hash,
        boolean::{Boolean, AllocatedBit}
    }
};

use pairing::{bn256::{Fr}};

mod merkle_tree;
mod zk_util;

use zk_util::{generate, prove, verify};

/// Circuit for proving knowledge of preimage of leaf in merkle tree
struct MerkleTreeCircuit<'a, E: JubjubEngine> {
    // nullifier
    nullifier: Option<E::Fr>,
    // secret
    secret: Option<E::Fr>,
    proof: Vec<Option<(bool, E::Fr)>>,
    params: &'a E::Params,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: JubjubEngine> Circuit<E> for MerkleTreeCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // nullifier is the left side of the preimage
        let nullifier = AllocatedNum::alloc(cs.namespace(|| "nullifier"),
            || Ok(match self.nullifier {
                Some(n) => n,
                None => E::Fr::zero(),
            })
        )?;
        nullifier.inputize(cs.namespace(|| "public input nullifier"))?;
        // secret is the right side of the preimage
        let secret = AllocatedNum::alloc(cs.namespace(|| "secret"),
            || Ok(match self.secret {
                Some(s) => s,
                None => E::Fr::zero(),
            })
        )?;
        // construct preimage using [nullifier_bits|secret_bits] concatenation
        let nullifier_bits = nullifier.into_bits_le_strict(cs.namespace(|| "nullifier bits")).unwrap().into_iter().take(Fr::NUM_BITS as usize);
        let secret_bits = secret.into_bits_le_strict(cs.namespace(|| "secret bits")).unwrap().into_iter().take(Fr::NUM_BITS as usize);
        let mut preimage = vec![];
        preimage.extend(nullifier_bits);
        preimage.extend(secret_bits);
        // compute leaf hash using pedersen hash of preimage
        let mut hash = baby_pedersen_hash::pedersen_hash(
            cs.namespace(|| "computation of leaf pedersen hash"),
            baby_pedersen_hash::Personalization::NoteCommitment,
            &preimage,
            self.params
        )?.get_x().clone();
        // reconstruct merkle root hash using the private merkle path
        for i in 0..self.proof.len() {
			match self.proof[i] {
                Some((ref side, ref element)) => {
                    let elt = AllocatedNum::alloc(cs.namespace(|| format!("elt {}", i)), || Ok(*element))?;
                    let right_side = Boolean::from(AllocatedBit::alloc(
                        cs.namespace(|| format!("position bit {}", i)),
                        Some(*side)).unwrap()
                    );
                    println!("\nElement is on right side{:?}\nElement\n{:?}", right_side.get_value(), element);
                    // Swap the two if the current subtree is on the right
                    let (xl, xr) = AllocatedNum::conditionally_reverse(
                        cs.namespace(|| format!("conditional reversal of preimage {}", i)),
                        &elt,
                        &hash,
                        &right_side
                    )?;
                    println!("Reversed pair\n{:?}\n{:?}", xl.get_value(), xr.get_value());
                    let mut preimage = vec![];
                    preimage.extend(xl.into_bits_le(cs.namespace(|| format!("xl into bits {}", i)))?);
                    preimage.extend(xr.into_bits_le(cs.namespace(|| format!("xr into bits {}", i)))?);
                    // Compute the new subtree value
                    let personalization = baby_pedersen_hash::Personalization::MerkleTree(i as usize);
                    println!("CIRCUIT PERSONALIZATION: {:?}", i);;
                    hash = baby_pedersen_hash::pedersen_hash(
                        cs.namespace(|| format!("computation of pedersen hash {}", i)),
                        personalization,
                        &preimage,
                        self.params
                    )?.get_x().clone(); // Injective encoding
                    println!("IN CIRCUIT {:?}", hash.get_value().unwrap().to_string());
                },
                None => (),
            }
        }

        hash.inputize(cs.namespace(|| "merkle root hash"))?;
        Ok(())
    }
}

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen(catch)]
pub fn generate_tree(seed_slice: &[u32]) -> Result<JsValue, JsValue> {
    let res = generate(seed_slice);
    if res.is_ok() {
        Ok(JsValue::from_serde(&res.ok().unwrap()).unwrap())
    } else {
        Err(JsValue::from_str(&res.err().unwrap().to_string()))
    }
}

#[wasm_bindgen(catch)]
pub fn prove_tree(
    seed_slice: &[u32],
    params: &str,
    nullifier_hex: &str,
    secret_hex: &str,
    root_hex: &str,
    proof_path_hex: &str,
    proof_path_sides: &str
) -> Result<JsValue, JsValue> {
    let res = prove(seed_slice, params, nullifier_hex, secret_hex, root_hex, proof_path_hex, proof_path_sides);
    if res.is_ok() {
        Ok(JsValue::from_serde(&res.ok().unwrap()).unwrap())
    } else {
        Err(JsValue::from_str(&res.err().unwrap().to_string()))
    }
}

#[wasm_bindgen(catch)]
pub fn verify_tree(
    params: &str,
    proof: &str,
    nullifier_hex: &str,
    root_hex: &str
) -> Result<JsValue, JsValue> {
    let res = verify(params, proof, nullifier_hex, root_hex);
    if res.is_ok() {
        Ok(JsValue::from_serde(&res.ok().unwrap()).unwrap())
    } else {
        Err(JsValue::from_str(&res.err().unwrap().to_string()))
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use pairing::{bn256::{Bn256, Fr}};
    use sapling_crypto::{
        babyjubjub::{
            JubjubBn256,
        }
    };
    use rand::{XorShiftRng, SeedableRng};

    use sapling_crypto::circuit::{
        test::TestConstraintSystem
    };
    use bellman::{
        Circuit,
    };
    use rand::Rand;

    use super::{MerkleTreeCircuit, generate, prove, verify};
    use merkle_tree::{create_leaf_list, create_leaf_from_preimage, build_merkle_tree_with_proof};
    use time::PreciseTime;

    #[test]
    fn test_merkle_circuit() {
        let mut cs = TestConstraintSystem::<Bn256>::new();
        let mut seed : [u32; 4] = [0; 4];
        seed.copy_from_slice(&[1u32, 1u32, 1u32, 1u32]);
        let rng = &mut XorShiftRng::from_seed(seed);
        println!("generating setup...");
        let start = PreciseTime::now();
        
        let mut proof_vec = vec![];
        for _ in 0..32 {
            proof_vec.push(Some((
                true,
                Fr::rand(rng))
            ));
        }

        let j_params = &JubjubBn256::new();
        let m_circuit = MerkleTreeCircuit {
            params: j_params,
            nullifier: Some(Fr::rand(rng)),
            secret: Some(Fr::rand(rng)),
            proof: proof_vec,
        };

        m_circuit.synthesize(&mut cs).unwrap();
        println!("setup generated in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        println!("num constraints: {}", cs.num_constraints());
        println!("num inputs: {}", cs.num_inputs());
    }

    #[test]
    fn test_wasm_fns() {
        let mut cs = TestConstraintSystem::<Bn256>::new();
        let mut seed : [u32; 4] = [0; 4];
        seed.copy_from_slice(&[1u32, 1u32, 1u32, 1u32]);
        let rng = &mut XorShiftRng::from_seed(seed);
        println!("generating setup...");
        let start = PreciseTime::now();
        
        let nullifier = Fr::rand(rng);
        let secret = Fr::rand(rng);
        let leaf = create_leaf_from_preimage(nullifier, secret);

        let mut leaves = vec![*leaf.hash()];
        for i in 0..7 {
            leaves.push(Fr::rand(rng));
        }
        let tree_nodes = create_leaf_list(leaves, 3);
        let (_r, proof_vec) = build_merkle_tree_with_proof(tree_nodes, 3, 3, *leaf.hash(), vec![]);

        let j_params = &JubjubBn256::new();
        let m_circuit = MerkleTreeCircuit {
            params: j_params,
            nullifier: Some(nullifier),
            secret: Some(secret),
            proof: proof_vec,
        };
        m_circuit.synthesize(&mut cs).unwrap();
        println!("setup generated in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        println!("num constraints: {}", cs.num_constraints());
        println!("num inputs: {}", cs.num_inputs());
    }

    #[test]
    fn test_generate_params() {
        let mut cs = TestConstraintSystem::<Bn256>::new();
        let mut seed : [u32; 4] = [0; 4];
        seed.copy_from_slice(&[1u32, 1u32, 1u32, 1u32]);
        let rng = &mut XorShiftRng::from_seed(seed);
        println!("generating setup...");
        let start = PreciseTime::now();
        
        let nullifier = Fr::rand(rng);
        let secret = Fr::rand(rng);
        let leaf = *create_leaf_from_preimage(nullifier, secret).hash();
        println!("Nullifer\n{:?}\nSecret\n{:?}Leaf\n{:?}", nullifier, secret, leaf);
        let mut leaves = vec![leaf];
        for _ in 0..7 {
            leaves.push(Fr::rand(rng));
        }
        println!("\n{:?}", leaves);
        let tree_nodes = create_leaf_list(leaves, 3);
        let (_r, proof) = build_merkle_tree_with_proof(tree_nodes, 3, 3, leaf, vec![]);

        let j_params = &JubjubBn256::new();
        let m_circuit = MerkleTreeCircuit {
            params: j_params,
            nullifier: Some(nullifier),
            secret: Some(secret),
            proof: proof.clone(),
        };
        m_circuit.synthesize(&mut cs).unwrap();

        println!("\nProof\n{:?}", proof);
        let nullifier_hex = &nullifier.to_hex();
        let secret_hex = &secret.to_hex();
        let root_hex = &_r.root.hash().to_hex();
        let mut proof_path_hex: String = "".to_string();
        let mut proof_path_sides: String = "".to_string();
        for inx in 0..proof.len() {
            match proof[inx] {
                Some((right_side, pt)) => {
                    proof_path_hex.push_str(&pt.to_hex());
                    proof_path_sides.push_str(if right_side { &"1" } else { &"0" });
                },
                None => {},
            }
        }
        println!("{:?}\n{:?}\n{:?}\n{:?}\n{:?}", nullifier_hex, secret_hex, root_hex, proof_path_hex, proof_path_sides);
        let params = generate(&seed).unwrap().params;
        let ppproof = prove(
            &seed,
            &params,
            nullifier_hex,
            secret_hex,
            root_hex,
            &proof_path_hex,
            &proof_path_sides,
        ).unwrap();
        print!("\nProof proof\n{:?}\n", ppproof.proof);
        fs::write("test/test.params", params).unwrap();
        fs::write("test/test.proof", ppproof.proof).unwrap();
        let parameters = &String::from_utf8(fs::read("test/test.params").unwrap()).unwrap();
        let proofameters = &String::from_utf8(fs::read("test/test.proof").unwrap()).unwrap();
        
        // let h = &String::from_utf8(fs::read("test/test_tree.h").unwrap()).unwrap();
        let verify = verify(parameters, proofameters, &nullifier_hex, &root_hex).unwrap();
        
        println!("Did the circuit work!? {:?}", verify.result);
    }


    use merkle_tree::compute_root_from_proof;

    #[test]
    fn test_proof_creation() {
        let mut seed : [u32; 4] = [0; 4];
        seed.copy_from_slice(&[1u32, 1u32, 1u32, 1u32]);
        let start = PreciseTime::now();    
        let rng = &mut XorShiftRng::from_seed(seed);
        println!("\nsetup generated in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);

        let target_leaf = Fr::rand(rng);
        println!("random target created in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        let mut leaves: Vec<pairing::bn256::Fr> = vec![1,2,3,4,5,6,7].iter().map(|_| Fr::rand(rng)).collect();
        println!("leaves created in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        leaves.push(target_leaf);
        println!("leaves pushed in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        let tree_nodes = create_leaf_list(leaves, 3);
        println!("leaf list generated in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        let (_r, proof) = build_merkle_tree_with_proof(tree_nodes, 3, 3, target_leaf, vec![]);
        println!("tree proof generated in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        let _computed_root = compute_root_from_proof(target_leaf, proof);
        println!("computed root generated in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        assert!(_computed_root == *_r.root.hash());
    }

    #[test]
    fn test_nullifier_proof() {
        let mut seed : [u32; 4] = [0; 4];
        seed.copy_from_slice(&[1u32, 1u32, 1u32, 1u32]);
        let start = PreciseTime::now();    
        let rng = &mut XorShiftRng::from_seed(seed);
        println!("\nsetup generated in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);

        let nullifier = Fr::rand(rng);
        let secret = Fr::rand(rng);
        let leaf = *create_leaf_from_preimage(nullifier, secret).hash();
        println!("\nrandom target created in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        let mut leaves = vec![leaf];
        for _ in 0..7 {
            leaves.push(Fr::rand(rng));
        }
        println!("\nleaves created in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        println!("\nleaves pushed in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        let tree_nodes = create_leaf_list(leaves, 3);
        println!("\nleaf list generated in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        let (_r, proof) = build_merkle_tree_with_proof(tree_nodes, 3, 3, leaf, vec![]);
        println!("\nProof\n{:?}", proof);
        println!("\nRoot\n{:?}", *_r.root.hash());
        println!("\ntree proof generated in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        let _computed_root = compute_root_from_proof(leaf, proof);
        println!("\ncomputed root generated in {} s\n\n", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        println!("\nComputed root{:?}\n", _computed_root);
        assert!(_computed_root == *_r.root.hash());
    }
}
