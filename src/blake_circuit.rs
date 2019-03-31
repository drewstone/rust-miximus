#![feature(custom_attribute)]
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

use pairing::{
    Engine,
};

use bellman::{
    Circuit,
    SynthesisError,
    ConstraintSystem,
};

use ff::{Field, PrimeField};
use sapling_crypto::{
    circuit::{
        num::{AllocatedNum},
        blake2s,
        uint32::Uint32,
        boolean::{Boolean, AllocatedBit}
    }
};

mod blake_circuit;

/// Circuit for proving knowledge of preimage of leaf in merkle tree
struct BlakeTreeCircuit<'a, E: JubjubEngine> {
    // nullifier
    nullifier: Option<Uint32>,
    // blake2 personalization
    personalization: Option<Vec<u8>>,
    // secret
    secret: Option<Uint32>,
    // merkle proof
    proof: Vec<Option<(bool, Uint32)>>,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: JubjubEngine> Circuit<E> for BlakeTreeCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // nullifier is the left side of the preimage
        let nullifier = AllocatedNum::alloc(cs.namespace(|| "nullifier"),
            || Ok(match self.nullifier {
                Some(n) => n.into_bits(),
                None => UInt32::constant(0 as u32).into_bits(),
            })
        )?;
        nullifier.inputize(cs.namespace(|| "public input nullifier"))?;

        // personalization is the left side of the preimage
        let personalization = AllocatedNum::alloc(cs.namespace(|| "personalization"),
            || Ok(match self.personalization {
                Some(n) => n.to_bytes(),
                None => b"12345678",
            })
        )?;
        personalization.inputize(cs.namespace(|| "public input personalization"))?;
        // secret is the right side of the preimage
        let secret = AllocatedNum::alloc(cs.namespace(|| "secret"),
            || Ok(match self.secret {
                Some(s) => s.into_bits(),
                None => UInt32::constant(0 as u32).into_bits(),
            })
        )?;
        // construct preimage using [nullifier_bits|secret_bits] concatenation
        let mut preimage = vec![];
        preimage.extend(nullifier.into_bits());
        preimage.extend(secret.into_bits());
        // compute leaf hash using pedersen hash of preimage
        let mut hash = blake2s(&mut cs, &preimage, personalization).unwrap();


        // reconstruct merkle root hash using the private merkle path
        for i in 0..self.proof.len() {
			if let Some((ref side, ref element)) = self.proof[i] {
                let elt = AllocatedNum::alloc(cs.namespace(|| format!("elt {}", i)), || Ok(*element))?;
                let right_side = Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("position bit {}", i)),
                    Some(*side)).unwrap()
                );
                // Swap the two if the current subtree is on the right
                let (xl, xr) = AllocatedNum::conditionally_reverse(
                    cs.namespace(|| format!("conditional reversal of preimage {}", i)),
                    &elt,
                    &hash,
                    &right_side
                )?;
                // build preimage of merkle hash as concatenation of left and right nodes
                let mut preimage = vec![];
                preimage.extend(xl.into_bits());
                preimage.extend(xr.into_bits());
                // Compute the new subtree value
                let personalization = baby_pedersen_hash::Personalization::MerkleTree(i as usize);
                hash = blake2s(&mut cs, &preimage, personalization);
            }
        }

        hash.inputize(cs)?;
        println!("THE ROOT HASH {:?}", hash.get_value());
        Ok(())
    }
}

#[derive(Serialize)]
pub struct KGGenerate {
    pub params: String
}

#[derive(Serialize)]
pub struct KGProof {
    pub proof: String,
}

#[derive(Serialize)]
pub struct KGVerify {
    pub result: bool
}

pub fn generate(seed_slice: &[u32], depth: u32) -> Result<KGGenerate, Box<Error>> {
    let rng = &mut ChaChaRng::from_seed(seed_slice);
    let params = &Engine::new();
    let mut proof_elts = vec![];

    for _ in 0..depth {
        proof_elts.push(Some((
            true,
            UInt32::constant(0 as u32),
        )));
    }
    let params = generate_random_parameters::<Bn256, _, _>(
        BlakeTreeCircuit {
            params: j_params,
            personalization: None,
            nullifier: None,
            secret: None,
            proof: proof_elts,
        },
        rng,
    )?;

    let mut v = vec![];

    params.write(&mut v)?;

    Ok(KGGenerate {
        params: hex::encode(&v[..])
    })
}

pub fn prove(
    seed_slice: &[u32],
    params: &str,
    nullifier: &u32,
    secret: &u32,
    mut proof_path: &[u32],
    mut proof_path_sides: &[u8]
) -> Result<KGProof, Box<Error>> {
    let de_params = Parameters::<Bn256>::read(&hex::decode(params)?[..], true)?;
    let rng = &mut ChaChaRng::from_seed(seed_slice);
    // Nullifier
    let nullifier_big = BigInt::from_str_radix(nullifier_hex, 16)?;
    let nullifier_raw = &nullifier_big.to_str_radix(10);
    let nullifier = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
    // Secret preimage data
    let secret_big = BigInt::from_str_radix(secret_hex, 16)?;
    let secret_raw = &secret_big.to_str_radix(10);
    let secret = Fr::from_str(secret_raw).ok_or("couldn't parse Fr")?;
    // Proof path
    let mut proof_p_big: Vec<Option<(bool, pairing::bn256::Fr)>> = vec![];
    let proof_len = proof_path_sides.len();
    for _ in 0..proof_len {
        let (neighbor_i, pfh) = proof_path_hex.split_at(64);
        let (side_i, pfs) = proof_path_sides.split_at(1);
        proof_path_hex = pfh;
        proof_path_sides = pfs;
        let mut side_bool = false;
        if side_i == "1" { side_bool = true }

        let p_big = BigInt::from_str_radix(neighbor_i, 16)?;
        let p_raw = &p_big.to_str_radix(10);
        let p = Fr::from_str(p_raw).ok_or("couldn't parse Fr")?;
        proof_p_big.push(Some((
            side_bool,
            p,
        )));
    }

    let proof = create_random_proof(
        MerkleTreeCircuit {
            params: j_params,
            nullifier: Some(nullifier),
            secret: Some(secret),
            proof: proof_p_big,
        },
        &de_params,
        rng
    ).unwrap();
    println!("hello");
    let mut v = vec![];
    proof.write(&mut v)?;
    Ok(KGProof {
        proof: hex::encode(&v[..]),
    })
}

pub fn verify(params: &str, proof: &str, nullifier_hex: &str, root_hex: &str) -> Result<KGVerify, Box<Error>> {
    let de_params = Parameters::read(&hex::decode(params)?[..], true)?;
    let pvk = prepare_verifying_key::<Bn256>(&de_params.vk);
    // Nullifier
    let nullifier_big = BigInt::from_str_radix(nullifier_hex, 16)?;
    let nullifier_raw = &nullifier_big.to_str_radix(10);
    let nullifier = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
    // Root hash
    let root_big = BigInt::from_str_radix(root_hex, 16)?;
    let root_raw = &root_big.to_str_radix(10);
    let root = Fr::from_str(root_raw).ok_or("couldn't parse Fr")?;
    let result = verify_proof(
        &pvk,
        &Proof::read(&hex::decode(proof)?[..])?,
        &[
            nullifier,
            root
        ])?;

    Ok(KGVerify{
        result: result
    })
}

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen(catch)]
pub fn generate_tree(seed_slice: &[u32], depth: u32) -> Result<JsValue, JsValue> {
    let res = generate(seed_slice, depth);
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
    nullifier: &u32,
    secret: &u32,
    proof_path: &[u32],
    proof_path_sides: &[u8]
) -> Result<JsValue, JsValue> {
    let res = prove(seed_slice, params, nullifier_hex, secret_hex, proof_path_hex, proof_path_sides);
    if res.is_ok() {
        Ok(JsValue::from_serde(&res.ok().unwrap()).unwrap())
    } else {
        Err(JsValue::from_str(&res.err().unwrap().to_string()))
    }
}

#[wasm_bindgen(catch)]
pub fn verify_tree(
    params: &str,
    proof: &[u32],
    nullifier: &u32,
    root: &u32
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
    use rand::{ChaChaRng, SeedableRng};

    use sapling_crypto::circuit::{
        test::TestConstraintSystem
    };
    use bellman::{
        Circuit,
    };
    use rand::Rand;

    use super::{BlakeTreeCircuit, generate, prove, verify};
    use merkle_tree::{create_leaf_list, create_leaf_from_preimage, build_merkle_tree_with_proof};
    use time::PreciseTime;

    #[test]
    fn test_merkle_circuit() {
        let mut cs = TestConstraintSystem::<Bn256>::new();
        let seed_slice = &[1u32, 1u32, 1u32, 1u32];
        let rng = &mut ChaChaRng::from_seed(seed_slice);
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
        let m_circuit = BlakeTreeCircuit {
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
}
