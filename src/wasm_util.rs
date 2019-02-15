extern crate wasm_bindgen;
extern crate sapling_crypto;
extern crate bellman;
extern crate pairing;
extern crate ff;
extern crate num_bigint;
extern crate num_traits;
extern crate rand;
extern crate time;

use wasm_bindgen::prelude::*;
use MerkleTreeCircuit;
use num_bigint::BigInt;
use num_traits::Num;
use std::error::Error;
use sapling_crypto::{
    babyjubjub::{
        JubjubBn256
    }
};
use bellman::{
    groth16::{
        Proof, Parameters, verify_proof, create_random_proof, prepare_verifying_key, generate_random_parameters
    }
};

use rand::{XorShiftRng, SeedableRng};
use ff::{PrimeField};
use pairing::{bn256::{Bn256, Fr}};
use sapling_crypto::{
    jubjub::{
        fs::Fs,
    },
};

use merkle_tree::{
    create_leaf_list,
    build_merkle_tree_with_proof,
};

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[derive(Serialize)]
pub struct KGGenerate {
    pub params: String
}

#[derive(Serialize)]
pub struct KGProof {
    pub proof: String,
    // pub nullifier: String,
    // pub secret: String,
    // pub leaf: String,
    // pub path: Vec<String>
}

#[derive(Serialize)]
pub struct KGVerify {
    pub result: bool
}

#[wasm_bindgen(catch)]
pub fn generate(seed_slice: &[u32]) -> Result<JsValue, JsValue> {
    let res = || -> Result<JsValue, Box<Error>> {
        let mut seed : [u32; 4] = [0; 4];
        seed.copy_from_slice(seed_slice);
        let rng = &mut XorShiftRng::from_seed(seed);

        let j_params = &JubjubBn256::new();
        let params = generate_random_parameters::<Bn256, _, _>(
            MerkleTreeCircuit {
                params: j_params,
                nullifier: None,
                secret: None,
                leaf: None,
                root: None,
                proof: vec![],
            },
            rng,
        )?;

        let mut v = vec![];

        params.write(&mut v)?;

        Ok(JsValue::from_serde(&KGGenerate {
            params: hex::encode(&v[..])
        })?)
    }();
    convert_error_to_jsvalue(res)
}

#[wasm_bindgen(catch)]
pub fn prove(seed_slice: &[u32], params: &str, nullifier_hex: &str, secret_hex: &str, leaf_hex: &str, root_hex: &str, proof_path_hex: Vec<&str>, proof_path_sides: &[bool]) -> Result<JsValue, JsValue> {
    let res = || -> Result<JsValue, Box<Error>> {
        if params.len() == 0 {
            return Err("Params are empty. Did you generate or load params?".into())
        }
        let de_params = Parameters::<Bn256>::read(&hex::decode(params)?[..], true)?;
        let j_params = &JubjubBn256::new();

        let mut seed : [u32; 4] = [0; 4];
        seed.copy_from_slice(seed_slice);
        let rng = &mut XorShiftRng::from_seed(seed);
        let params = &JubjubBn256::new();

        let s = &format!("{}", Fs::char())[2..];
        let s_big = BigInt::from_str_radix(s, 16)?;
        // Nullifier
        let nullifier_big = BigInt::from_str_radix(nullifier_hex, 16)?;
        if nullifier_big >= s_big {
            return Err("nullifier should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
        }
        let nullifier_raw = &nullifier_big.to_str_radix(10);
        let nullifier = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
        let nullifier_s = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
        // Secret preimage data
        let secret_big = BigInt::from_str_radix(secret_hex, 16)?;
        if secret_big >= s_big {
            return Err("secret should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
        }
        let secret_raw = &secret_big.to_str_radix(10);
        let secret = Fr::from_str(secret_raw).ok_or("couldn't parse Fr")?;
        let secret_s = Fr::from_str(secret_raw).ok_or("couldn't parse Fr")?;
        // Leaf hash
        let leaf_big = BigInt::from_str_radix(leaf_hex, 16)?;
        if leaf_big >= s_big {
            return Err("leaf should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
        }
        let leaf_raw = &leaf_big.to_str_radix(10);
        let leaf = Fr::from_str(leaf_raw).ok_or("couldn't parse Fr")?;
        let leaf_s = Fr::from_str(leaf_raw).ok_or("couldn't parse Fr")?;
        // Root hash
        let root_big = BigInt::from_str_radix(root_hex, 16)?;
        if root_big >= s_big {
            return Err("root should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
        }
        let root_raw = &root_big.to_str_radix(10);
        let root = Fr::from_str(root_raw).ok_or("couldn't parse Fr")?;
        let root_s = Fr::from_str(root_raw).ok_or("couldn't parse Fr")?;
        // Proof path
        // let mut proof_path_hx = proof_path_hex;
        // proof_path_hx.iter().map(|p|  std::str::from_utf8(p));
        let mut proof_p_big = vec![];
        for inx in 0..proof_path_hex.len() {
            let p_big = BigInt::from_str_radix(proof_path_hex[inx], 16)?;
            if p_big >= s_big {
                return Err("root should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
            }
            let p_raw = &p_big.to_str_radix(10);
            let p = Fr::from_str(p_raw).ok_or("couldn't parse Fr")?;
            let p_s = Fr::from_str(p_raw).ok_or("couldn't parse Fr")?;
            proof_p_big.push(Some((
                proof_path_sides[inx],
                p,
            )));
        }

        let proof = create_random_proof(
            MerkleTreeCircuit {
                params: j_params,
                nullifier: Some(nullifier),
                secret: Some(secret),
                leaf: Some(leaf),
                root: Some(root),
                proof: proof_p_big,
            },
            &de_params,
            rng
        )?;

        let mut v = vec![];
        proof.write(&mut v)?;

        Ok(JsValue::from_serde(&KGProof {
            proof: hex::encode(&v[..]),
        })?)
    }();

    convert_error_to_jsvalue(res)
}

#[wasm_bindgen(catch)]
pub fn verify(params: &str, proof: &str, nullifier_hex: &str, root_hex: &str) -> Result<JsValue, JsValue> {
    let res = || -> Result<JsValue, Box<Error>> {
        let de_params = Parameters::read(&hex::decode(params)?[..], true)?;
        let j_params = &JubjubBn256::new();
        let pvk = prepare_verifying_key::<Bn256>(&de_params.vk);


        let s = &format!("{}", Fs::char())[2..];
        let s_big = BigInt::from_str_radix(s, 16)?;
        // Nullifier
        let nullifier_big = BigInt::from_str_radix(nullifier_hex, 16)?;
        if nullifier_big >= s_big {
            return Err("x should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
        }
        let nullifier_raw = &nullifier_big.to_str_radix(10);
        let nullifier = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
        let nullifier_s = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
        // Root hash
        let root_big = BigInt::from_str_radix(root_hex, 16)?;
        if root_big >= s_big {
            return Err("x should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
        }
        let root_raw = &root_big.to_str_radix(10);
        let root = Fr::from_str(root_raw).ok_or("couldn't parse Fr")?;
        let root_s = Fr::from_str(root_raw).ok_or("couldn't parse Fr")?;


        let result = verify_proof(
            &pvk,
            &Proof::read(&hex::decode(proof)?[..])?,
            &[
                nullifier,
                root
            ])?;

        Ok(JsValue::from_serde(&KGVerify{
            result: result
        })?)
    }();
    convert_error_to_jsvalue(res)
}

fn convert_error_to_jsvalue(res: Result<JsValue, Box<Error>>) -> Result<JsValue, JsValue> {
    if res.is_ok() {
        Ok(res.ok().unwrap())
    } else {
        Err(JsValue::from_str(&res.err().unwrap().to_string()))
    }
}