use rand::{XorShiftRng, SeedableRng};
use bellman::groth16::{Proof, Parameters, verify_proof, create_random_proof, prepare_verifying_key, generate_random_parameters};
use num_bigint::BigInt;
use num_traits::Num;
use std::error::Error;


use ff::{PrimeField};
use sapling_crypto::{
    babyjubjub::{
        fs::Fs,
        JubjubBn256,
    },
};

use pairing::{bn256::{Bn256, Fr}};
use MerkleTreeCircuit;

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

pub fn generate(seed_slice: &[u32]) -> Result<KGGenerate, Box<Error>> {
    let mut seed : [u32; 4] = [0; 4];
    seed.copy_from_slice(seed_slice);
    let rng = &mut XorShiftRng::from_seed(seed);

    let j_params = &JubjubBn256::new();
    let params = generate_random_parameters::<Bn256, _, _>(
        MerkleTreeCircuit {
            params: j_params,
            nullifier: None,
            secret: None,
            proof: vec![],
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
        nullifier_hex: &str,
        secret_hex: &str,
        root_hex: &str,
        mut proof_path_hex: &str,
        mut proof_path_sides: &str,
) -> Result<KGProof, Box<Error>> {
    // if params.len() == 0 {
    //     return Err("Params are empty. Did you generate or load params?".into())
    // }
    let de_params = Parameters::<Bn256>::read(&hex::decode(params)?[..], true)?;
    let j_params = &JubjubBn256::new();

    let mut seed : [u32; 4] = [0; 4];
    seed.copy_from_slice(seed_slice);
    let rng = &mut XorShiftRng::from_seed(seed);
    let params = &JubjubBn256::new();

    let s = &format!("{}", Fs::char())[2..];
    let s_big = BigInt::from_str_radix(s, 16)?;
    println!("{:?}, {:?}", s, Fs::char());
    // Nullifier
    let nullifier_big = BigInt::from_str_radix(nullifier_hex, 16)?;
    // if nullifier_big >= s_big {
    //     return Err("nullifier should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
    // }
    let nullifier_raw = &nullifier_big.to_str_radix(10);
    let nullifier = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
    let nullifier_s = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
    // Secret preimage data
    let secret_big = BigInt::from_str_radix(secret_hex, 16)?;
    // if secret_big >= s_big {
    //     return Err("secret should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
    // }
    let secret_raw = &secret_big.to_str_radix(10);
    let secret = Fr::from_str(secret_raw).ok_or("couldn't parse Fr")?;
    let secret_s = Fr::from_str(secret_raw).ok_or("couldn't parse Fr")?;
    // Root hash
    let root_big = BigInt::from_str_radix(root_hex, 16)?;
    // if root_big >= s_big {
    //     return Err("root should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
    // }
    let root_raw = &root_big.to_str_radix(10);
    let root = Fr::from_str(root_raw).ok_or("couldn't parse Fr")?;
    let root_s = Fr::from_str(root_raw).ok_or("couldn't parse Fr")?;
    // Proof path
    println!("{:?}\n{:?}\n{:?}", nullifier, secret, root);
    let mut proof_p_big: Vec<Option<(bool, pairing::bn256::Fr)>> = vec![];
    let proof_len = proof_path_sides.len();
    for i in 0..proof_len {
        let (neighbor_i, pfh) = proof_path_hex.split_at(64);
        let (side_i, pfs) = proof_path_sides.split_at(1);
        proof_path_hex = pfh;
        proof_path_sides = pfs;
        let mut side_bool = false;
        if side_i == "1" {
            side_bool = true;
        }

        let p_big = BigInt::from_str_radix(neighbor_i, 16)?;
        // if p_big >= s_big {
        //     return Err("root should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
        // }
        let p_raw = &p_big.to_str_radix(10);
        let p = Fr::from_str(p_raw).ok_or("couldn't parse Fr")?;
        let p_s = Fr::from_str(p_raw).ok_or("couldn't parse Fr")?;
        proof_p_big.push(Some((
            side_bool,
            p,
        )));
    }
    println!("Proof in ZK_UTIL\n{:?}\n", proof_p_big);
    let proof = create_random_proof(
        MerkleTreeCircuit {
            params: j_params,
            nullifier: Some(nullifier),
            secret: Some(secret),
            proof: vec![],
        },
        &de_params,
        rng
    )?;

    let mut v = vec![];
    proof.write(&mut v)?;
    Ok(KGProof {
        proof: hex::encode(&v[..]),
    })
}

pub fn verify(params: &str, proof: &str, nullifier_hex: &str, root_hex: &str) -> Result<KGVerify, Box<Error>> {
    let de_params = Parameters::read(&hex::decode(params)?[..], true)?;
    let j_params = &JubjubBn256::new();
    let pvk = prepare_verifying_key::<Bn256>(&de_params.vk);

    let s = &format!("{}", Fs::char())[2..];
    let s_big = BigInt::from_str_radix(s, 16)?;
    // Nullifier
    let nullifier_big = BigInt::from_str_radix(nullifier_hex, 16)?;
    // if nullifier_big >= s_big {
    //     return Err("x should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
    // }
    let nullifier_raw = &nullifier_big.to_str_radix(10);
    let nullifier = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
    let nullifier_s = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
    // Root hash
    let root_big = BigInt::from_str_radix(root_hex, 16)?;
    // if root_big >= s_big {
    //     return Err("x should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
    // }
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

    Ok(KGVerify{
        result: result
    })
}
