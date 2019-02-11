extern crate wasm_bindgen;
extern crate sapling_crypto;
extern crate bellman;
extern crate pairing;
extern crate ff;
extern crate num_bigint;
extern crate num_traits;
extern crate rand;
extern crate time;

use time::PreciseTime;
use bellman::{
    Circuit,
    SynthesisError,
    ConstraintSystem,
    groth16::{
        // Proof, Parameters, verify_proof, create_random_proof, prepare_verifying_key,
        generate_random_parameters
    }
};

use rand::{XorShiftRng, SeedableRng};
use ff::{BitIterator, PrimeField};
use pairing::bn256::Bn256;
use sapling_crypto::{
    alt_babyjubjub::AltJubjubBn256,
    jubjub::{
        fs::Fs,
        JubjubEngine,
    },
    circuit::{
        Assignment,
        num::{AllocatedNum},
        pedersen_hash,
        boolean::{AllocatedBit, Boolean}
    }
};

#[derive(Serialize)]
pub struct KGGenerate {
    pub params: String
}

#[derive(Serialize)]
pub struct KGProof {
    pub proof: String,
    pub h: String
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

        let j_params = &AltJubjubBn256::new();
        let params = generate_random_parameters::<Bn256, _, _>(
            MerkleTreeCircuit {
                params: j_params,
                nullifier: None,
                xr: None,
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
pub fn prove(seed_slice: &[u32], params: &str, nullifier_hex: &str, xr_hex: &str, leaf_hex: &str, root_hex: &str, proof_hex: Vec<&str>) -> Result<JsValue, JsValue> {
    let res = || -> Result<JsValue, Box<Error>> {
        if params.len() == 0 {
            return Err("Params are empty. Did you generate or load params?".into())
        }
        let de_params = Parameters::<Bn256>::read(&hex::decode(params)?[..], true)?;

        let mut seed : [u32; 4] = [0; 4];
        seed.copy_from_slice(seed_slice);
        let rng = &mut XorShiftRng::from_seed(seed);
        let params = &AltJubjubBn256::new();

        let g = params.generator(FixedGenerators::ProofGenerationKey);
        let s = &format!("{}", Fs::char())[2..];
        let s_big = BigInt::from_str_radix(s, 16)?;
        // X
        let x_big = BigInt::from_str_radix(x_hex, 16)?;
        if x_big >= s_big {
            return Err("x should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
        }
        let x_raw = &x_big.to_str_radix(10);
        let xs = Fs::from_str(x_raw).ok_or("couldn't parse Fr")?;
        let x = Fr::from_str(x_raw).ok_or("couldn't parse Fr")?;
        // Nullifier
        let nullifier_big = BigInt::from_str_radix(nullifier_hex, 16)?;
        if nullifier_big >= s_big {
            return Err("x should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
        }
        let nullifier_raw = &nullifier_big.to_str_radix(10);
        let nullifier = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
        let nullifier_s = Fr::from_str(nullifier_raw).ok_or("couldn't parse Fr")?;
        // xr - secret data
        let xr_big = BigInt::from_str_radix(xr_hex, 16)?;
        if xr_big >= s_big {
            return Err("x should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
        }
        let xr_raw = &xr_big.to_str_radix(10);
        let xr = Fr::from_str(xr_raw).ok_or("couldn't parse Fr")?;
        let xr_s = Fr::from_str(xr_raw).ok_or("couldn't parse Fr")?;
        // leaf hash
        let leaf_big = BigInt::from_str_radix(leaf_hex, 16)?;
        if leaf_big >= s_big {
            return Err("x should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
        }
        let leaf_raw = &leaf_big.to_str_radix(10);
        let leaf = Fr::from_str(leaf_raw).ok_or("couldn't parse Fr")?;
        let leaf_s = Fr::from_str(leaf_raw).ok_or("couldn't parse Fr")?;

        // leaf hash
        let proof_big = proof_hex.iter().map(|s, p_hex| BigInt::from_str_radix(p_hex, 16)?);
        for (s, p) in proof_big {
            if p >= s_big {
                return Err("p should be less than 60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1".into())
            }
        }
            
        let proof_raw = proof_hex.iter().map(|s, p| &proof_big.to_str_radix(10));
        let proof = proof_raw.iter().map(|s, p| Some(Fr::from_str(p).ok_or("couldn't parse Fr")?));
        let proof_s = proof_raw.iter().map(|s, p| Some(Fr::from_str(p).ok_or("couldn't parse Fr")?));

        let leaf_hash = g.mul(xs, params);

        let proof = create_random_proof(
            MerkleTreeCircuit {
                params: j_params,
                nullifier: Some(nullifier),
                xr: Some(xr),
                leaf: Some(leaf),
                root: Some(root),
                proof: proof,
            },
            &de_params,
            rng
        )?;

        let mut v = vec![];
        proof.write(&mut v)?;

        let mut v2 = vec![];
        h.write(&mut v2)?;

        Ok(JsValue::from_serde(&KGProof {
            proof: hex::encode(&v[..]),
            h: hex::encode(&v2[..])
        })?)
    }();

    convert_error_to_jsvalue(res)
}

#[wasm_bindgen(catch)]
pub fn verify(params: &str, proof: &str, h: &str) -> Result<JsValue, JsValue> {
    let res = || -> Result<JsValue, Box<Error>> {
        let j_params = &JubjubBn256::new();
        let de_params = Parameters::read(&hex::decode(params)?[..], true)?;
        let pvk = prepare_verifying_key::<Bn256>(&de_params.vk);
        let h = Point::<Bn256, _>::read(&hex::decode(h)?[..], j_params)?;
        let (h_x, h_y) = h.into_xy();
        let result = verify_proof(
            &pvk,
            &Proof::read(&hex::decode(proof)?[..])?,
            &[
            h_x,
            h_y
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