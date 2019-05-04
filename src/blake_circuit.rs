use sapling_crypto::circuit::blake2s::blake2s;
use rand::{ChaChaRng, SeedableRng, Rng};
use bellman::groth16::{Proof, Parameters, verify_proof, create_random_proof, prepare_verifying_key, generate_random_parameters};
use num_bigint::BigInt;
use num_traits::Num;
use std::error::Error;

use pairing::{bn256::{Fr, Bn256}};

use wasm_bindgen::prelude::*;

use pairing::{
    Engine,
};

use bellman::{
    Circuit,
    SynthesisError,
    ConstraintSystem,
};

use ff::{PrimeField};
use sapling_crypto::{
    circuit::{
        multipack,
        num::{AllocatedNum},
        boolean::{Boolean, AllocatedBit},
    }
};

pub const SUBSTRATE_BLAKE2_PERSONALIZATION: &'static [u8; 8]
          = b"TFWTFWTF";

/// Circuit for proving knowledge of preimage of leaf in merkle tree
struct BlakeTreeCircuit {
    // nullifier
    nullifier: Option<[u8; 32]>,
    // secret
    secret: Option<[u8; 32]>,
    // merkle proof
    proof: Vec<Option<(bool, [u8; 32])>>,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<E: Engine> Circuit<E> for BlakeTreeCircuit {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // nullifier is the left side of the preimage
        let nullifier: Vec<Boolean> = witness_u256(
            cs.namespace(|| "nullifier as Vec<Boolean>"),
            self.nullifier.as_ref().map(|v| &v[..])
        ).unwrap();
        multipack::pack_into_inputs(cs.namespace(|| "nullifier pack"), &nullifier)?;

        let nullifier_field_pt: E::Fr = multipack::compute_multipacking::<E>(&booleans_to_bools(nullifier.clone()))[0];
        let nullifier_alloc: AllocatedNum<E> = AllocatedNum::alloc(cs.namespace(|| "nullifier"), || Ok(nullifier_field_pt))?;
        nullifier_alloc.inputize(cs.namespace(|| "public input nullifier"))?;

        // secret is the right side of the preimage
        let secret: Vec<Boolean> = witness_u256(
            cs.namespace(|| "secret"),
            self.secret.as_ref().map(|v| &v[..])
        ).unwrap();
        multipack::pack_into_inputs(cs.namespace(|| "secret pack"), &secret)?;

        // construct preimage using [nullifier_bits|secret_bits] concatenation
        let mut preimage: Vec<Boolean> = vec![];

        preimage.extend(nullifier.into_iter());
        preimage.resize(256, Boolean::Constant(false));

        preimage.extend(secret.iter().cloned());
        preimage.resize(512, Boolean::Constant(false));
        // compute leaf hash using pedersen hash of preimage
        let mut hash = blake2s(cs.namespace(|| "blake hash 0"), &preimage, SUBSTRATE_BLAKE2_PERSONALIZATION).unwrap();

        // reconstruct merkle root hash using the private merkle path
        for i in 0..self.proof.len() {
			if let Some((ref side, ref element)) = self.proof[i] {
                let elt = witness_u256(
                    cs.namespace(|| format!("elt {}", i)),
                    Some(element.as_ref())
                ).unwrap();

                // Swap the two if the current subtree is on the right
                let (xl, xr): (Vec<Boolean>, Vec<Boolean>);
                if *side {
                    xl = elt;
                    xr = hash;
                } else {
                    xl = hash;
                    xr = elt;
                }

                // build preimage of merkle hash as concatenation of left and right nodes
                let mut preimage = vec![];
                preimage.extend(xl.into_iter());
                preimage.resize(256, Boolean::Constant(false));

                preimage.extend(xr.iter().cloned());
                preimage.resize(512, Boolean::Constant(false));


                hash = blake2s(cs.namespace(|| format!("black hash depth: {}", i)), &preimage, SUBSTRATE_BLAKE2_PERSONALIZATION).unwrap();
            }
        }

        assert_eq!(hash.len(), 256);
        let hash_pt: E::Fr = multipack::compute_multipacking::<E>(&booleans_to_bools(hash))[0];
        let hash_alloc: AllocatedNum<E> = AllocatedNum::alloc(cs.namespace(|| "hash alloc"), || Ok(hash_pt))?;
        hash_alloc.inputize(cs.namespace(|| "calculated root hash"))?;
        Ok(())
    }
}

fn booleans_to_bools(booleans: Vec<Boolean>) -> Vec<bool> {
    let mut bools: Vec<bool> = vec![];
    for i in 0..booleans.len() {
        bools.push(booleans[i].get_value().unwrap());
    }
    bools
}

/// Witnesses some bytes in the constraint system,
/// skipping the first `skip_bits`.
fn witness_bits<E, CS>(
    mut cs: CS,
    value: Option<&[u8]>,
    num_bits: usize,
    skip_bits: usize
) -> Result<Vec<Boolean>, SynthesisError>
    where E: Engine, CS: ConstraintSystem<E>,
{
    let bit_values = if let Some(value) = value {
        let mut tmp = vec![];
        for b in value.iter()
                      .flat_map(|&m| (0..8).rev().map(move |i| m >> i & 1 == 1))
                      .skip(skip_bits)
        {
            tmp.push(Some(b));
        }
        tmp
    } else {
        vec![None; num_bits]
    };
    assert_eq!(bit_values.len(), num_bits);

    let mut bits = vec![];

    for (i, value) in bit_values.into_iter().enumerate() {
        bits.push(Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| format!("bit {}", i)),
            value
        )?));
    }

    Ok(bits)
}

fn witness_u256<E, CS>(
    cs: CS,
    value: Option<&[u8]>,
) -> Result<Vec<Boolean>, SynthesisError>
    where E: Engine, CS: ConstraintSystem<E>,
{
    witness_bits(cs, value, 256, 0)
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
    let mut proof_elts = vec![];

    for _ in 0..depth {
        proof_elts.push(Some((
            true,
            rng.gen::<[u8; 32]>(),
        )));
    }
    let params = generate_random_parameters::<Bn256, _, _>(
        BlakeTreeCircuit {
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
    nullifier: &[u8; 32],
    secret: &[u8; 32],
    root_hash: &[u8; 32],
    mut proof_path: Vec<[u8; 32]>,
    mut proof_path_sides: &str,
) -> Result<KGProof, Box<Error>> {
    let rng = &mut ChaChaRng::from_seed(seed_slice);
    // construct proof path structure
    let de_params = Parameters::<Bn256>::read(&hex::decode(params)?[..], true)?;
    let mut proof_p_big: Vec<Option<(bool, [u8; 32])>> = vec![];
    let proof_len = proof_path_sides.len();
    for _ in 0..proof_len {
        let neighbor_i = proof_path.remove(0);
        let (side_i, pfs) = proof_path_sides.split_at(1);

        proof_path_sides = pfs;
        let mut side_bool = false;
        if side_i == "1" { side_bool = true }

        proof_p_big.push(Some((
            side_bool,
            neighbor_i,
        )));
    }

    let proof = create_random_proof(
        BlakeTreeCircuit {
            nullifier: Some(*nullifier),
            secret: Some(*secret),
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

pub fn verify(
    params: &str,
    proof: &str,
    nullifier_hex: &str,
    root_hex: &str
) -> Result<KGVerify, Box<Error>> {
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
    nullifier: &[u8; 32],
    secret: &[u8; 32],
    root_hash: &[u8; 32],
    proof_path: Vec<[u8; 32]>,
    proof_path_sides: &str,
) -> Result<JsValue, JsValue> {
    let res = prove(seed_slice, params, nullifier, secret, root_hash, proof_path, proof_path_sides);
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
    nullifier: &str,
    root: &str,
) -> Result<JsValue, JsValue> {
    let res = verify(params, proof, nullifier, root);
    if res.is_ok() {
        Ok(JsValue::from_serde(&res.ok().unwrap()).unwrap())
    } else {
        Err(JsValue::from_str(&res.err().unwrap().to_string()))
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;
    use pairing::{bn256::{Bn256}};
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
    

    use super::{BlakeTreeCircuit};
    use time::PreciseTime;

    #[test]
    fn test_merkle_circuit() {
        let mut cs = TestConstraintSystem::<Bn256>::new();
        let seed_slice = &[1u32, 1u32, 1u32, 1u32];
        let rng = &mut ChaChaRng::from_seed(seed_slice);
        println!("generating setup...");
        let start = PreciseTime::now();
        
        let depth = 3;

        let mut proof_elts = vec![];
        for _ in 0..depth {
            proof_elts.push(Some((
                true,
                rng.gen::<[u8; 32]>(),
            )));
        }

        let _j_params = &JubjubBn256::new();
        let m_circuit = BlakeTreeCircuit {
            nullifier: Some(rng.gen::<[u8; 32]>()),
            secret: Some(rng.gen::<[u8; 32]>()),
            proof: proof_elts,
        };

        m_circuit.synthesize(&mut cs).unwrap();
        println!("setup generated in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        println!("num constraints: {}", cs.num_constraints());
        println!("num inputs: {}", cs.num_inputs());
    }

    #[test]
    fn test_all_components() {
        
    }
}
