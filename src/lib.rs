

extern crate sapling_crypto;
extern crate bellman;
extern crate pairing;
extern crate ff;
extern crate num_bigint;
extern crate num_traits;
extern crate rand;
extern crate time;

use time::PreciseTime;
use std::error::Error;
use bellman::{
    Circuit,
    SynthesisError,
    ConstraintSystem,
    groth16::{
    	Proof, Parameters, verify_proof, create_random_proof, prepare_verifying_key,
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

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
struct MerkleTreeCircuit<'a, E: JubjubEngine> {
    // nullifier
    xl: Option<E::Fr>,
    // secret
    xr: Option<E::Fr>,
    root: Option<E::Fr>,
    proof: Vec<Option<(Boolean, E::Fr)>>,
    params: &'a E::Params,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: JubjubEngine> Circuit<E> for MerkleTreeCircuit<'a, E> where E: sapling_crypto::jubjub::JubjubEngine {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let root_value = self.root;
        // Expose inputs and do the bits decomposition of hash
        let root = AllocatedNum::alloc(
            cs.namespace(|| "old root"),
            || Ok(*root_value.get()?)
        )?;
        root.inputize(cs.namespace(|| "root input"))?;

        let mut xl_bits = match self.xl {
            Some(x) => {
                BitIterator::new(x.into_repr()).collect::<Vec<_>>()
            }
            None => {
                vec![false; Fs::NUM_BITS as usize]
            }
        };
        xl_bits.reverse();
        xl_bits.truncate(Fs::NUM_BITS as usize);

        let xl_bits = xl_bits.into_iter()
                           .enumerate()
                           .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("scalar bit {}", i)), Some(b)).unwrap())
                           .map(|v| Boolean::from(v))
                           .collect::<Vec<_>>();

        let mut xr_bits = match self.xr {
            Some(x) => {
                BitIterator::new(x.into_repr()).collect::<Vec<_>>()
            }
            None => {
                vec![false; Fs::NUM_BITS as usize]
            }
        };
        xr_bits.reverse();
        xr_bits.truncate(Fs::NUM_BITS as usize);

        let xr_bits = xr_bits.into_iter()
                           .enumerate()
                           .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("scalar bit {}", i)), Some(b)).unwrap())
                           .map(|v| Boolean::from(v))
                           .collect::<Vec<_>>();

        let mut preimage = vec![];
        preimage.extend(xl_bits);
        preimage.extend(xr_bits);

        let mut hash = apply_pedersen(
        	cs.namespace(|| "to data hash"),
        	&preimage,
        	self.params
        ).unwrap();

        for item in self.proof {
			match item {
                Some((right_side, elt)) => {
				    if right_side.get_value().unwrap() {
	                    hash = merkle_hash_nodes(
	                    	cs.namespace(|| "to parent node hash"),
	                    	hash.get_value().unwrap(),
	                    	elt,
	                    	&self.params
	                    )?;
				    } else {
	                    hash = merkle_hash_nodes(
	                    	cs.namespace(|| "to parent node hash"),
	                    	elt,
	                    	hash.get_value().unwrap(),
	                    	&self.params
	                    )?;
				    }
                },
                None => (),
            }
        }

        cs.enforce(
            || "enforce new root equal to recalculated one",
            |lc| lc + hash.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + root.get_variable()
        );

        Ok(())
    }
}

fn merkle_hash_nodes<E: JubjubEngine, CS: ConstraintSystem<E>>(
	mut cs: CS,
	left: E::Fr,
	right: E::Fr,
	params: &E::Params
) -> Result<AllocatedNum<E>, SynthesisError> {
    let mut left_bits = BitIterator::new(left.into_repr()).collect::<Vec<_>>();
    left_bits.reverse();
    left_bits.truncate(Fs::NUM_BITS as usize);

    let left_bits = left_bits.into_iter()
                       .enumerate()
                       .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("scalar bit {}", i)), Some(b)).unwrap())
                       .map(|v| Boolean::from(v))
                       .collect::<Vec<_>>();


    let mut elt_bits = BitIterator::new(right.into_repr()).collect::<Vec<_>>();
    elt_bits.reverse();
    elt_bits.truncate(Fs::NUM_BITS as usize);

    let elt_bits = elt_bits.into_iter()
                       .enumerate()
                       .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("scalar bit {}", i)), Some(b)).unwrap())
                       .map(|v| Boolean::from(v))
                       .collect::<Vec<_>>();

    let mut preimage = vec![];
    preimage.extend(left_bits);
    preimage.extend(elt_bits);
    return apply_pedersen(
    	cs.namespace(|| "to pedersen hash"),
    	&preimage,
    	params,
    )
}

fn apply_pedersen<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    elt: &[Boolean],
    params: &E::Params,
) -> Result<AllocatedNum<E>, SynthesisError> {
    // Compute the hash of the from leaf
    let hash = pedersen_hash::pedersen_hash(
        cs.namespace(|| "to leaf content hash"),
        pedersen_hash::Personalization::NoteCommitment,
        &elt,
        params
    )?;
    let cur_from = hash.get_x().clone();
    Ok(cur_from)
}

#[test]
fn test_merkle() {
    let mut seed : [u32; 4] = [0; 4];
    seed.copy_from_slice(&[1u32]);
    let rng = &mut XorShiftRng::from_seed(seed);
    println!("generating setup...");
    let start = PreciseTime::now();
    
    let j_params = &AltJubjubBn256::new();
    let _params = generate_random_parameters::<Bn256, _, _>(
        MerkleTreeCircuit {
            params: j_params,
            xl: None,
            xr: None,
            root: None,
            proof: vec![],
        },
        rng
    ).unwrap();
    println!("setup generated in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
}