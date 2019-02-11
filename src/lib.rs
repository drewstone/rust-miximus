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
    nullifier: Option<E::Fr>,
    // secret
    xr: Option<E::Fr>,
    leaf: Option<E::Fr>,
    root: Option<E::Fr>,
    proof: Vec<Option<(Boolean, E::Fr)>>,
    params: &'a E::Params,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: JubjubEngine> Circuit<E> for MerkleTreeCircuit<'a, E> where E: sapling_crypto::jubjub::JubjubEngine {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let root = AllocatedNum::alloc(cs.namespace(|| "root"), || {
            let root_value = self.root.unwrap();
            Ok(root_value)
        })?;

        let nullifier = AllocatedNum::alloc(cs.namespace(|| "nullifier"), || {
            let nullifier_value = self.nullifier.unwrap();
            Ok(nullifier_value)
        })?;

        let xr = AllocatedNum::alloc(cs.namespace(|| "xr"), || {
            let xr_value = self.xr.unwrap();
            Ok(xr_value)
        })?;

        let leaf = AllocatedNum::alloc(cs.namespace(|| "leaf"), || {
            let leaf_value = self.leaf.unwrap();
            Ok(leaf_value)
        })?;



        // let mut xl_bits = match self.xl {
        //     Some(x) => {
        //         BitIterator::new(x.into_repr()).collect::<Vec<_>>()
        //     }
        //     None => {
        //         vec![false; Fs::NUM_BITS as usize]
        //     }
        // };

        // xl_bits.reverse();
        // xl_bits.truncate(Fs::NUM_BITS as usize);
        // let xl_bits = xl_bits.into_iter()
        //                    .enumerate()
        //                    .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("left scalar bit {}", i)), Some(b)).unwrap())
        //                    .map(|v| Boolean::from(v))
        //                    .collect::<Vec<_>>();

        // let mut xr_bits = match self.xr {
        //     Some(x) => {
        //         BitIterator::new(x.into_repr()).collect::<Vec<_>>()
        //     }
        //     None => {
        //         vec![false; Fs::NUM_BITS as usize]
        //     }
        // };
        // xr_bits.reverse();
        // xr_bits.truncate(Fs::NUM_BITS as usize);
        // let xr_bits = xr_bits.into_iter()
        //                    .enumerate()
        //                    .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("right scalar bit {}", i)), Some(b)).unwrap())
        //                    .map(|v| Boolean::from(v))
        //                    .collect::<Vec<_>>();
        

        
        let nullifier_bits = nullifier.into_bits_le_strict(cs.namespace(|| "nullifier bits")).unwrap();
        let xr_bits = xr.into_bits_le_strict(cs.namespace(|| "secret bits")).unwrap();
        let mut preimage = vec![];
        preimage.extend(nullifier_bits);
        preimage.extend(xr_bits);

        let mut hash = apply_pedersen(
        	cs.namespace(|| "to data hash"),
        	&preimage,
        	self.params
        ).unwrap();

        cs.enforce(
            || "enforce leaf equal to recalculated one",
            |lc| lc + hash.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + leaf.get_variable()
        );

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

#[cfg(test)]
mod test {
    // use rand::{XorShiftRng, SeedableRng, Rng};
    use bellman::groth16::generate_random_parameters;
    use sapling_crypto::jubjub::JubjubEngine;
    use pairing::{bn256::{Bn256, Fr}};
    use sapling_crypto::{
        alt_babyjubjub::AltJubjubBn256,
    };
    use rand::{XorShiftRng, SeedableRng};

    use sapling_crypto::circuit::test::TestConstraintSystem;
    use bellman::{
        Circuit,
    };
    use rand::Rand;

    use super::MerkleTreeCircuit;

    use time::PreciseTime;

    #[test]
    fn test_merkle() {
        let mut cs = TestConstraintSystem::<Bn256>::new();
        let mut seed : [u32; 4] = [0; 4];
        seed.copy_from_slice(&[1u32, 1u32, 1u32, 1u32]);
        let rng = &mut XorShiftRng::from_seed(seed);
        println!("generating setup...");
        let start = PreciseTime::now();
        
        let j_params = &AltJubjubBn256::new();
        let m_circuit = MerkleTreeCircuit {
            params: j_params,
            nullifier: Some(Fr::rand(rng)),
            xr: Some(Fr::rand(rng)),
            leaf: Some(Fr::rand(rng)),
            root: Some(Fr::rand(rng)),
            proof: vec![],
        };

        // let _params = generate_random_parameters::<Bn256, _, _>(
        //     m_circuit,
        //     rng
        // ).unwrap();
        // println!("setup generated in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        m_circuit.synthesize(&mut cs).unwrap();
        println!("num constraints: {}", cs.num_constraints());
        println!("num inputs: {}", cs.num_inputs());
    }
}