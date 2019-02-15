
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

mod tree;
mod merkle_tree;
mod wasm_util;

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
struct MerkleTreeCircuit<'a, E: JubjubEngine> {
    // nullifier
    nullifier: Option<E::Fr>,
    // secret
    secret: Option<E::Fr>,
    leaf: Option<E::Fr>,
    root: Option<E::Fr>,
    proof: Vec<Option<(bool, E::Fr)>>,
    params: &'a E::Params,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: JubjubEngine> Circuit<E> for MerkleTreeCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // root is public merkle root of the merkle tree
        let root = AllocatedNum::alloc(cs.namespace(|| "root"), || {
            let root_value = self.root.unwrap();
            Ok(root_value)
        })?;
        root.inputize(cs.namespace(|| "public input root"))?;
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
        // leaf is a private input (potentially not needed)
        let leaf = AllocatedNum::alloc(cs.namespace(|| "leaf"),
            || Ok(match self.leaf {
                Some(l) => l,
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
        // enforce the hash is equivalent to the private leaf input
        cs.enforce(
            || "enforce leaf equal to recalculated one",
            |lc| lc + hash.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + leaf.get_variable()
        );
        // reconstruct merkle root hash using the private merkle path
        for i in 0..self.proof.len() {
			match self.proof[i] {
                Some((ref side, ref element)) => {
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

                    let mut preimage = vec![];
                    preimage.extend(xl.into_bits_le(cs.namespace(|| format!("xl into bits {}", i)))?);
                    preimage.extend(xr.into_bits_le(cs.namespace(|| format!("xr into bits {}", i)))?);

                    // Compute the new subtree value
                    hash = baby_pedersen_hash::pedersen_hash(
                        cs.namespace(|| format!("computation of pedersen hash {}", i)),
                        baby_pedersen_hash::Personalization::MerkleTree(i as usize),
                        &preimage,
                        self.params
                    )?.get_x().clone(); // Injective encoding
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

#[cfg(test)]
mod test {
    use pairing::{bn256::{Bn256, Fr}};
    use sapling_crypto::{
        babyjubjub::{
            JubjubBn256
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

    use super::MerkleTreeCircuit;
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
            leaf: Some(Fr::rand(rng)),
            root: Some(Fr::rand(rng)),
            proof: proof_vec,
        };

        m_circuit.synthesize(&mut cs).unwrap();
        println!("setup generated in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
        println!("num constraints: {}", cs.num_constraints());
        println!("num inputs: {}", cs.num_inputs());
    }
}