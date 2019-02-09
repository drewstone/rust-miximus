extern crate bellman;
extern crate pairing;
extern crate rand;

// For randomness (during paramgen and proof generation)
use rand::{thread_rng, Rng};

// For benchmarking
use std::time::{Duration, Instant};

// We'll use these interfaces to construct our circuit.
use bellman::{
    Circuit,
    ConstraintSystem,
    SynthesisError
};

use sapling_crypto::circuit::{
    Boolean,
    blake2s,
    babyjubjub::{
        fs::Fs,
        JubjubBn256,
        FixedGenerators,
        JubjubEngine,
        JubjubParams,
        edwards::Point
    },
    {
        baby_ecc::fixed_base_multiplication,
        boolean::{AllocatedBit, Boolean}
    }
};
use sapling_crypto::circuit::


/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
struct MerkleTree<'a, E: Engine> {
    // nullifier
    xl: Option<E::Fr>,
    // secret
    xr: Option<E::Fr>,
    root: Option<E::Fr>,
    proof: Option<Vec<(Boolean, E::Fr)>>,
    params: &'a E::Params,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for MerkleTree<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
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

        let mut xr_bits = match self.xl {
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

        xl_bits.extend(xr_bits);

        let h = fixed_base_multiplication(
            cs.namespace(|| "multiplication"),
            FixedGenerators::ProofGenerationKey,
            &xl_bits,
            self.params
        )?;

        h.inputize(cs)?;

        let mut temp = h;
        for (side, elt) in self.proof {
            let mut temp_bits = BitIterator::new(h.into_repr()).collect::<Vec<_>>()
            temp_bits.reverse();
            temp_bits.truncate(Fs::NUM_BITS as usize);
            let temp_bits = temp_bits.into_iter()
                            .enumerate()
                            .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("scalar bit {}", i)), Some(b)).unwrap())
                            .map(|v| Boolean::from(v))
                            .collect::<Vec<_>>();
            


            let mut elt_bits = BitIterator::new(elt.into_repr()).collect::<Vec<_>>()
            elt_bits.reverse();
            elt_bits.truncate(Fs::NUM_BITS as usize);
            let elt_bits = elt_bits.into_iter()
                            .enumerate()
                            .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("scalar bit {}", i)), Some(b)).unwrap())
                            .map(|v| Boolean::from(v))
                            .collect::<Vec<_>>();
            
            let mut input_bits = Vec::new();
            if side {
                input_bits = xl_bits.extend(xr_bits);
            } else {
                input_bits = xr_bits.extend(xk_bits)
            }
            let hash = blake2s(&cs, &input_bits, "0x00000000");
            temp = hash;
        }

        cs.enforce(
            || "enforce root equal to recalculated one",
            |lc| lc + new_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + temp.get_variable()
        );

        Ok(())
    }
}

#[test]
fn test_merkle_tree() {
    
}
