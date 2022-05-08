use ark_bls12_381::{Fr, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;

// A shared secret proof proves that a point was necessarily created by multiplying the discrete log of a series of previous points
//
// For example; Given the point P = (a * b * c) G_1
// An shared secret proof is capable of proving that P was created in four steps:
// 1 * G_1 -> a * G_1 -> (a * b) * G_1 -> (a * b * c) * G_1

pub struct SharedSecretChain {
    accumulated_points: Vec<G1Projective>,
    witnesses: Vec<G2Projective>,
}

impl SharedSecretChain {
    // Starts a shared secret chain from the prime subgroup generator
    pub fn new() -> Self {
        Self::starting_from(G1Projective::prime_subgroup_generator())
    }

    pub fn starting_from(starting_point: G1Projective) -> Self {
        Self {
            accumulated_points: vec![starting_point],
            witnesses: vec![],
        }
    }

    pub fn last_accumulated_point(&self) -> G1Projective {
        *self
            .accumulated_points
            .last()
            .expect("there should be at least one point in the accumulation vector")
    }

    // Extends a shared secret chain with the new accumulated point and a witness that
    // holds the discrete log that was used to transition from the previous accumulator to the next
    pub fn extend(&mut self, new_accumulated_point: G1Projective, witness: G2Projective) {
        self.accumulated_points.push(new_accumulated_point);
        self.witnesses.push(witness)
    }

    // Uses a secret to extend extend a shared secret chain
    #[cfg(test)]
    pub fn accumulate(&mut self, scalar: Fr) {
        let gen_g2 = G2Affine::prime_subgroup_generator();

        let last_accumulated_point = self.accumulated_points.last().unwrap();
        let new_accumulated_point = last_accumulated_point.mul(scalar.into_repr());

        let witness = gen_g2.mul(scalar.into_repr());
        self.extend(new_accumulated_point, witness)
    }
    // Verifies a shared secret chain, each accumulator is checked to have been transformed from the previous one
    // using the specified witness
    pub fn verify(&self) -> bool {
        // Overlapping window of two; see example: https://gist.github.com/rust-play/d83ae8ffdbf24f17612e05dc75c2ee06
        // Group accumulated points into overlapping pairs
        let acc_pairs = self.accumulated_points.as_slice().windows(2);

        let gen_g2 = G2Affine::prime_subgroup_generator();

        for (acc_pair, witness) in acc_pairs.zip(&self.witnesses) {
            let prev_acc = acc_pair[0];
            let next_acc = acc_pair[1];
            let p1 = ark_bls12_381::Bls12_381::pairing(next_acc, gen_g2);
            let p2 = ark_bls12_381::Bls12_381::pairing(prev_acc, *witness);
            if p1 != p2 {
                return false;
            }
        }
        true
    }
}

#[test]
fn shared_secret_fuzz() {
    let witness_a = Fr::from(100u64);
    let witness_b = Fr::from(200u64);
    let witness_c = Fr::from(300u64);

    let mut product_chain = SharedSecretChain::new();
    product_chain.accumulate(witness_a);
    product_chain.accumulate(witness_b);
    product_chain.accumulate(witness_c);

    assert!(product_chain.verify())
}
