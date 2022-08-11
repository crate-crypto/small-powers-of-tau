use ark_bls12_381::{G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine};

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
    pub fn starting_from(starting_point: G1Projective) -> Self {
        Self {
            accumulated_points: vec![starting_point],
            witnesses: vec![],
        }
    }

    // Extends a shared secret chain with the new accumulated point and a witness that
    // holds the discrete log that was used to transition from the previous srs to the next
    pub fn extend(&mut self, new_accumulated_point: G1Projective, witness: G2Projective) {
        self.accumulated_points.push(new_accumulated_point);
        self.witnesses.push(witness)
    }

    // Verifies a shared secret chain, each srs is checked to have been transformed from the previous one
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
