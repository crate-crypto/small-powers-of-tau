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
    #[cfg(test)]
    fn remove_last(&mut self) {
        self.accumulated_points.pop();
        self.witnesses.pop();
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

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G1Projective, G2Projective};
    use ark_ec::ProjectiveCurve;
    use ark_ff::PrimeField;

    use super::SharedSecretChain;

    #[test]
    fn shared_secret_smoke() {
        let g1_generator = G1Projective::prime_subgroup_generator();
        let g2_generator = G2Projective::prime_subgroup_generator();

        let a = Fr::from(20u64);
        let b = Fr::from(21u64);
        let c = Fr::from(23u64);
        let d = Fr::from(24u64);

        let a_witness = g2_generator.mul(a.into_repr());
        let b_witness = g2_generator.mul(b.into_repr());
        let c_witness = g2_generator.mul(c.into_repr());
        let d_witness = g2_generator.mul(d.into_repr());

        let mut chain = SharedSecretChain::starting_from(g1_generator);

        // Add `a` into the product so we have `a * G1` as the accumulated point
        //
        let a_g1 = g1_generator.mul(a.into_repr());
        chain.extend(a_g1, a_witness);
        assert!(chain.verify());
        //
        // Add `b` into the product so we have `a * b * G1` as the accumulated point
        let ab_g1 = a_g1.mul(b.into_repr());
        chain.extend(ab_g1, b_witness);
        assert!(chain.verify());
        //
        // Add `c` into the product so we have `a * b * c * G1` as the accumulated point
        let abc_g1 = ab_g1.mul(c.into_repr());
        chain.extend(abc_g1, c_witness);
        assert!(chain.verify());
        //
        // Add `d` into the product so we have `a * b * c * d * G1` as the accumulated point
        let abcd_g1 = abc_g1.mul(d.into_repr());

        // -- Now for the witness we add `c` instead of `d`. This should verify as false
        chain.extend(abcd_g1, c_witness);
        assert!(chain.verify() == false);
        chain.remove_last();
        // -- Now add the correct witness, but the wrong accumulated point
        chain.extend(abc_g1, d_witness);
        assert!(chain.verify() == false);
        chain.remove_last();
        // -- Add the correct accumulated point and witness
        chain.extend(abcd_g1, d_witness);
        assert!(chain.verify())
    }
}
