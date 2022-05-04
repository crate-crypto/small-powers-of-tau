// An update proof shows two things:
// - One knows the discrete log to a secret `p` via KoE
// - `p` was used to update an existing point A to a new point A'

use crate::shared_secret::SharedSecretChain;
use ark_bn254::{G1Projective, G2Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::Zero;

#[derive(Debug, Clone, Copy)]
pub struct UpdateProof {
    // A commitment to the secret scalar `p`
    pub(crate) commitment_to_secret: G2Projective,
    // This is the point before we updated it
    pub(crate) previous_accumulated_point: G1Projective,
    // This is the previous point multiplied by the scalar `p`
    pub(crate) new_accumulated_point: G1Projective,
}

impl UpdateProof {
    #[cfg(test)]
    pub(crate) fn verify(&self) -> bool {
        // Check if update proof is valid
        if !self.is_valid() {
            return false;
        }

        // Now check that the transition from the previous accumulated point to the new accumulated point
        // was due to the scalar `p` that was in the proof of knowledge
        let mut chain = SharedSecretChain::starting_from(self.previous_accumulated_point);
        chain.extend(self.new_accumulated_point, self.commitment_to_secret);

        chain.verify()
    }
    fn is_valid(&self) -> bool {
        // Check that they did not use the scalar `1` to update the accumulator
        // This essentially reveals their secret, as its easy to spot.
        if self.commitment_to_secret == G2Projective::prime_subgroup_generator() {
            return false;
        }
        // This check is superfluous because if they used zero, then the degree-1 element in the accumulator would be
        // zero
        if self.commitment_to_secret.is_zero() {
            return false;
        }

        true
    }

    pub(crate) fn verify_chain(update_proofs: &[UpdateProof]) -> bool {
        assert!(!update_proofs.is_empty(), "no update proofs are present");

        // Verify all of the update proofs and verify that they link
        let first_update_proof = update_proofs.first().unwrap();

        let mut chain =
            SharedSecretChain::starting_from(first_update_proof.previous_accumulated_point);

        for update_proof in update_proofs {
            if !update_proof.is_valid() {
                return false;
            }

            // Add the new accumulated point into the chain along with a witness that attests to the
            // transition from the previous point to it.
            chain.extend(
                update_proof.new_accumulated_point,
                update_proof.commitment_to_secret,
            );
        }

        chain.verify()
    }
}
