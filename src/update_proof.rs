// An update proof shows two things:
// - One knows the discrete log to a secret `p` via KoE
// - `p` was used to update an existing point A to a new point A'

use crate::shared_secret::SharedSecretChain;
use ark_bls12_381::{G1Projective, G2Projective};

#[derive(Debug, Clone, Copy)]
pub struct UpdateProof {
    // A commitment to the secret scalar `p`
    pub(crate) commitment_to_secret: G2Projective,
    // This is the degree-1 element of the SRS after it has been
    // updated by the contributor
    pub(crate) new_accumulated_point: G1Projective,
}

impl UpdateProof {
    #[cfg(test)]
    pub(crate) fn verify(&self, starting_point: G1Projective) -> bool {
        let mut chain = SharedSecretChain::starting_from(starting_point);
        chain.extend(self.new_accumulated_point, self.commitment_to_secret);

        chain.verify()
    }

    pub(crate) fn verify_chain(
        starting_point: G1Projective,
        update_proofs: &[UpdateProof],
    ) -> bool {
        // TODO: consider either returning a result here or returning false
        // TODO: alternatively, we can say that its the job of the caller to
        // TODO: ensure that its not empty
        assert!(!update_proofs.is_empty(), "no update proofs are present");

        let mut chain = SharedSecretChain::starting_from(starting_point);

        for update_proof in update_proofs {
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
