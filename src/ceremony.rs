// This file contains method to check the ceremony after it has been completed.
//
use crate::{accumulator::Accumulator, update_proof::UpdateProof};
use ark_bn254::G2Projective;

pub struct Ceremony;

impl Ceremony {
    // Verifies whether the final SRS was indeed updated correctly according to the update proofs
    pub fn verify(
        starting_srs: &Accumulator,
        final_srs: &Accumulator,
        update_proofs: &[UpdateProof],
    ) -> bool {
        Accumulator::verify_update(starting_srs, final_srs, update_proofs)
    }
    // Returns the position at which the public key contributed in the ceremony
    fn find_contribution(update_proofs: &[UpdateProof], public_key: G2Projective) -> Option<u64> {
        update_proofs
            .into_iter()
            .position(|up| up.commitment_to_secret == public_key)
            .map(|position| position as u64)
    }

    pub fn verify_and_find_contribution(
        starting_srs: &Accumulator,
        final_srs: &Accumulator,
        update_proofs: &[UpdateProof],
        public_key: G2Projective,
    ) -> (bool, Option<u64>) {
        let ok = Ceremony::verify(starting_srs, final_srs, &update_proofs);
        let position = Ceremony::find_contribution(update_proofs, public_key);
        (ok, position)
    }
}
