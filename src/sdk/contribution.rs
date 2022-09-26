use ark_bls12_381::Fr;
use ark_ff::{PrimeField, Zero};
use serde::{Deserialize, Serialize};

use crate::{
    keypair::PrivateKey,
    srs::SRS,
    update_proof::UpdateProof,
    serialisation::SRSJson,
    sdk::{NUM_CEREMONIES, CEREMONIES},
};

pub struct Contribution {
    pub contributions: [SRS; NUM_CEREMONIES],
}

impl Default for Contribution {
    fn default() -> Self {
        Contribution {
            contributions: [
                SRS::new(CEREMONIES[0]).unwrap(),
                SRS::new(CEREMONIES[1]).unwrap(),
                SRS::new(CEREMONIES[2]).unwrap(),
                SRS::new(CEREMONIES[3]).unwrap(),
            ],
        }
    }
}

pub fn update_contribution(
    mut contribution: Contribution,
    secrets: [String; NUM_CEREMONIES],
) -> Option<(Contribution, [UpdateProof; NUM_CEREMONIES])> {
    // Check that the parameters for each SRS is correct
    for (srs, params) in contribution.contributions.iter().zip(CEREMONIES.into_iter()) {
        if srs.g1_elements().len() != params.num_g1_elements_needed {
            return None;
        }
        if srs.g2_elements().len() != params.num_g2_elements_needed {
            return None;
        }
    }

    let mut update_proofs = Vec::with_capacity(NUM_CEREMONIES);

    for (i, secret_hex) in secrets.into_iter().enumerate() {
        if let Some(stripped_point_json) = secret_hex.strip_prefix("0x") {
            let bytes = hex::decode(stripped_point_json).ok()?;
            let priv_key = PrivateKey::from_bytes(&bytes);

            let update_proof = contribution.contributions[i].update(priv_key);
            update_proofs.push(update_proof);
        } else {
            return None;
        }
    }

    let update_proofs: [UpdateProof; NUM_CEREMONIES] = update_proofs.try_into().unwrap();

    Some((contribution, update_proofs))
}

pub fn contribution_subgroup_check(contribution: Contribution) -> bool {
    for srs in &contribution.contributions {
        if !srs.subgroup_check() {
            return false;
        }
    }
    true
}

// TODO: keep copying functions from sdk/transcript.rs to here.
// Change transcript by contribution and sub_ceremonies by contributions