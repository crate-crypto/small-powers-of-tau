use ark_bls12_381::Fr;
use ark_ff::PrimeField;
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

pub fn contribution_verify_update(
    old_contribution: &Contribution,
    new_contribution: &Contribution,
    update_proofs: &[UpdateProof; NUM_CEREMONIES],
    random_hex_elements: [String; NUM_CEREMONIES],
) -> bool {
    for i in 0..NUM_CEREMONIES {
        // Decode random hex string into a field element
        //
        //
        let hex_str = &random_hex_elements[i];
        let hex_str = if let Some(stripped_random_hex) = hex_str.strip_prefix("0x") {
            stripped_random_hex
        } else {
            return false;
        };

        let element = match hex::decode(hex_str) {
            Ok(bytes) => Fr::from_be_bytes_mod_order(&bytes),
            Err(_) => return false,
        };

        // Verify update
        //
        let proof = update_proofs[i];
        let before = &old_contribution.contributions[i];
        let after = &new_contribution.contributions[i];
        if !SRS::verify_update(before, after, &proof, element) {
            return false;
        };
    }

    true
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContributionJSON {
    pub contributions: [SRSJson; NUM_CEREMONIES],
}

impl From<&Contribution> for ContributionJSON {
    fn from(contribution: &Contribution) -> Self {
        let contributions_json = contribution
            .contributions
            // TODO: can remove clone but will need to try_into for array size
            .clone()
            .map(|srs| SRSJson::from(&srs));
        Self {
            contributions: contributions_json,
        }
    }
}

impl From<&ContributionJSON> for Contribution {
    fn from(contribution_json: &ContributionJSON) -> Self {
        // TODO: find a cleaner way to write this
        let contributions_option: [Option<SRS>; NUM_CEREMONIES] = contribution_json
            .contributions
            .clone()
            .map(|srs_json| (&srs_json).into());

        let mut contributions = Vec::new();

        for optional_srs in contributions_option {
            match optional_srs {
                Some(srs) => contributions.push(srs),
                None => return Contribution::default(),
            }
        }
        Self {
            contributions: contributions.try_into().unwrap(),
        }
    }
}