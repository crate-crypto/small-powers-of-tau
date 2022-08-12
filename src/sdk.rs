use crate::{
    keypair::PrivateKey,
    srs::{Parameters, SRS},
    update_proof::UpdateProof,
};

const NUM_CEREMONIES: usize = 4;

const CEREMONIES: [Parameters; NUM_CEREMONIES] = [
    Parameters {
        num_g1_elements_needed: 4096,
        num_g2_elements_needed: 65,
    },
    Parameters {
        num_g1_elements_needed: 8192,
        num_g2_elements_needed: 65,
    },
    Parameters {
        num_g1_elements_needed: 16384,
        num_g2_elements_needed: 65,
    },
    Parameters {
        num_g1_elements_needed: 32768,
        num_g2_elements_needed: 65,
    },
];

pub struct Transcript {
    sub_ceremonies: [SRS; NUM_CEREMONIES],
}

pub fn update_transcript(
    mut transcript: Transcript,
    secrets: [String; NUM_CEREMONIES],
) -> Option<(Transcript, [UpdateProof; NUM_CEREMONIES])> {
    // Check that the parameters for each SRS is correct
    for (srs, params) in transcript.sub_ceremonies.iter().zip(CEREMONIES.into_iter()) {
        if srs.tau_g1.len() != params.num_g1_elements_needed {
            return None;
        }
        if srs.tau_g2.len() != params.num_g2_elements_needed {
            return None;
        }
    }

    let mut update_proofs = Vec::with_capacity(NUM_CEREMONIES);

    for (i, secret_hex) in secrets.into_iter().enumerate() {
        if let Some(stripped_point_json) = secret_hex.strip_prefix("0x") {
            let bytes = hex::decode(stripped_point_json).ok()?;
            let priv_key = PrivateKey::from_bytes(&bytes);

            let update_proof = transcript.sub_ceremonies[i].update(priv_key);
            update_proofs.push(update_proof);
        } else {
            return None;
        }
    }

    let update_proofs: [UpdateProof; NUM_CEREMONIES] = update_proofs.try_into().unwrap();

    Some((transcript, update_proofs))
}

pub fn transcript_subgroup_check(transcript: Transcript) -> bool {
    for srs in &transcript.sub_ceremonies {
        if !srs.subgroup_check() {
            return false;
        }
    }
    true
}
