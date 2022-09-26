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


pub struct Transcript {
    pub transcripts: [SRS; NUM_CEREMONIES],
}

impl Default for Transcript {
    fn default() -> Self {
        Transcript {
            transcripts: [
                SRS::new(CEREMONIES[0]).unwrap(),
                SRS::new(CEREMONIES[1]).unwrap(),
                SRS::new(CEREMONIES[2]).unwrap(),
                SRS::new(CEREMONIES[3]).unwrap(),
            ],
        }
    }
}

pub fn update_transcript(
    mut transcript: Transcript,
    secrets: [String; NUM_CEREMONIES],
) -> Option<(Transcript, [UpdateProof; NUM_CEREMONIES])> {
    // Check that the parameters for each SRS is correct
    for (srs, params) in transcript.transcripts.iter().zip(CEREMONIES.into_iter()) {
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

            let update_proof = transcript.transcripts[i].update(priv_key);
            update_proofs.push(update_proof);
        } else {
            return None;
        }
    }

    let update_proofs: [UpdateProof; NUM_CEREMONIES] = update_proofs.try_into().unwrap();

    Some((transcript, update_proofs))
}

pub fn transcript_subgroup_check(transcript: Transcript) -> bool {
    for srs in &transcript.transcripts {
        if !srs.subgroup_check() {
            return false;
        }
    }
    true
}

pub fn transcript_verify_update(
    old_transcript: &Transcript,
    new_transcript: &Transcript,
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
        let before = &old_transcript.transcripts[i];
        let after = &new_transcript.transcripts[i];
        if !SRS::verify_update(before, after, &proof, element) {
            return false;
        };
    }

    true
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TranscriptJSON {
    pub transcripts: [SRSJson; NUM_CEREMONIES],
}

impl From<&Transcript> for TranscriptJSON {
    fn from(transcript: &Transcript) -> Self {
        let transcripts_json = transcript
            .transcripts
            // TODO: can remove clone but will need to try_into for array size
            .clone()
            .map(|srs| SRSJson::from(&srs));
        Self {
            transcripts: transcripts_json,
        }
    }
}

impl From<&TranscriptJSON> for Transcript {
    fn from(transcript_json: &TranscriptJSON) -> Self {
        // TODO: find a cleaner way to write this
        let transcripts_option: [Option<SRS>; NUM_CEREMONIES] = transcript_json
            .transcripts
            .clone()
            .map(|srs_json| (&srs_json).into());

        let mut transcripts = Vec::new();

        for optional_srs in transcripts_option {
            match optional_srs {
                Some(srs) => transcripts.push(srs),
                None => return Transcript::default(),
            }
        }
        Self {
            transcripts: transcripts.try_into().unwrap(),
        }
    }
}
