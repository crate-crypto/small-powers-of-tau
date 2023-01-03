use crate::interop_point_encoding::{
    deserialize_g1, deserialize_g2, serialize_g1, serialize_g2, G1_SERIALISED_SIZE,
    G2_SERIALISED_SIZE,
};
use serde::{Deserialize, Serialize};

use crate::{
    srs::{Parameters, SRS},
    update_proof::UpdateProof,
};
use ark_bls12_381::{G1Projective, G2Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};

fn hex_string_to_g1(hex_str: &str) -> Option<G1Projective> {
    if let Some(stripped_point_json) = hex_str.strip_prefix("0x") {
        let bytes = hex::decode(stripped_point_json).ok()?;
        if bytes.len() != G1_SERIALISED_SIZE {
            return None;
        }
        let mut fixed_array = [0u8; G1_SERIALISED_SIZE];
        fixed_array.copy_from_slice(&bytes);
        return Some(deserialize_g1(fixed_array)?.into_projective());
    } else {
        return None;
    }
}
fn hex_string_to_g2(hex_str: &str) -> Option<G2Projective> {
    if let Some(stripped_point_json) = hex_str.strip_prefix("0x") {
        let bytes = hex::decode(stripped_point_json).ok()?;
        if bytes.len() != G2_SERIALISED_SIZE {
            return None;
        }
        let mut fixed_array = [0u8; G2_SERIALISED_SIZE];
        fixed_array.copy_from_slice(&bytes);
        return Some(deserialize_g2(fixed_array)?.into_projective());
    } else {
        return None;
    }
}

impl SRS {
    pub fn serialise(&self) -> (Vec<String>, Vec<String>) {
        self.to_json_array()
    }

    fn g1s_to_json_array(g1s: &[G1Projective]) -> Vec<String> {
        let mut g1_points_json = Vec::new();

        let g1_points_affine = G1Projective::batch_normalization_into_affine(g1s);

        for point in &g1_points_affine {
            let mut point_as_hex = hex::encode(serialize_g1(point));
            point_as_hex.insert_str(0, "0x");
            g1_points_json.push(point_as_hex)
        }

        g1_points_json
    }
    fn g2s_to_json_array(g2s: &[G2Projective]) -> Vec<String> {
        let mut g2_points_json = Vec::new();

        let g2_points_affine = G2Projective::batch_normalization_into_affine(g2s);

        for point in &g2_points_affine {
            let mut point_as_hex = hex::encode(serialize_g2(point));
            point_as_hex.insert_str(0, "0x");
            g2_points_json.push(point_as_hex)
        }

        g2_points_json
    }

    fn to_json_array(&self) -> (Vec<String>, Vec<String>) {
        let g1_points_json = Self::g1s_to_json_array(self.g1_elements());
        let g2_points_json = Self::g2s_to_json_array(self.g2_elements());

        (g1_points_json, g2_points_json)
    }

    // We do not check if the point is the identity when deserialising
    // What we do check, is that every point is a point on the curve
    pub fn deserialise(json_arr: (&[String], &[String]), parameters: Parameters) -> Option<Self> {
        SRS::from_json_array(json_arr, parameters)
    }

    fn from_json_array(json_array: (&[String], &[String]), parameters: Parameters) -> Option<Self> {
        let (g1_points_json_array, g2_points_json_array) = json_array;
        let mut g1 = vec![];
        let mut g2 = vec![];

        for point_json in g1_points_json_array {
            g1.push(hex_string_to_g1(&point_json)?);
        }
        for point_json in g2_points_json_array {
            g2.push(hex_string_to_g2(&point_json)?)
        }

        if g1.len() != parameters.num_g1_elements_needed {
            return None;
        }
        if g2.len() != parameters.num_g2_elements_needed {
            return None;
        }

        SRS::from_vectors(g1, g2)
    }
}

impl UpdateProof {
    pub fn serialise(&self) -> [String; 2] {
        self.to_json_array()
    }

    fn to_json_array(&self) -> [String; 2] {
        let mut a = hex::encode(serialize_g2(&self.commitment_to_secret.into_affine()));
        a.insert_str(0, "0x");

        let mut b = hex::encode(serialize_g1(&self.new_accumulated_point.into_affine()));
        b.insert_str(0, "0x");

        [a, b]
    }
    pub fn deserialise(json_array: [String; 2]) -> Option<Self> {
        UpdateProof::from_json_array(json_array)
    }

    fn from_json_array(points_json_arr: [String; 2]) -> Option<Self> {
        let commitment_to_secret = hex_string_to_g2(&points_json_arr[0])?;
        let new_accumulated_point = hex_string_to_g1(&points_json_arr[1])?;

        Some(UpdateProof {
            commitment_to_secret,
            new_accumulated_point,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SRSJson {
    #[serde(rename = "numG1Powers")]
    num_g1_powers: usize,
    #[serde(rename = "numG2Powers")]
    num_g2_powers: usize,
    #[serde(rename = "powersOfTau")]
    powers_of_tau: PowerOfTau,
    #[serde(rename = "potPubkey")]
    pot_pubkey: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PowerOfTau {
    #[serde(rename = "G1Powers")]
    g1_powers: Vec<String>,
    #[serde(rename = "G2Powers")]
    g2_powers: Vec<String>,
}

impl From<&SRS> for SRSJson {
    fn from(srs: &SRS) -> Self {
        let g1s = srs.g1_elements();
        let g2s = srs.g2_elements();

        Self {
            num_g1_powers: g1s.len(),
            num_g2_powers: g2s.len(),
            powers_of_tau: PowerOfTau {
                g1_powers: SRS::g1s_to_json_array(g1s),
                g2_powers: SRS::g2s_to_json_array(g2s),
            },
            pot_pubkey: SRS::g2s_to_json_array(g2s).get(1).unwrap().to_string(),
        }
    }
}
impl From<&SRSJson> for Option<SRS> {
    fn from(srs: &SRSJson) -> Self {
        let parameters = Parameters {
            num_g1_elements_needed: srs.num_g1_powers,
            num_g2_elements_needed: srs.num_g2_powers,
        };
        SRS::deserialise(
            (&srs.powers_of_tau.g1_powers, &srs.powers_of_tau.g2_powers),
            parameters,
        )
    }
}
#[cfg(test)]
mod tests {
    use crate::keypair::PrivateKey;
    use ark_bls12_381::Fr;
    use ark_ec::ProjectiveCurve;
    use ark_ff::PrimeField;

    use super::*;
    #[test]
    fn update_proof_serialise_roundtrip() {
        let proof = UpdateProof {
            commitment_to_secret: G2Projective::prime_subgroup_generator()
                .mul(Fr::from(200u64).into_repr()),
            new_accumulated_point: G1Projective::prime_subgroup_generator()
                .mul(Fr::from(789u64).into_repr()),
        };

        let bytes = proof.serialise();
        let deserialised_proof = UpdateProof::deserialise(bytes).unwrap();

        assert_eq!(proof, deserialised_proof)
    }

    #[test]
    fn srs_serialise_roundtrip() {
        let params = Parameters {
            num_g1_elements_needed: 100,
            num_g2_elements_needed: 25,
        };

        let secret = PrivateKey::from_u64(5687);
        let mut acc = SRS::new(params).unwrap();
        acc.update(secret);

        let bytes = acc.serialise();
        let deserialised_srs = SRS::deserialise((&bytes.0, &bytes.1), params).unwrap();

        assert_eq!(acc, deserialised_srs);
    }
}
