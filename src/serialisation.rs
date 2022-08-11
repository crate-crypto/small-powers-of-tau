use crate::interop_point_encoding::{deserialize_g1, deserialize_g2, serialize_g1, serialize_g2};
use crate::{
    srs::{Parameters, SRS},
    update_proof::UpdateProof,
};
use ark_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::Zero;
use std::io::Read;

// TODO: use JSON serialisation strategy that is being used in the python specs

impl SRS {
    pub fn serialise(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let g1_points_affine = G1Projective::batch_normalization_into_affine(&self.tau_g1);
        let g2_points_affine = G2Projective::batch_normalization_into_affine(&self.tau_g2);

        for point in &g1_points_affine {
            let points_as_bytes = serialize_g1(point);
            bytes.extend(points_as_bytes);
        }

        for point in &g2_points_affine {
            let points_as_bytes = serialize_g2(point);
            bytes.extend(points_as_bytes);
        }

        bytes
    }

    // We do not check if the point is the identity when deserialising
    // What we do check, is that every point is a point on the curve
    pub fn deserialise(bytes: &[u8], parameters: Parameters) -> Result<Self, ()> {
        // TODO: We need to deserialise into affine representation because arkworks does not have `is_on_curve` and `subgroup_check` for Projective representation
        // TODO: its possible to deserialise and then do the checks first, then store it in the
        // TODO: vector
        let mut g1 = vec![G1Affine::prime_subgroup_generator(); parameters.num_g1_elements_needed];
        let mut g2 = vec![G2Affine::prime_subgroup_generator(); parameters.num_g2_elements_needed];

        let mut reader = std::io::Cursor::new(bytes);

        for element in g1.iter_mut() {
            let mut point_bytes = [0u8; 48];
            reader.read_exact(&mut point_bytes).unwrap();
            match deserialize_g1(point_bytes) {
                Some(des_point) => *element = des_point,
                None => return Err(()),
            };
        }
        for element in g2.iter_mut() {
            let mut point_bytes = [0u8; 96];
            reader.read_exact(&mut point_bytes).unwrap();
            match deserialize_g2(point_bytes) {
                Some(des_point) => *element = des_point,
                None => return Err(()),
            };
        }

        Ok(SRS {
            tau_g1: g1
                .into_iter()
                .map(|element| element.into_projective())
                .collect(),
            tau_g2: g2
                .into_iter()
                .map(|element| element.into_projective())
                .collect(),
        })
    }
}

impl UpdateProof {
    pub fn serialise(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let public_key_bytes = serialize_g2(&self.commitment_to_secret.into_affine());
        let update_point_bytes = serialize_g1(&self.new_accumulated_point.into_affine());

        bytes.extend(public_key_bytes);
        bytes.extend(update_point_bytes);

        bytes
    }
    pub fn deserialise(bytes: &[u8]) -> Self {
        let mut reader = std::io::Cursor::new(bytes);

        let mut point_bytes = [0u8; 96];
        reader.read_exact(&mut point_bytes).unwrap();
        let commitment_to_secret = deserialize_g2(point_bytes).unwrap();
        let commitment_to_secret = commitment_to_secret.into_projective();

        let mut point_bytes = [0u8; 48];
        reader.read_exact(&mut point_bytes).unwrap();
        let new_accumulated_point = deserialize_g1(point_bytes).unwrap();
        let new_accumulated_point = new_accumulated_point.into_projective();

        assert!(!commitment_to_secret.is_zero());
        assert!(!new_accumulated_point.is_zero());

        UpdateProof {
            commitment_to_secret,
            new_accumulated_point,
        }
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
        let deserialised_proof = UpdateProof::deserialise(&bytes);

        assert_eq!(proof, deserialised_proof)
    }

    #[test]
    fn srs_serialise_roundtrip() {
        let params = Parameters {
            num_g1_elements_needed: 100,
            num_g2_elements_needed: 25,
        };

        let secret = PrivateKey::from_u64(5687);
        let mut acc = SRS::new(params);
        acc.update(secret);

        let bytes = acc.serialise();
        let deserialised_srs = SRS::deserialise(&bytes, params).unwrap();

        assert_eq!(acc, deserialised_srs);
    }
}
