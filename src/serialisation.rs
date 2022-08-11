use crate::interop_point_encoding;
use crate::{
    srs::{Parameters, SRS},
    update_proof::UpdateProof,
};
use ark_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read};

impl SRS {
    pub fn serialise(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let g1_points_affine = G1Projective::batch_normalization_into_affine(&self.tau_g1);
        let g2_points_affine = G2Projective::batch_normalization_into_affine(&self.tau_g2);

        for point in &g1_points_affine {
            let points_as_bytes = interop_point_encoding::serialize_g1(point);
            bytes.extend(points_as_bytes);
        }

        for point in &g2_points_affine {
            let points_as_bytes = interop_point_encoding::serialize_g2(point);
            bytes.extend(points_as_bytes);
        }

        bytes
    }

    // We do not check if the point is the identity when deserialising
    // What we do check, is that every point is a point on the curve
    pub fn deserialise(bytes: &[u8], parameters: Parameters) -> Result<Self, ()> {
        use crate::interop_point_encoding::{deserialize_g1, deserialize_g2};
        // TODO: We need to deserialise into affine representation because arkworks does not have `is_on_curve` and `subgroup_check` for Projective representation
        // TODO: its possible to deserialise and then do the checks first, then store it in the
        // TODO: vector
        let mut g1 = vec![G1Affine::prime_subgroup_generator(); parameters.num_g1_elements_needed];
        let mut g2 = vec![G2Affine::prime_subgroup_generator(); parameters.num_g2_elements_needed];

        let mut reader = std::io::Cursor::new(bytes);
        // TODO: note when we deserialise, we get the y coordinate using the x
        // TODO: coordinate, so we do not need to do a subgroup check
        for element in g1.iter_mut() {
            let mut point_bytes = [0u8; 48];
            reader.read_exact(&mut point_bytes).unwrap();
            *element = deserialize_g1(point_bytes);
        }
        for element in g2.iter_mut() {
            let mut point_bytes = [0u8; 96];
            reader.read_exact(&mut point_bytes).unwrap();
            *element = deserialize_g2(point_bytes);
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

        self.commitment_to_secret
            .serialize_uncompressed(&mut bytes)
            .unwrap();
        self.new_accumulated_point
            .serialize_uncompressed(&mut bytes)
            .unwrap();

        bytes
    }
    pub fn deserialise(bytes: &[u8]) -> Self {
        let mut reader = std::io::Cursor::new(bytes);

        let commitment_to_secret: G2Projective =
            CanonicalDeserialize::deserialize_uncompressed(&mut reader).unwrap();
        let new_accumulated_point: G1Projective =
            CanonicalDeserialize::deserialize_uncompressed(&mut reader).unwrap();

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
