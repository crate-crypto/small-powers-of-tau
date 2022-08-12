use crate::interop_point_encoding::{g1_from_reader, g2_from_reader, serialize_g1, serialize_g2};
use crate::{
    srs::{Parameters, SRS},
    update_proof::UpdateProof,
};
use ark_bls12_381::{G1Projective, G2Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};

// TODO: use JSON serialisation strategy that is being used in the python specs

impl SRS {
    pub fn serialise(&self) -> Vec<u8> {
        self.to_bytes()
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let g1_points_affine = G1Projective::batch_normalization_into_affine(&self.tau_g1);
        let g2_points_affine = G2Projective::batch_normalization_into_affine(&self.tau_g2);

        for point in &g1_points_affine {
            bytes.extend(serialize_g1(point));
        }

        for point in &g2_points_affine {
            bytes.extend(serialize_g2(point));
        }

        bytes
    }

    // We do not check if the point is the identity when deserialising
    // What we do check, is that every point is a point on the curve
    pub fn deserialise(bytes: &[u8], parameters: Parameters) -> Option<Self> {
        SRS::from_bytes(bytes, parameters)
    }
    fn from_bytes(bytes: &[u8], parameters: Parameters) -> Option<Self> {
        let mut g1 = vec![G1Projective::default(); parameters.num_g1_elements_needed];
        let mut g2 = vec![G2Projective::default(); parameters.num_g2_elements_needed];

        let mut reader = std::io::Cursor::new(bytes);

        for element in g1.iter_mut() {
            let deserialised_point = g1_from_reader(&mut reader)?;
            *element = deserialised_point.into_projective()
        }
        for element in g2.iter_mut() {
            let deserialised_point = g2_from_reader(&mut reader)?;
            *element = deserialised_point.into_projective()
        }

        Some(SRS {
            tau_g1: g1,
            tau_g2: g2,
        })
    }
}

impl UpdateProof {
    pub fn serialise(&self) -> Vec<u8> {
        self.to_bytes()
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let public_key_bytes = serialize_g2(&self.commitment_to_secret.into_affine());
        let update_point_bytes = serialize_g1(&self.new_accumulated_point.into_affine());

        bytes.extend(public_key_bytes);
        bytes.extend(update_point_bytes);

        bytes
    }
    pub fn deserialise(bytes: &[u8]) -> Option<Self> {
        UpdateProof::from_bytes(bytes)
    }
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut reader = std::io::Cursor::new(bytes);

        let commitment_to_secret = g2_from_reader(&mut reader)?.into_projective();
        let new_accumulated_point = g1_from_reader(&mut reader)?.into_projective();

        Some(UpdateProof {
            commitment_to_secret,
            new_accumulated_point,
        })
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
        let deserialised_proof = UpdateProof::deserialise(&bytes).unwrap();

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
