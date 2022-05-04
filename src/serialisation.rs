use crate::{
    accumulator::{Accumulator, Parameters},
    update_proof::UpdateProof,
};
use ark_bn254::{G1Projective, G2Projective};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

// TODO: Once we specify how to deal with failure cases, make these methods return a Result

impl Accumulator {
    pub fn serialise(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        for g1 in &self.tau_g1 {
            g1.serialize_uncompressed(&mut bytes).unwrap()
        }
        for g2 in &self.tau_g2 {
            g2.serialize_uncompressed(&mut bytes).unwrap()
        }

        bytes
    }
    // TODO: modify this method to return a result.
    // TODO: what does a contributor do when they are given a zero element?
    pub fn deserialise(bytes: &[u8], parameters: Parameters) -> Self {
        let mut acc = Accumulator::new(parameters);

        let mut reader = std::io::Cursor::new(bytes);

        for g1 in acc.tau_g1.iter_mut() {
            *g1 = CanonicalDeserialize::deserialize_uncompressed(&mut reader).unwrap();
            if g1.is_zero() {
                panic!("unexpected zero point")
            }
        }
        for g2 in acc.tau_g2.iter_mut() {
            *g2 = CanonicalDeserialize::deserialize_uncompressed(&mut reader).unwrap();
            if g2.is_zero() {
                panic!("unexpected zero point")
            }
        }

        acc
    }
}

impl PartialEq for UpdateProof {
    fn eq(&self, other: &Self) -> bool {
        self.commitment_to_secret == other.commitment_to_secret
            && self.previous_accumulated_point == other.previous_accumulated_point
            && self.new_accumulated_point == other.new_accumulated_point
    }
}

impl PartialEq for Accumulator {
    fn eq(&self, other: &Self) -> bool {
        self.tau_g1 == other.tau_g1 && self.tau_g2 == other.tau_g2
    }
}

impl UpdateProof {
    pub fn serialise(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        self.commitment_to_secret
            .serialize_uncompressed(&mut bytes)
            .unwrap();
        self.previous_accumulated_point
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
        let previous_accumulated_point: G1Projective =
            CanonicalDeserialize::deserialize_uncompressed(&mut reader).unwrap();
        let new_accumulated_point: G1Projective =
            CanonicalDeserialize::deserialize_uncompressed(&mut reader).unwrap();

        assert!(!commitment_to_secret.is_zero());
        assert!(!previous_accumulated_point.is_zero());
        assert!(!new_accumulated_point.is_zero());

        UpdateProof {
            commitment_to_secret,
            previous_accumulated_point,
            new_accumulated_point,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::keypair::PrivateKey;
    use ark_bn254::Fr;
    use ark_ec::ProjectiveCurve;
    use ark_ff::PrimeField;

    use super::*;

    #[test]
    fn update_proof_serialise_roundtrip() {
        let proof = UpdateProof {
            commitment_to_secret: G2Projective::prime_subgroup_generator()
                .mul(Fr::from(200u64).into_repr()),
            previous_accumulated_point: G1Projective::prime_subgroup_generator()
                .mul(Fr::from(888u64).into_repr()),
            new_accumulated_point: G1Projective::prime_subgroup_generator()
                .mul(Fr::from(789u64).into_repr()),
        };

        let bytes = proof.serialise();
        let deserialised_proof = UpdateProof::deserialise(&bytes);

        assert_eq!(proof, deserialised_proof)
    }

    #[test]
    fn accumulator_serialise_roundtrip() {
        let params = Parameters {
            num_g1_elements_needed: 100,
            num_g2_elements_needed: 25,
        };

        let secret = PrivateKey::from_u64(5687);
        let mut acc = Accumulator::new(params);
        acc.update(secret);

        let bytes = acc.serialise();
        let deserialised_acc = Accumulator::deserialise(&bytes, params);

        assert_eq!(acc, deserialised_acc);
    }
}
