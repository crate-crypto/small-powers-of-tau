use crate::{
    accumulator::{Accumulator, Parameters},
    update_proof::UpdateProof,
};
use ark_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::AffineCurve;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

// TODO: Once we specify how to deal with failure cases, make these methods return a Result
pub enum SubgroupCheck {
    // This is very expensive, each group element is multiplied by the order of the prime subgroup
    // The result is checked to be the identity.
    Full,
    // Only the first group element is checked. This should only be done for participants of the ceremony.
    Partial,
}
impl Accumulator {
    pub fn serialise(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        for g1 in &self.tau_g1 {
            g1.serialize_unchecked(&mut bytes).unwrap()
        }
        for g2 in &self.tau_g2 {
            g2.serialize_unchecked(&mut bytes).unwrap()
        }

        bytes
    }

    // TODO: modify this method to return a result.
    // TODO: what does a contributor do when they are given a zero element?
    pub fn deserialise(
        bytes: &[u8],
        parameters: Parameters,
        subgroup_check: SubgroupCheck,
    ) -> Self {
        // TODO: We need to deserialise into affine representation because arkworks does not have `is_on_curve` and `subgroup_check` for Projective representation
        let mut g1 = vec![G1Affine::prime_subgroup_generator(); parameters.num_g1_elements_needed];
        let mut g2 = vec![G2Affine::prime_subgroup_generator(); parameters.num_g2_elements_needed];

        let mut reader = std::io::Cursor::new(bytes);

        for element in g1.iter_mut() {
            *element = CanonicalDeserialize::deserialize_unchecked(&mut reader).unwrap();
            if element.is_zero() {
                panic!("unexpected zero point")
            }
        }
        for element in g2.iter_mut() {
            *element = CanonicalDeserialize::deserialize_unchecked(&mut reader).unwrap();
            if element.is_zero() {
                panic!("unexpected zero point")
            }
        }
        // Check if points are on the curve
        for element in &g1 {
            if !element.is_on_curve() {
                panic!("point is not on curve")
            }
        }
        for element in &g2 {
            if !element.is_on_curve() {
                panic!("point is not on curve")
            }
        }

        // This method should be used by participants, we only check that one element is in the group
        // then by induction and the structure of the SRS, the rest of the elements are in the group
        //
        // We actually make the check cheaper because we use the canonical generators,
        // so its just an equals check
        // TODO: write a proof for this -- assume it is unsafe
        let first_g1_element = g1[0];
        if first_g1_element != G1Affine::prime_subgroup_generator() {
            panic!("first g1 element is not the canonical prime subgroup generator")
        }
        let first_g2_element = g2[0];
        if first_g2_element != G2Affine::prime_subgroup_generator() {
            panic!("first g2 element is not the canonical prime subgroup generator")
        }

        if let SubgroupCheck::Full = subgroup_check {
            // TODO: swap this out by using the bowe endomorphism
            g1.par_iter().for_each(|element| {
                if !element.is_in_correct_subgroup_assuming_on_curve() {
                    panic!("point is not in the prime subgroup")
                }
            });
            g2.par_iter().for_each(|element| {
                if !element.is_in_correct_subgroup_assuming_on_curve() {
                    panic!("point is not in the prime subgroup")
                }
            });
        }

        Accumulator {
            tau_g1: g1
                .into_iter()
                .map(|element| element.into_projective())
                .collect(),
            tau_g2: g2
                .into_iter()
                .map(|element| element.into_projective())
                .collect(),
        }
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
    use ark_bls12_381::Fr;
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
        let deserialised_acc = Accumulator::deserialise(&bytes, params, SubgroupCheck::Full);

        assert_eq!(acc, deserialised_acc);
    }
}
