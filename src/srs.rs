use crate::{keypair::PrivateKey, update_proof::UpdateProof};
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::{msm::VariableBaseMSM, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, Zero};
use itertools::Itertools;

// Structured Reference String. Stores the powers of tau
// in G1 and G2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SRS {
    // #[serde(serialize_with = "serialize_vec_g1s", rename = "G1Powers")]
    tau_g1: Vec<G1Projective>,
    // #[serde(serialize_with = "serialize_vec_g2s", rename = "G2Powers")]
    tau_g2: Vec<G2Projective>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameters {
    pub(crate) num_g1_elements_needed: usize,
    pub(crate) num_g2_elements_needed: usize,
}

impl Parameters {
    pub fn new(num_g1: usize, num_g2: usize) -> Self {
        Parameters {
            num_g1_elements_needed: num_g1,
            num_g2_elements_needed: num_g2,
        }
    }
}

impl SRS {
    // Creates a powers of tau ceremony.
    // This is not compatible with the BGM17 Groth16 powers of tau ceremony (notice there is no \alpha, \beta)
    pub fn new(parameters: Parameters) -> Option<SRS> {
        let g1s = vec![G1Projective::prime_subgroup_generator(); parameters.num_g1_elements_needed];
        let g2s = vec![G2Projective::prime_subgroup_generator(); parameters.num_g2_elements_needed];
        SRS::from_vectors(g1s, g2s)
    }
    pub fn from_vectors(g1s: Vec<G1Projective>, g2s: Vec<G2Projective>) -> Option<SRS> {
        let cond = g1s.len() > 1 && g2s.len() > 1;
        if !cond {
            return None;
        } else {
            Some(SRS {
                tau_g1: g1s,
                tau_g2: g2s,
            })
        }
    }

    pub fn g1_elements(&self) -> &[G1Projective] {
        &self.tau_g1
    }
    pub fn g2_elements(&self) -> &[G2Projective] {
        &self.tau_g2
    }

    // Returns the degree-1 element as a summary of the SRS
    pub fn summary(&self) -> String {
        let mut point_as_hex = hex::encode(crate::interop_point_encoding::serialize_g1(
            &self.tau_g1[1].into_affine(),
        ));
        point_as_hex.insert_str(0, "0x");
        point_as_hex
    }

    // Creates a ceremony for the kzg polynomial commitment scheme
    // One should input the number of coefficients for the polynomial with the
    // highest degree that you wish to use kzg with.
    //
    // Example; a degree 2 polynomial has 3 coefficients ax^0 + bx^1 + cx^2
    #[cfg(test)]
    #[deprecated(
        note = "this is not applicable for the ethereum context, so we can eventually remove"
    )]
    pub(crate) fn new_for_kzg(num_coefficients: usize) -> SRS {
        // The amount of G2 elements needed for KZG based commitment schemes
        const NUM_G2_ELEMENTS_NEEDED: usize = 2;

        let params = Parameters {
            num_g1_elements_needed: num_coefficients,
            num_g2_elements_needed: NUM_G2_ELEMENTS_NEEDED,
        };

        SRS::new(params).unwrap()
    }

    // Updates the srs and produces a proof of this update
    pub fn update(&mut self, private_key: PrivateKey) -> UpdateProof {
        self.update_srs(private_key.tau);
        let updated_tau = self.tau_g1[1];

        UpdateProof {
            commitment_to_secret: private_key.to_public(),
            new_accumulated_point: updated_tau,
        }
    }

    // Updates the group elements using a users private key
    fn update_srs(&mut self, private_key: Fr) {
        use ark_ec::wnaf::WnafContext;

        #[cfg(feature = "parallel")]
        use rayon::prelude::*;

        let max_number_elements = std::cmp::max(self.tau_g1.len(), self.tau_g2.len());

        let powers_of_priv_key = vandemonde_challenge(private_key, max_number_elements - 1);

        let wnaf = WnafContext::new(3);

        ark_std::cfg_iter_mut!(self.tau_g1)
            // Skip the degree-0 element as it does not get updated
            .skip(1)
            .zip(&powers_of_priv_key)
            .for_each(|(tg1, priv_pow)| {
                *tg1 = wnaf.mul(*tg1, priv_pow);
            });

        ark_std::cfg_iter_mut!(self.tau_g2)
            // Skip the degree-0 element as it does not get updated
            .skip(1)
            .zip(&powers_of_priv_key)
            .for_each(|(tg2, priv_pow)| {
                *tg2 = wnaf.mul(*tg2, priv_pow);
            })
    }

    // Verify whether the transition from one SRS to the other was valid
    //
    // After the ceremony is over, an actor whom wants to verify that the ceremony was
    // was done correctly will collect all of the updates from the ceremony, along with
    // the starting and ending SRS in order to call this method.
    pub fn verify_updates(
        before: &SRS,
        after: &SRS,
        update_proofs: &[UpdateProof],
        random_element: Fr,
    ) -> bool {
        // If there are no update proofs and the user calls this method
        // we return False regardless. Even if `before===after`
        // We do not accept a transition without a proof
        let last_update = match update_proofs.last() {
            Some(update) => update,
            None => return false,
        };

        // 1. Check that the updates finished at the ending SRS
        if after.tau_g1[1] != last_update.new_accumulated_point {
            return false;
        }

        // 2. Check the update proofs are correct and form a chain of updates
        if !UpdateProof::verify_chain(before.tau_g1[1], update_proofs) {
            return false;
        }

        // 3. Check that the degree-1 component is not the identity element
        // No need to check the other elements because the structure check will fail
        // if they are also not the identity element
        //
        // Since resulting SRS is not zero, it implies that the private key/randomness
        // used was also not zero. Which implies that the public key inside of the
        // update proof is not the identity element or the update proof check will fail.
        if after.tau_g1[1].is_zero() {
            return false;
        }
        if after.tau_g2[1].is_zero() {
            return false;
        }

        // 3. Check that the new SRS goes up in incremental powers
        if !after.structure_check_opt(random_element) {
            return false;
        }

        true
    }

    // Check that the list of G1 and G2 elements are in the
    // prime order subgroup
    // These points are already checked to be on the curve which is _cheap_
    // so that we do not become victim to the invalid curve attack
    pub fn subgroup_check(&self) -> bool {
        use crate::interop_subgroup_checks::{g1, g2};

        let g1_points_affine = G1Projective::batch_normalization_into_affine(&self.tau_g1);
        let g2_points_affine = G2Projective::batch_normalization_into_affine(&self.tau_g2);
        for point in g1_points_affine {
            if !g1::is_in_correct_subgroup_assuming_on_curve(&point) {
                return false;
            }
        }
        for point in g2_points_affine {
            if !g2::is_in_correct_subgroup_assuming_on_curve(&point) {
                return false;
            }
        }

        true
    }

    // Verify that a single update was applied to transition `before` to `after`
    // This method will be used during the Ceremony by the Coordinator, when
    // they receive a contribution from a contributor
    pub fn verify_update(
        before: &SRS,
        after: &SRS,
        update_proof: &UpdateProof,
        random_element: Fr,
    ) -> bool {
        SRS::verify_updates(before, after, &[*update_proof], random_element)
    }

    // We detail the algorithm here: https://hackmd.io/C0lk1xyWQryGggRlNYDqZw#Appendix-1---Incremental-powers-of-tau-check-Batching
    // This allows us to check that the SRS has the correct structure using only 1 pairing
    pub fn structure_check_opt(&self, random_element: Fr) -> bool {
        // Check will always pass if the random element is zero
        // We return false in this case
        if random_element.is_zero() {
            return false;
        }

        let len_g1 = self.tau_g1.len();
        let len_g2 = self.tau_g2.len();

        let max_number_elements = std::cmp::max(len_g1, len_g2);
        let rand_pow = vandemonde_challenge(random_element, max_number_elements - 1);

        let tau_g2_0 = self.tau_g2[0];
        let tau_g2_1 = self.tau_g2[1];

        let tau_g1_0 = self.tau_g1[0];
        let tau_g1_1 = self.tau_g1[1];

        let scalars = rand_pow
            .into_iter()
            .map(|scalar| scalar.into_repr())
            .collect_vec();

        // All elements in G1 except the last element
        let L = &self.tau_g1[0..len_g1 - 1];
        assert_eq!(L.len(), len_g1 - 1);

        // All elements in G1 except the first element
        let R = &self.tau_g1[1..];
        assert_eq!(R.len(), len_g1 - 1);

        let L_comm = VariableBaseMSM::multi_scalar_mul(
            &L.iter().map(|element| element.into_affine()).collect_vec(),
            &scalars,
        );
        let R_comm = VariableBaseMSM::multi_scalar_mul(
            &R.iter().map(|element| element.into_affine()).collect_vec(),
            &scalars,
        );
        let p1 = ark_bls12_381::Bls12_381::pairing(L_comm, tau_g2_1);
        let p2 = ark_bls12_381::Bls12_381::pairing(R_comm, tau_g2_0);

        if p1 != p2 {
            return false;
        }

        // Check G2

        // All elements in G2 except the last element
        let L = &self.tau_g2[0..len_g2 - 1];
        assert_eq!(L.len(), len_g2 - 1);

        // All elements in G2 except the first element
        let R = &self.tau_g2[1..];
        assert_eq!(R.len(), len_g2 - 1);

        let L_comm = VariableBaseMSM::multi_scalar_mul(
            &L.iter().map(|element| element.into_affine()).collect_vec(),
            &scalars,
        );
        let R_comm = VariableBaseMSM::multi_scalar_mul(
            &R.iter().map(|element| element.into_affine()).collect_vec(),
            &scalars,
        );

        let p1 = ark_bls12_381::Bls12_381::pairing(tau_g1_1, L_comm);
        let p2 = ark_bls12_381::Bls12_381::pairing(tau_g1_0, R_comm);

        p1 == p2
    }

    // Inefficiently checks that the srs has the correct structure
    // Meaning each subsequent element is increasing the index of tau for both G_1 and G_2 elements
    fn structure_check(&self) -> bool {
        let tau_g2_0 = self.tau_g2[0];
        let tau_g2_1 = self.tau_g2[1];

        let tau_g1_0 = self.tau_g1[0];
        let tau_g1_1 = self.tau_g1[1];

        // Check G_1 elements
        let power_pairs = self.tau_g1.as_slice().windows(2);
        for pair in power_pairs {
            let tau_i = pair[0]; // tau^i
            let tau_i_next = pair[1]; // tau^{i+1}
            let p1 = ark_bls12_381::Bls12_381::pairing(tau_i_next, tau_g2_0);
            let p2 = ark_bls12_381::Bls12_381::pairing(tau_i, tau_g2_1);
            if p1 != p2 {
                return false;
            }
        }

        // Check G_2 elements
        let power_pairs = self.tau_g2.as_slice().windows(2);
        for pair in power_pairs {
            let tau_i = pair[0]; // tau^i
            let tau_i_next = pair[1]; // tau^{i+1}
            let p1 = ark_bls12_381::Bls12_381::pairing(tau_g1_0, tau_i_next);
            let p2 = ark_bls12_381::Bls12_381::pairing(tau_g1_1, tau_i);
            if p1 != p2 {
                return false;
            }
        }

        true
    }
}

fn vandemonde_challenge(x: Fr, n: usize) -> Vec<Fr> {
    let mut challenges: Vec<Fr> = Vec::with_capacity(n);
    challenges.push(x);
    for i in 0..n - 1 {
        challenges.push(challenges[i] * x);
    }
    challenges
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Field, One, PrimeField};
    #[test]
    fn reject_private_key_zero() {
        // This test ensures that one cannot update the SRS using 0

        let before = SRS::new_for_kzg(100);
        let mut after = before.clone();

        let secret = PrivateKey::from_u64(0);
        let update_proof = after.update(secret);

        assert!(!SRS::verify_update(
            &before,
            &after,
            &update_proof,
            Fr::from(123456789)
        ));
    }
    #[test]
    fn zero_pow_zero() {
        // This test checks that 0^0  = 1
        // This can only happen if a user decides to use 0 as their private key
        // which is rejected anyways. This is only needed for tests.
        //
        // Note that in the wnaf update method, we do not modify the degree-0 element
        // which has the same effect when 0^0 = 1
        let secret = PrivateKey::from_u64(0);
        let value = secret.tau.pow(&[0]);

        assert!(value.is_one())
    }

    #[test]
    fn update_works() {
        // This test ensures that when we update the SRS, it is being updated
        // correctly

        let mut got_srs = SRS::new_for_kzg(100);
        let mut expected_srs = got_srs.clone();

        let secret = PrivateKey::from_u64(123456789);
        let secret_fr = secret.tau.clone();

        got_srs.update(secret);

        for (index, tg1) in expected_srs.tau_g1.iter_mut().enumerate() {
            let secret_pow_i = secret_fr.pow(&[index as u64]);
            *tg1 = tg1.mul(secret_pow_i.into_repr())
        }
        for (index, tg2) in expected_srs.tau_g2.iter_mut().enumerate() {
            let secret_pow_i = secret_fr.pow(&[index as u64]);
            *tg2 = tg2.mul(secret_pow_i.into_repr())
        }

        assert_eq!(expected_srs, got_srs)
    }

    #[test]
    fn acc_smoke() {
        let secret_a = PrivateKey::from_u64(252);
        let secret_b = PrivateKey::from_u64(512);
        let secret_c = PrivateKey::from_u64(789);

        let mut acc = SRS::new_for_kzg(100);

        // Simulate 3 participants updating the srs, one after the other
        let before_update_1_degree_1 = acc.tau_g1[1];
        let update_proof_1 = acc.update(secret_a);

        let update_proof_2 = acc.update(secret_b);

        let update_proof_3 = acc.update(secret_c);

        // Here we also verify the chain, if elements in the vector are out of place, the proof will also fail
        assert!(UpdateProof::verify_chain(
            before_update_1_degree_1,
            &[update_proof_1, update_proof_2, update_proof_3,]
        ));
    }

    #[test]
    fn structure_checks_probabilistic() {
        let secret_a = PrivateKey::from_u64(252);

        let mut acc = SRS::new_for_kzg(100);
        acc.update(secret_a);
        assert!(acc.structure_check_opt(Fr::from(100u64)));
    }
}
