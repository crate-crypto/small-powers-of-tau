use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField, Zero};

use crate::{keypair::PrivateKey, update_proof::UpdateProof};

// Structured Reference String. Stores the powers of tau
// in G1 and G2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SRS {
    pub(crate) tau_g1: Vec<G1Projective>,
    pub(crate) tau_g2: Vec<G2Projective>,
}
// TODO: we can add the starting points here too
#[derive(Debug, Clone, Copy)]
pub struct Parameters {
    pub num_g1_elements_needed: usize,
    pub num_g2_elements_needed: usize,
}
impl SRS {
    // Creates a powers of tau ceremony.
    // This is not compatible with the BGM17 Groth16 powers of tau ceremony (notice there is no \alpha, \beta)
    pub fn new(parameters: Parameters) -> SRS {
        Self {
            tau_g1: vec![
                G1Projective::prime_subgroup_generator();
                parameters.num_g1_elements_needed
            ],
            tau_g2: vec![
                G2Projective::prime_subgroup_generator();
                parameters.num_g2_elements_needed
            ],
        }
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

        SRS::new(params)
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
    // TODO: add an in-efficient version without wnaf
    fn update_srs(&mut self, private_key: Fr) {
        use ark_ec::wnaf::WnafContext;
        use rayon::prelude::*;

        let max_number_elements = std::cmp::max(self.tau_g1.len(), self.tau_g2.len());

        let powers_of_priv_key = vandemonde_challenge(private_key, max_number_elements);

        let wnaf = WnafContext::new(3);

        self.tau_g1
            .par_iter_mut()
            .skip(1)
            .zip(&powers_of_priv_key)
            .for_each(|(tg1, priv_pow)| {
                *tg1 = wnaf.mul(*tg1, priv_pow);
            });

        self.tau_g2
            .par_iter_mut()
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
    pub fn verify_updates(before: &SRS, after: &SRS, update_proofs: &[UpdateProof]) -> bool {
        let last_update = update_proofs.last().expect("expected at least one update");

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
        if after.tau_g1[1].is_zero() {
            return false;
        }
        if after.tau_g2[1].is_zero() {
            return false;
        }

        // 3. Check that the new SRS goes up in incremental powers
        if !after.structure_check() {
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

        return true;
    }

    // Verify that a single update was applied to transition `before` to `after`
    // This method will be used during the Ceremony by the Coordinator, when
    // they receive a contribution from a contributor
    pub fn verify_update(before: &SRS, after: &SRS, update_proof: &UpdateProof) -> bool {
        SRS::verify_updates(before, after, &[*update_proof])
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

#[test]
fn reject_private_key_zero() {
    // This test ensures that one cannot update the SRS using 0

    let before = SRS::new_for_kzg(100);
    let mut after = before.clone();

    let secret = PrivateKey::from_u64(0);
    let update_proof = after.update(secret);

    assert!(!SRS::verify_update(&before, &after, &update_proof));
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

    let before_update_2_degree_1 = acc.tau_g1[1];
    let update_proof_2 = acc.update(secret_b);

    let before_update_3_degree_1 = acc.tau_g1[1];
    let update_proof_3 = acc.update(secret_c);

    // This verifies each update proof makes the correct transition, but it does not link
    // the update proofs, so these could in theory be updates to different srs
    assert!(update_proof_1.verify(before_update_1_degree_1));
    assert!(update_proof_2.verify(before_update_2_degree_1));
    assert!(update_proof_3.verify(before_update_3_degree_1));

    // Here we also verify the chain, if elements in the vector are out of place, the proof will also fail
    assert!(UpdateProof::verify_chain(
        before_update_1_degree_1,
        &[update_proof_1, update_proof_2, update_proof_3,]
    ));
}
