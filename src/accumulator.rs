use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{Field, PrimeField, Zero};

use crate::{keypair::PrivateKey, update_proof::UpdateProof};

#[derive(Debug, Clone)]
pub struct Accumulator {
    pub(crate) tau_g1: Vec<G1Affine>,
    pub(crate) tau_g2: Vec<G2Affine>,
}
#[derive(Debug, Clone, Copy)]
pub struct Parameters {
    pub(crate) num_g1_elements_needed: usize,
    pub(crate) num_g2_elements_needed: usize,
}
impl Accumulator {
    // Creates a powers of tau ceremony.
    // This is not compatible with the BGM17 Groth16 powers of tau ceremony (notice there is no \alpha, \beta)
    pub fn new(parameters: Parameters) -> Accumulator {
        Self {
            tau_g1: vec![G1Affine::prime_subgroup_generator(); parameters.num_g1_elements_needed],
            tau_g2: vec![G2Affine::prime_subgroup_generator(); parameters.num_g2_elements_needed],
        }
    }

    // Creates a ceremony for the kzg polynomial commitment scheme
    // One should input the number of coefficients for the polynomial with the
    // highest degree that you wish to use kzg with.
    //
    // Example; a degree 2 polynomial has 3 coefficients ax^0 + bx^1 + cx^2
    pub fn new_for_kzg(num_coefficients: usize) -> Accumulator {
        // The amount of G2 elements needed for KZG based commitment schemes
        const NUM_G2_ELEMENTS_NEEDED: usize = 2;

        let params = Parameters {
            num_g1_elements_needed: num_coefficients,
            num_g2_elements_needed: NUM_G2_ELEMENTS_NEEDED,
        };

        Accumulator::new(params)
    }

    // Updates the accumulator and produces a proof of this update
    pub fn update(&mut self, private_key: PrivateKey) -> UpdateProof {
        // Save the previous s*G_1 element, then update the accumulator and save the new s*private_key*G_1 element
        let previous_tau = self.tau_g1[1].into_projective();
        self.update_accumulator(private_key.tau);
        let updated_tau = self.tau_g1[1].into_projective();

        UpdateProof {
            commitment_to_secret: private_key.to_public(),
            previous_accumulated_point: previous_tau,
            new_accumulated_point: updated_tau,
        }
    }

    // Inefficiently, updates the group elements using a users private key
    fn update_accumulator(&mut self, private_key: Fr) {
        // TODO use rayon
        for (i, tg1) in self.tau_g1.iter_mut().enumerate() {
            let exponent: Fr = (i as u64).into();
            let tau_pow = private_key.pow(exponent.into_repr());

            *tg1 = tg1.mul(tau_pow.into_repr()).into();
        }
        for (i, tg2) in self.tau_g2.iter_mut().enumerate() {
            let exponent: Fr = (i as u64).into();
            let tau_pow = private_key.pow(exponent.into_repr());

            *tg2 = tg2.mul(tau_pow.into_repr()).into();
        }
    }

    // Verify whether the transition from one SRS to the other was valid
    //
    // Most of the time, there will be a single update proof for verifying that a contribution did indeed update the SRS correctly.
    //
    // After the ceremony is over, one may use this method to check all update proofs that were given in the ceremony
    pub fn verify_updates(
        // TODO: We do not _need_ the whole `before` accumulator, this API is just a bit cleaner
        before: &Accumulator,
        after: &Accumulator,
        update_proofs: &[UpdateProof],
    ) -> bool {
        let first_update = update_proofs.first().expect("expected at least one update");
        let last_update = update_proofs.last().expect("expected at least one update");

        // 1a. Check that the updates started from the starting SRS
        if before.tau_g1[1] != first_update.previous_accumulated_point {
            return false;
        }
        // 1b.Check that the updates finished at the ending SRS
        if after.tau_g1[1] != last_update.new_accumulated_point {
            return false;
        }

        // 2. Check the update proofs are correct and form a chain of updates
        if !UpdateProof::verify_chain(update_proofs) {
            return false;
        }

        // 3. Check that the degree-0 component is not the identity element
        // No need to check the other elements because the structure check will fail
        // if they are also not the identity element
        if after.tau_g1[0].is_zero() {
            return false;
        }
        if after.tau_g2[0].is_zero() {
            return false;
        }

        // 3. Check that the new SRS goes up in incremental powers
        if !after.structure_check() {
            return false;
        }

        true
    }

    pub fn verify_update(
        before: &Accumulator,
        after: &Accumulator,
        update_proof: &UpdateProof,
    ) -> bool {
        Accumulator::verify_updates(before, after, &[*update_proof])
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
            let p1 = ark_bn254::Bn254::pairing(tau_i_next, tau_g2_0);
            let p2 = ark_bn254::Bn254::pairing(tau_i, tau_g2_1);
            if p1 != p2 {
                return false;
            }
        }

        // Check G_2 elements
        let power_pairs = self.tau_g2.as_slice().windows(2);
        for pair in power_pairs {
            let tau_i = pair[0]; // tau^i
            let tau_i_next = pair[1]; // tau^{i+1}
            let p1 = ark_bn254::Bn254::pairing(tau_g1_0, tau_i_next);
            let p2 = ark_bn254::Bn254::pairing(tau_g1_1, tau_i);
            if p1 != p2 {
                return false;
            }
        }

        true
    }
}

#[test]
fn reject_private_key_one() {
    // This test ensures that one cannot update the SRS using either 0 or 1

    let before = Accumulator::new_for_kzg(100);
    let mut after = before.clone();

    let secret = PrivateKey::from_u64(1);
    let update_proof = after.update(secret);

    assert!(!Accumulator::verify_update(&before, &after, &update_proof));
}
#[test]
fn reject_private_key_zero() {
    // This test ensures that one cannot update the SRS using either 0 or 1

    let before = Accumulator::new_for_kzg(100);
    let mut after = before.clone();

    let secret = PrivateKey::from_u64(0);
    let update_proof = after.update(secret);

    assert!(!Accumulator::verify_update(&before, &after, &update_proof));
}

#[test]
fn acc_fuzz() {
    let secret_a = PrivateKey::from_u64(252);
    let secret_b = PrivateKey::from_u64(512);
    let secret_c = PrivateKey::from_u64(789);

    let mut acc = Accumulator::new_for_kzg(100);

    // Simulate 3 participants updating the accumulator, one after the other
    let update_proof_1 = acc.update(secret_a);
    let update_proof_2 = acc.update(secret_b);
    let update_proof_3 = acc.update(secret_c);

    // This verifies each update proof makes the correct transition, but it does not link
    // the update proofs, so these could in theory be updates to different accumulators
    assert!(update_proof_1.verify());
    assert!(update_proof_2.verify());
    assert!(update_proof_3.verify());

    // Here we also verify the chain, if elements in the vector are out of place, the proof will also fail
    assert!(UpdateProof::verify_chain(&[
        update_proof_1,
        update_proof_2,
        update_proof_3,
    ]));
}
