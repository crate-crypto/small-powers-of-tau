use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{Field, PrimeField, Zero};

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

}