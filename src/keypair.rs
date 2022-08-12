use ark_bls12_381::{Fr, G2Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::{PrimeField, UniformRand};
use rand::Rng;
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct PrivateKey {
    pub(crate) tau: Fr,
}

impl PrivateKey {
    // This function should only be used for testing purposes
    #[cfg(test)]
    pub(crate) fn from_u64(int: u64) -> Self {
        Self { tau: Fr::from(int) }
    }
    // Creates a private key using entropy from a RNG
    pub fn rand<R: Rng>(mut rand: R) -> Self {
        PrivateKey {
            tau: Fr::rand(&mut rand),
        }
    }
    // Creates a private key using bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        PrivateKey {
            tau: Fr::from_be_bytes_mod_order(bytes),
        }
    }
}

impl PrivateKey {
    // Converts a private key into a public key
    pub fn to_public(self) -> G2Projective {
        let gen_g2 = G2Projective::prime_subgroup_generator();
        gen_g2.mul(self.tau.into_repr())
    }
}
