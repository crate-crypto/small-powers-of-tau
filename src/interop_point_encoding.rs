//  The problem is that the arkworks encoding is not consistent with the "official" encoding for bls12_381
// So this wrapper code is needed.
//
// Code was adapted from zkcrypto/bls12-381
// This should NOT be audited.
use ark_bls12_381::{Fq, G1Affine, G2Affine};
use ark_ff::{BigInteger384, Fp2, PrimeField};

fn serialize_g2_x(p: &G2Affine) -> [u8; 96] {
    let mut result = [0u8; 96];

    let c1_bytes = serialise_fq(p.x.c1);
    let c0_bytes = serialise_fq(p.x.c0);
    (&mut result[0..48]).copy_from_slice(&c1_bytes[..]);
    (&mut result[48..96]).copy_from_slice(&c0_bytes[..]);

    result
}
fn serialize_g1_x(p: &G1Affine) -> [u8; 48] {
    return serialise_fq(p.x);
}

fn serialise_fq(field: Fq) -> [u8; 48] {
    let mut result = [0u8; 48];

    let rep = field.into_repr();

    result[0..8].copy_from_slice(&rep.0[5].to_be_bytes());
    result[8..16].copy_from_slice(&rep.0[4].to_be_bytes());
    result[16..24].copy_from_slice(&rep.0[3].to_be_bytes());
    result[24..32].copy_from_slice(&rep.0[2].to_be_bytes());
    result[32..40].copy_from_slice(&rep.0[1].to_be_bytes());
    result[40..48].copy_from_slice(&rep.0[0].to_be_bytes());

    result
}

fn deserialise_fq(bytes: [u8; 48]) -> Fq {
    let mut tmp = BigInteger384([0, 0, 0, 0, 0, 0]);

    tmp.0[5] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());
    tmp.0[4] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
    tmp.0[3] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
    tmp.0[2] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());
    tmp.0[1] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap());
    tmp.0[0] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap());

    Fq::from_repr(tmp).unwrap()
}

pub fn deserialize_g1(bytes: [u8; 48]) -> G1Affine {
    // Obtain the three flags from the start of the byte sequence
    let flags = EncodingFlags::get_flags(&bytes[..]);

    if !flags.is_compressed {
        unimplemented!("uncompressed serialisation is not implemented")
    }

    if flags.is_infinity {
        return G1Affine::default();
    }
    // Attempt to obtain the x-coordinate
    let x = {
        let mut tmp = [0; 48];
        tmp.copy_from_slice(&bytes[0..48]);

        // Mask away the flag bits
        tmp[0] &= 0b0001_1111;

        deserialise_fq(tmp)
    };

    G1Affine::get_point_from_x(x, flags.is_lexographically_largest).unwrap()
}

// TODO: return optional here instead
pub fn deserialize_g2(bytes: [u8; 96]) -> G2Affine {
    // Obtain the three flags from the start of the byte sequence
    let flags = EncodingFlags::get_flags(&bytes);

    if flags.is_infinity {
        return G2Affine::default();
    }
    if !flags.is_compressed {
        unimplemented!("uncompressed serialisation is not implemented")
    }

    // Attempt to obtain the x-coordinate
    let xc1 = {
        let mut tmp = [0; 48];
        tmp.copy_from_slice(&bytes[0..48]);

        // Mask away the flag bits
        tmp[0] &= 0b0001_1111;

        deserialise_fq(tmp)
    };
    let xc0 = {
        let mut tmp = [0; 48];
        tmp.copy_from_slice(&bytes[48..96]);

        deserialise_fq(tmp)
    };

    let x = Fp2::new(xc0, xc1);

    G2Affine::get_point_from_x(x, flags.is_lexographically_largest).unwrap()
}

struct EncodingFlags {
    is_compressed: bool,
    is_infinity: bool,
    is_lexographically_largest: bool,
}

impl EncodingFlags {
    fn get_flags(bytes: &[u8]) -> Self {
        let compression_flag_set = (bytes[0] >> 7) & 1;
        let infinity_flag_set = (bytes[0] >> 6) & 1;
        let sort_flag_set = (bytes[0] >> 5) & 1;

        Self {
            is_compressed: compression_flag_set == 1,
            is_infinity: infinity_flag_set == 1,
            is_lexographically_largest: sort_flag_set == 1,
        }
    }
    fn encode_flags(&self, bytes: &mut [u8]) {
        if self.is_compressed {
            bytes[0] |= 1 << 7;
        }

        if self.is_infinity {
            bytes[0] |= 1 << 6;
        }

        if self.is_compressed && !self.is_infinity && self.is_lexographically_largest {
            bytes[0] |= 1 << 5;
            return;
        }
    }
}

// fn add_encoding(result: &mut [u8], is_inf: bool, positive_y: bool) {
//     // add compression flag
//     result[0] |= 1 << 7;

//     if is_inf {
//         result[0] |= 1 << 6;
//         return;
//     }

//     if positive_y {
//         result[0] |= 1 << 5;
//         return;
//     }
// }

pub fn serialize_g1(p: &G1Affine) -> [u8; 48] {
    let mut result = serialize_g1_x(p);
    let encoding = EncodingFlags {
        is_compressed: true,
        is_infinity: p.infinity,
        is_lexographically_largest: p.y > -p.y,
    };
    encoding.encode_flags(&mut result[..]);
    result
}

pub fn serialize_g2(p: &G2Affine) -> [u8; 96] {
    let mut result = serialize_g2_x(p);
    let encoding = EncodingFlags {
        is_compressed: true,
        is_infinity: p.infinity,
        is_lexographically_largest: p.y > -p.y,
    };

    encoding.encode_flags(&mut result[..]);
    result
}
#[cfg(test)]
mod test {
    use super::*;
    use ark_ec::AffineCurve;
    #[test]
    fn test_correct_g1() {
        let p = G1Affine::prime_subgroup_generator();
        let enc = serialize_g1(&p);
        assert_eq!(hex::encode(enc), "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
        assert_eq!(hex::encode(serialize_g1(&G1Affine::default())), "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    }
    #[test]
    fn test_correct_g2() {
        let p = G2Affine::prime_subgroup_generator();
        assert_eq!(hex::encode(serialize_g2(&p)), "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");
        assert_eq!(hex::encode(serialize_g2(&G2Affine::default())), "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    }
    #[test]
    fn test_serialize_deserialize() {
        let p = G1Affine::prime_subgroup_generator();
        let got = deserialize_g1(serialize_g1(&p));

        assert_eq!(got, p);
        let p2 = G2Affine::prime_subgroup_generator();
        let got = deserialize_g2(serialize_g2(&p2));
        assert_eq!(got, p2);
    }
}
