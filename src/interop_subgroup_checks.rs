// This is taken from arkworks.rs
// They have a dependency problem, so we cannot
// yet use the newer code with this check.
//
// This should NOT be audited.
pub mod g1 {
    use std::ops::Neg;

    use ark_bls12_381::g1::Parameters;
    use ark_bls12_381::Parameters as CurveParams;

    use ark_bls12_381::Fq;
    use ark_ec::short_weierstrass_jacobian::GroupAffine;
    use ark_ec::ProjectiveCurve;
    use ark_ec::{bls12::Bls12Parameters, AffineCurve};
    use ark_ff::{field_new, BigInteger256};

    /// BETA is a non-trivial cubic root of unity in Fq.
    const BETA: Fq = field_new!(Fq, "793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350");

    fn endomorphism(p: &GroupAffine<Parameters>) -> GroupAffine<Parameters> {
        // Endomorphism of the points on the curve.
        // endomorphism_p(x,y) = (BETA * x, y) where BETA is a non-trivial cubic root of unity in Fq.
        let mut res = (*p).clone();
        res.x *= BETA;
        res
    }

    pub fn is_in_correct_subgroup_assuming_on_curve(p: &GroupAffine<Parameters>) -> bool {
        // Algorithm from Section 6 of https://eprint.iacr.org/2021/1130.
        //
        // Check that endomorphism_p(P) == -[X^2]P

        let x = BigInteger256::new([CurveParams::X[0], 0, 0, 0]);

        // An early-out optimization described in Section 6.
        // If uP == P but P != point of infinity, then the point is not in the right subgroup.
        let x_times_p = p.mul(x);
        if x_times_p.eq(p) && !p.infinity {
            return false;
        }

        let minus_x_squared_times_p = x_times_p.mul(x).neg();
        let endomorphism_p = endomorphism(p);
        minus_x_squared_times_p.eq(&endomorphism_p)
    }
}

pub mod g2 {
    // psi(x,y) = (x**p * PSI_X, y**p * PSI_Y) is the Frobenius composed
    // with the quadratic twist and its inverse

    use ark_bls12_381::Parameters as CurveParams;
    use ark_bls12_381::{g2::Parameters, Fq, Fq2, FQ_ZERO};
    use ark_ec::bls12::Bls12Parameters;
    use ark_ec::{short_weierstrass_jacobian::GroupAffine, AffineCurve};
    use ark_ff::{field_new, BigInteger256, Field};

    pub fn is_in_correct_subgroup_assuming_on_curve(point: &GroupAffine<Parameters>) -> bool {
        // Algorithm from Section 4 of https://eprint.iacr.org/2021/1130.
        //
        // Checks that [p]P = [X]P

        let mut x_times_point = point.mul(BigInteger256([CurveParams::X[0], 0, 0, 0]));
        if CurveParams::X_IS_NEGATIVE {
            x_times_point = -x_times_point;
        }

        let p_times_point = p_power_endomorphism(point);

        x_times_point.eq(&p_times_point)
    }

    // PSI_X = 1/(u+1)^((p-1)/3)
    const P_POWER_ENDOMORPHISM_COEFF_0 : Fq2 = field_new!(
    Fq2,
    FQ_ZERO,
    field_new!(
       Fq,
       "4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437"
    )
);

    // PSI_Y = 1/(u+1)^((p-1)/2)
    const P_POWER_ENDOMORPHISM_COEFF_1: Fq2 = field_new!(
    Fq2,
    field_new!(
       Fq,
       "2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530"),
    field_new!(
       Fq,
       "1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257")
);

    fn p_power_endomorphism(p: &GroupAffine<Parameters>) -> GroupAffine<Parameters> {
        // The p-power endomorphism for G2 is defined as follows:
        // 1. Note that G2 is defined on curve E': y^2 = x^3 + 4(u+1). To map a point (x, y) in E' to (s, t) in E,
        //    one set s = x / ((u+1) ^ (1/3)), t = y / ((u+1) ^ (1/2)), because E: y^2 = x^3 + 4.
        // 2. Apply the Frobenius endomorphism (s, t) => (s', t'), another point on curve E,
        //    where s' = s^p, t' = t^p.
        // 3. Map the point from E back to E'; that is,
        //    one set x' = s' * ((u+1) ^ (1/3)), y' = t' * ((u+1) ^ (1/2)).
        //
        // To sum up, it maps
        // (x,y) -> (x^p / ((u+1)^((p-1)/3)), y^p / ((u+1)^((p-1)/2)))
        // as implemented in the code as follows.

        let mut res = *p;
        res.x.frobenius_map(1);
        res.y.frobenius_map(1);

        let tmp_x = res.x.clone();

        res.x.c0 = -P_POWER_ENDOMORPHISM_COEFF_0.c1 * &tmp_x.c1;
        res.x.c1 = P_POWER_ENDOMORPHISM_COEFF_0.c1 * &tmp_x.c0;
        res.y *= P_POWER_ENDOMORPHISM_COEFF_1;

        res
    }
}
