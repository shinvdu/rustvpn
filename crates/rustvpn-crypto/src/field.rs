//! GF(2^255-19) arithmetic for the `extra25519` representative encoding.
//!
//! The limb arithmetic is `fiat-crypto`'s formally verified Curve25519
//! backend.  We only compose it (inversion, square roots, canonical
//! encoding).  This module exists because `curve25519-dalek` keeps its
//! field element type private and does not expose square roots.

use fiat_crypto::curve25519_64::{
    fiat_25519_add, fiat_25519_carry, fiat_25519_carry_mul, fiat_25519_carry_square,
    fiat_25519_from_bytes, fiat_25519_loose_field_element, fiat_25519_opp, fiat_25519_relax,
    fiat_25519_selectznz, fiat_25519_tight_field_element, fiat_25519_to_bytes,
};
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

#[derive(Clone, Copy)]
pub(crate) struct FieldElement(fiat_25519_tight_field_element);

impl FieldElement {
    pub(crate) const ZERO: Self = Self(fiat_25519_tight_field_element([0, 0, 0, 0, 0]));
    pub(crate) const ONE: Self = Self(fiat_25519_tight_field_element([1, 0, 0, 0, 0]));

    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut masked = *bytes;
        masked[31] &= 0x7f;
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_from_bytes(&mut out, &masked);
        Self(out)
    }

    pub(crate) fn as_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        fiat_25519_to_bytes(&mut out, &self.0);
        out
    }

    fn relax(&self) -> fiat_25519_loose_field_element {
        let mut out = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_relax(&mut out, &self.0);
        out
    }

    fn from_loose(loose: &fiat_25519_loose_field_element) -> Self {
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry(&mut out, loose);
        Self(out)
    }

    pub(crate) fn add(&self, rhs: &Self) -> Self {
        let mut out = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_add(&mut out, &self.0, &rhs.0);
        Self::from_loose(&out)
    }

    pub(crate) fn neg(&self) -> Self {
        let mut out = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_opp(&mut out, &self.0);
        Self::from_loose(&out)
    }

    pub(crate) fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.neg())
    }

    pub(crate) fn mul(&self, rhs: &Self) -> Self {
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry_mul(&mut out, &self.relax(), &rhs.relax());
        Self(out)
    }

    pub(crate) fn square(&self) -> Self {
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry_square(&mut out, &self.relax());
        Self(out)
    }

    fn pow2k(&self, k: u32) -> Self {
        let mut acc = *self;
        for _ in 0..k {
            acc = acc.square();
        }
        acc
    }

    fn pow22501(&self) -> (Self, Self) {
        // self^(2^250 - 1), self^3
        let t0 = self.square();
        let t1 = t0.square().square();
        let t2 = self.mul(&t1);
        let t3 = t0.mul(&t2);
        let t4 = t3.square();
        let t5 = t2.mul(&t4);
        let t6 = t5.pow2k(5);
        let t7 = t6.mul(&t5);
        let t8 = t7.pow2k(10);
        let t9 = t8.mul(&t7);
        let t10 = t9.pow2k(20);
        let t11 = t10.mul(&t9);
        let t12 = t11.pow2k(10);
        let t13 = t12.mul(&t7);
        let t14 = t13.pow2k(50);
        let t15 = t14.mul(&t13);
        let t16 = t15.pow2k(100);
        let t17 = t16.mul(&t15);
        let t18 = t17.pow2k(50);
        let t19 = t18.mul(&t13);
        (t19, t3)
    }

    pub(crate) fn pow_p58(&self) -> Self {
        let (t19, _) = self.pow22501();
        t19.pow2k(2).mul(self)
    }

    pub(crate) fn nonzero(&self) -> Choice {
        !self.ct_eq(&Self::ZERO)
    }

    pub(crate) fn invert(&self) -> Self {
        let (t19, t3) = self.pow22501();
        t19.pow2k(5).mul(&t3)
    }

    pub(crate) fn is_negative(&self) -> Choice {
        Choice::from(self.as_bytes()[0] & 1)
    }

    pub(crate) fn sqrt_m1() -> Self {
        let two = Self::ONE.add(&Self::ONE);
        let (t19, _) = two.pow22501();
        t19.pow2k(3).mul(&two.square().mul(&two))
    }

    /// `sqrt(u/v)`, returning `(u/v is a nonzero square, canonical root)`.
    pub(crate) fn sqrt_ratio_i(u: &Self, v: &Self) -> (Choice, Self) {
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut r = u.mul(&v3).mul(&u.mul(&v7).pow_p58());
        let check = v.mul(&r.square());
        let i = Self::sqrt_m1();
        let neg_u = u.neg();
        let correct_sign_sqrt = check.ct_eq(u);
        let flipped_sign_sqrt = check.ct_eq(&neg_u);
        let flipped_sign_sqrt_i = check.ct_eq(&neg_u.mul(&i));
        let r_prime = i.mul(&r);
        r.conditional_assign(&r_prime, flipped_sign_sqrt | flipped_sign_sqrt_i);
        r.conditional_negate(r.is_negative());
        (correct_sign_sqrt | flipped_sign_sqrt, r)
    }

    pub(crate) fn is_square(&self) -> Choice {
        Self::sqrt_ratio_i(self, &Self::ONE).0
    }

    /// Little-endian canonical comparison `self < other`, constant time.
    pub(crate) fn lt_bytes(&self, other: &[u8; 32]) -> Choice {
        let a = self.as_bytes();
        let mut borrow = 0u16;
        for i in 0..32 {
            let (_, underflow) = (a[i] as u16).overflowing_sub(other[i] as u16 + borrow);
            borrow = underflow as u16;
        }
        Choice::from(borrow as u8)
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(&other.as_bytes())
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = [0u64; 5];
        fiat_25519_selectznz(&mut out, choice.unwrap_u8(), &a.0 .0, &b.0 .0);
        Self(fiat_25519_tight_field_element(out))
    }
}

impl ConditionallyNegatable for FieldElement {
    fn conditional_negate(&mut self, choice: Choice) {
        let neg = self.neg();
        self.conditional_assign(&neg, choice);
    }
}
