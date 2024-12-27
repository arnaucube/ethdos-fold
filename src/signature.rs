use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    Absorb, CryptographicSponge,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::prelude::CurveVar;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::Rng, Zero};
use core::borrow::Borrow;
use rand_core::CryptoRngCore;
use std::fmt::Debug;

use arkeddsa::{signature::Signature, PublicKey, SigningKey};

use crate::fcircuit::CF;

// recall, here C = ed_on_bn254, so C::BaseField = BN254::ScalarField
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SigPk<C: CurveGroup> {
    pub pk: PublicKey<C>,
    pub sig: Signature<C>,
}
impl<C: CurveGroup> Default for SigPk<C> {
    fn default() -> Self {
        Self {
            pk: PublicKey(C::zero().into_affine()),
            sig: Signature::new(C::zero().into_affine(), C::ScalarField::zero()),
        }
    }
}
impl<C: CurveGroup> SigPk<C> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_bytes = self.sig.to_bytes();
        let pk_bytes = self.pk.to_bytes();
        vec![sig_bytes, pk_bytes].concat()
    }
    pub fn from_bytes(b: Vec<u8>) -> Self {
        let u_point_size = C::Affine::generator().serialized_size(ark_serialize::Compress::No);

        let sig = Signature::<C>::from_bytes(&b[..32 + u_point_size]).unwrap();
        let pk = PublicKey::<C>::from_bytes(&b[32 + u_point_size..]).unwrap();
        Self { pk, sig }
    }
}

#[derive(Clone, Debug)]
pub struct SigPkVar<C: CurveGroup, GC: CurveVar<C, CF<C>>> {
    pub pk: GC,
    pub sig_r: GC,
    pub sig_s: Vec<Boolean<CF<C>>>,
}
impl<C: CurveGroup, GC: CurveVar<C, CF<C>>> Default for SigPkVar<C, GC> {
    fn default() -> Self {
        Self {
            pk: GC::zero(),
            sig_r: GC::zero(),
            sig_s: vec![Boolean::<CF<C>>::FALSE; 253], // TODO 253-> fieldbitsize
        }
    }
}

impl<C, GC> AllocVar<SigPk<C>, CF<C>> for SigPkVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, CF<C>>,
{
    fn new_variable<T: Borrow<SigPk<C>>>(
        cs: impl Into<Namespace<CF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();

            let e = val.borrow();
            let pk = GC::new_variable(cs.clone(), || Ok(e.pk.0), mode)?;
            let sig_r = GC::new_variable(cs.clone(), || Ok(e.sig.r), mode)?;
            let sig_s = Vec::<Boolean<CF<C>>>::new_variable(
                cs.clone(),
                || Ok(e.sig.s.into_bigint().to_bits_le()),
                mode,
            )?;
            let v = Self { pk, sig_r, sig_s };

            Ok(v)
        })
    }
}

pub fn hash_pk<C: CurveGroup>(
    poseidon_config: &PoseidonConfig<C::BaseField>,
    pk: PublicKey<C>,
) -> C::BaseField
where
    C::BaseField: PrimeField + Absorb,
{
    let mut poseidon = PoseidonSponge::new(poseidon_config);
    let (pk_x, pk_y): (C::BaseField, C::BaseField) = pk.xy().unwrap();
    poseidon.absorb(&vec![pk_x, pk_y]);
    let k = poseidon.squeeze_field_elements::<C::BaseField>(1);
    *k.first().unwrap()
}

// returns a vector of signatures & publickeys, where each signature is of the previous public key
pub fn gen_signatures<R: Rng + CryptoRngCore, C: CurveGroup>(
    rng: &mut R,
    poseidon_config: &PoseidonConfig<C::BaseField>,
    steps: usize,
) -> Vec<SigPk<C>>
where
    C::BaseField: PrimeField + Absorb,
{
    let mut prev_pk = None;
    let mut res: Vec<SigPk<C>> = Vec::new();
    for _ in 0..steps {
        let extinp = gen_sig(rng, poseidon_config, prev_pk);
        res.push(extinp);
        prev_pk = Some(extinp.pk);
    }
    res
}

// generates a new secret key, and signs the given `prev_pk` with it. If the `prev_pk==None`, it
// will use the newly generated public key as the prev_pk.
pub fn gen_sig<R: Rng + CryptoRngCore, C: CurveGroup>(
    rng: &mut R,
    poseidon_config: &PoseidonConfig<C::BaseField>,
    prev_pk: Option<PublicKey<C>>,
) -> SigPk<C>
where
    C::BaseField: PrimeField + Absorb,
{
    let sk = SigningKey::<C>::generate::<blake2::Blake2b512>(rng).unwrap();
    let pk = sk.public_key();

    // if prev_pk!=None, use it, else, set the new pk to it
    let prev_pk = if prev_pk.is_some() {
        prev_pk.unwrap()
    } else {
        *pk
    };

    let msg = hash_pk(poseidon_config, prev_pk);

    let sig = sk
        .sign::<blake2::Blake2b512>(&poseidon_config, &msg)
        .unwrap();
    pk.verify(&poseidon_config, &msg, &sig).unwrap();
    SigPk {
        pk: pk.clone(),
        sig,
    }
}
