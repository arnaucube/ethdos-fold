use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
    Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::prelude::CurveVar;
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;
use std::fmt::Debug;

use arkeddsa::constraints::verify;
use folding_schemes::{frontend::FCircuit, Error};

use crate::signature::{SigPk, SigPkVar};

pub type CF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// Test circuit to be folded
#[derive(Clone, Debug)]
pub struct EthDosCircuit<F: PrimeField, C: CurveGroup, GC: CurveVar<C, F>> {
    _c: PhantomData<C>,
    _gc: PhantomData<GC>,
    config: PoseidonConfig<F>,
}
impl<F: PrimeField, C: CurveGroup, GC: CurveVar<C, F>> FCircuit<F> for EthDosCircuit<F, C, GC>
where
    F: Absorb,
    C: CurveGroup<BaseField = F>,
{
    type Params = PoseidonConfig<F>;
    type ExternalInputs = SigPk<C>;
    type ExternalInputsVar = SigPkVar<C, GC>;

    fn new(config: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            _c: PhantomData,
            _gc: PhantomData,
            config,
        })
    }
    fn state_len(&self) -> usize {
        5
    }
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let pk_0_x = z_i[0].clone();
        let pk_0_y = z_i[1].clone();
        let pk_i_x = z_i[2].clone();
        let pk_i_y = z_i[3].clone();
        let mut degree = z_i[4].clone();

        // get the 'msg' that has been signed, which is the hash of the previous-signer public key
        let mut poseidon = PoseidonSpongeVar::new(cs.clone(), &self.config);
        poseidon.absorb(&vec![pk_i_x, pk_i_y])?;
        let h = poseidon.squeeze_field_elements(1)?;
        let msg = h
            .first()
            .ok_or(ark_relations::r1cs::SynthesisError::Unsatisfiable)?;

        // check that the last signer is signed by the new signer
        let ei: SigPkVar<C, GC> = external_inputs.into();
        let res = verify::<C, GC>(
            cs.clone(),
            self.config.clone(),
            ei.pk.clone(),
            (ei.sig_r, ei.sig_s),
            msg.clone(),
        )?;
        res.enforce_equal(&Boolean::<F>::TRUE)?;

        // increment the degree
        degree = degree.clone() + FpVar::<F>::one();

        let pk_i1_xy = ei.pk.to_constraint_field()?;
        Ok(vec![vec![pk_0_x, pk_0_y], pk_i1_xy, vec![degree]].concat())
    }
}
#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ec::AffineRepr;
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::Zero;
    use rand::rngs::OsRng;

    use crate::signature::{gen_signatures, hash_pk};
    use arkeddsa::ed_on_bn254_twist::{constraints::EdwardsVar, EdwardsProjective};
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    #[test]
    fn test_sig() {
        let mut rng = OsRng;
        let poseidon_config = poseidon_canonical_config::<Fr>();

        const N: usize = 1;
        let ext_inps = gen_signatures::<OsRng, EdwardsProjective>(&mut rng, &poseidon_config, 1);
        let e = ext_inps[0].clone();

        let msg = hash_pk(&poseidon_config, e.pk);

        e.pk.verify(&poseidon_config, &msg, &e.sig).unwrap();
    }

    fn ensure_fcircuit_trait<FC: FCircuit<Fr>>(params: FC::Params) {
        let _ = FC::new(params);
    }

    // test to check that the Sha256FCircuit computes the same values inside and outside the circuit
    #[test]
    fn test_fcircuit() {
        let mut rng = rand::rngs::OsRng;
        let poseidon_config = poseidon_canonical_config::<Fr>();

        let pks_sigs = gen_signatures::<OsRng, EdwardsProjective>(&mut rng, &poseidon_config, 1);

        // here `Fr` is the BN254::G1::Fr = ed_on_bn254_twist::EdwardsProjective::Fq
        let cs = ConstraintSystem::<Fr>::new_ref();

        type FC = EthDosCircuit<Fr, EdwardsProjective, EdwardsVar>;
        ensure_fcircuit_trait::<FC>(poseidon_config.clone());

        let circuit = FC::new(poseidon_config).unwrap();
        let xy: (Fr, Fr) = pks_sigs[0].pk.0.xy().unwrap();
        let pk0 = vec![xy.0, xy.1];
        let z_i: Vec<Fr> = vec![pk0.clone(), pk0, vec![Fr::zero()]].concat();

        let external_inputs_var =
            SigPkVar::<EdwardsProjective, EdwardsVar>::new_witness(cs.clone(), || Ok(pks_sigs[0]))
                .unwrap();

        let z_iVar = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z_i)).unwrap();
        let computed_z_i1Var = circuit
            .generate_step_constraints(cs.clone(), 0, z_iVar.clone(), external_inputs_var)
            .unwrap();
        // check that the degree (in the last state) is 1, the amount of signatures verified
        assert_eq!(computed_z_i1Var.value().unwrap()[4], Fr::from(1_u32));
        assert!(cs.is_satisfied().unwrap());
        dbg!(cs.num_constraints());
        dbg!(&computed_z_i1Var.value().unwrap());
    }
}
