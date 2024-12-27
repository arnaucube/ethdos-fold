//! This file contains the WASM bindings.
//!
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::AffineRepr;
use ark_grumpkin::Projective as G2;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::Zero;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use rand::rngs::OsRng;

use arkeddsa::ed_on_bn254_twist::{constraints::EdwardsVar, EdwardsProjective};

use folding_schemes::{
    commitment::pedersen::Pedersen,
    folding::nova::{Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    FoldingScheme,
};

use crate::fcircuit::EthDosCircuit;
use crate::signature::{gen_signatures, SigPk};
use crate::utils::{dbg, elapsed, get_time};

mod fcircuit;
mod fold_ethdos;
mod signature;
mod utils;

use wasm_bindgen::prelude::*;

// define type aliases for the FCircuit (FC) and the FoldingScheme (FS), to avoid writting the
// whole type each time.
type FC = EthDosCircuit<Fr, EdwardsProjective, EdwardsVar>;
type FS = Nova<G1, G2, FC, Pedersen<G1>, Pedersen<G2>, false>;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn gen_params() -> Vec<String> {
    let mut rng = OsRng;
    let poseidon_config = poseidon_canonical_config::<Fr>();

    let f_circuit = FC::new(poseidon_config.clone()).unwrap();

    let nova_preprocess_params = PreprocessorParam::new(poseidon_config.clone(), f_circuit.clone());
    let start = get_time();
    let nova_params = FS::preprocess(&mut rng, &nova_preprocess_params).unwrap();
    dbg(format!("Nova params generated: {:?}ms", elapsed(start)));

    // serialize
    let start = get_time();
    let mut prover_params_serialized = vec![];
    nova_params
        .0
        .serialize_compressed(&mut prover_params_serialized)
        .unwrap();
    dbg(format!(
        "Nova prover params serialized: {:?}ms",
        elapsed(start)
    ));

    let start = get_time();
    let mut verifier_params_serialized = vec![];
    nova_params
        .1
        .serialize_compressed(&mut verifier_params_serialized)
        .unwrap();
    dbg(format!(
        "Nova prover params serialized: {:?}ms",
        elapsed(start)
    ));

    vec![
        b64.encode(&prover_params_serialized),
        b64.encode(&prover_params_serialized),
    ]
}

#[wasm_bindgen]
pub fn gen_sigs(n_steps: usize) -> Vec<String> {
    let mut rng = OsRng;
    let poseidon_config = poseidon_canonical_config::<Fr>();

    let sigs: Vec<SigPk<EdwardsProjective>> = gen_signatures(&mut rng, &poseidon_config, n_steps);
    let b: Vec<Vec<u8>> = sigs.iter().map(|&s| s.to_bytes()).collect();
    b.iter().map(|s| b64.encode(s)).collect::<Vec<String>>()
}

#[wasm_bindgen]
pub fn fold_sigs(params: Vec<String>, sigs_pks: Vec<String>) -> String {
    dbg("starting fold_sigs (rust)".to_string());
    dbg(format!("received sigs: {:?}", sigs_pks));

    let poseidon_config = poseidon_canonical_config::<Fr>();

    // parse sigs_pks
    let b: Vec<Vec<u8>> = sigs_pks.iter().map(|s| b64.decode(s).unwrap()).collect();
    let pks_sigs: Vec<SigPk<EdwardsProjective>> =
        b.iter().map(|s| SigPk::from_bytes(s.clone())).collect();

    // parse params
    let start = get_time();
    let pp = FS::pp_deserialize_with_mode(
        &mut b64.decode(params[0].clone()).unwrap().as_slice(),
        ark_serialize::Compress::Yes,
        ark_serialize::Validate::Yes,
        poseidon_config.clone(), // fcircuit_params
    )
    .unwrap();
    let vp = FS::vp_deserialize_with_mode(
        &mut b64.decode(params[1].clone()).unwrap().as_slice(),
        ark_serialize::Compress::Yes,
        ark_serialize::Validate::Yes,
        poseidon_config.clone(), // fcircuit_params
    )
    .unwrap();
    let fs_params = (pp, vp);
    dbg(format!(
        "params (prover & verifier) deserialization: {:?}ms",
        elapsed(start)
    ));

    // set the initial state
    let xy = pks_sigs[0].pk.0.xy().unwrap();
    let pk0 = vec![xy.0, xy.1];
    let z_0: Vec<Fr> = [pk0.clone(), pk0, vec![Fr::zero()]].concat();

    type FC = EthDosCircuit<Fr, EdwardsProjective, EdwardsVar>;
    let f_circuit = FC::new(poseidon_config.clone()).unwrap();

    // initialize the folding scheme engine, in our case we use Nova
    let mut nova = FS::init(&fs_params, f_circuit, z_0.clone()).unwrap();
    let rng = OsRng;
    let n_steps = sigs_pks.len();

    let start_full = get_time();
    #[allow(clippy::needless_range_loop)]
    for i in 0..n_steps {
        let start = get_time();
        nova.prove_step(rng, pks_sigs[i], None).unwrap();
        dbg(format!(
            "Nova::prove_step {}: {:?}ms",
            nova.i,
            elapsed(start)
        ));
    }
    dbg(format!(
        "Nova's all {} steps time: {:?}ms",
        n_steps,
        elapsed(start_full)
    ));

    let ivc_proof = nova.ivc_proof();
    let mut ivc_proof_bytes = vec![];
    ivc_proof
        .serialize_compressed(&mut ivc_proof_bytes)
        .unwrap();

    b64.encode(ivc_proof_bytes)
}

#[wasm_bindgen]
pub fn verify_proof(verifier_params: String, ivc_proof: String) -> String {
    let poseidon_config = poseidon_canonical_config::<Fr>();

    let vp = FS::vp_deserialize_with_mode(
        &mut b64.decode(verifier_params.clone()).unwrap().as_slice(),
        ark_serialize::Compress::Yes,
        ark_serialize::Validate::Yes,
        poseidon_config.clone(), // fcircuit_params
    )
    .unwrap();
    // let proof =
    //     FS::IVCProof::deserialize_compressed(b64.decode(ivc_proof).unwrap().as_slice()).unwrap();
    let proof = <Nova<G1, G2, FC, Pedersen<G1>, Pedersen<G2>, false> as FoldingScheme<
        G1,
        G2,
        FC,
    >>::IVCProof::deserialize_compressed(b64.decode(ivc_proof).unwrap().as_slice())
    .unwrap();

    FS::verify(
        vp, // Nova's verifier params
        proof,
    )
    .unwrap();
    "verified".to_string()
}
