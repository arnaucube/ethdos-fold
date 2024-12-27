#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Projective as G1};
    use ark_ec::AffineRepr;
    use ark_grumpkin::Projective as G2;
    use ark_std::Zero;
    use rand::rngs::OsRng;

    use arkeddsa::ed_on_bn254_twist::{constraints::EdwardsVar, EdwardsProjective};

    use folding_schemes::{
        commitment::pedersen::Pedersen,
        folding::nova::{Nova, PreprocessorParam},
        frontend::FCircuit,
        transcript::poseidon::poseidon_canonical_config,
        FoldingScheme,
    };

    use crate::{
        fcircuit::EthDosCircuit,
        signature::gen_signatures,
        utils::{dbg, elapsed, get_time},
    };

    #[test]
    fn full_flow() {
        // set how many steps of folding we want to compute
        const N_STEPS: usize = 10;
        dbg(format!(
            "running Nova folding scheme on EthDosCircuit, with N_STEPS={}",
            N_STEPS
        ));

        let mut rng = OsRng;
        let poseidon_config = poseidon_canonical_config::<Fr>();

        let pks_sigs =
            gen_signatures::<OsRng, EdwardsProjective>(&mut rng, &poseidon_config, N_STEPS);

        // set the initial state
        let xy = pks_sigs[0].pk.0.xy().unwrap();
        let pk0 = vec![xy.0, xy.1];
        let z_0: Vec<Fr> = vec![pk0.clone(), pk0, vec![Fr::zero()]].concat();

        type FC = EthDosCircuit<Fr, EdwardsProjective, EdwardsVar>;
        let f_circuit = FC::new(poseidon_config.clone()).unwrap();

        // define type aliases for the FoldingScheme (FS) and Decider (D), to avoid writting the
        // whole type each time
        pub type FS = Nova<G1, G2, FC, Pedersen<G1>, Pedersen<G2>, false>;

        // prepare the Nova prover & verifier params
        let nova_preprocess_params =
            PreprocessorParam::new(poseidon_config.clone(), f_circuit.clone());
        let start = get_time();
        let nova_params = FS::preprocess(&mut rng, &nova_preprocess_params).unwrap();
        dbg(format!("Nova params generated: {:?}", elapsed(start)));

        // initialize the folding scheme engine, in our case we use Nova
        let mut nova = FS::init(&nova_params, f_circuit, z_0.clone()).unwrap();

        // run n steps of the folding iteration
        let start_full = get_time();
        for i in 0..N_STEPS {
            let start = get_time();
            nova.prove_step(rng, pks_sigs[i].clone(), None).unwrap();
            dbg(format!("Nova::prove_step {}: {:?}", nova.i, elapsed(start)));
        }
        dbg(format!(
            "Nova's all {} steps time: {:?}",
            N_STEPS,
            elapsed(start_full)
        ));

        // verify the last IVC proof
        let ivc_proof = nova.ivc_proof();
        dbg!(&ivc_proof.z_i);
        FS::verify(
            nova_params.1.clone(), // Nova's verifier params
            ivc_proof,
        )
        .unwrap();
    }
}
