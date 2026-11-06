use bitcoin::{consensus, Network};
use frostsnap_core::{
    coordinator::{keys::KeyMutation, CoordinatorSend, Mutation},
    device::KeyPurpose,
    silent_payments::SilentPaymentRecipient,
    test::{
        silent_payments::{public, scalar, template, RemoteSigningEnv},
        Run, TEST_ENCRYPTION_KEY,
    },
    tweak::BitcoinBip32Path,
    WireSignTask,
};
use frostsnap_sp_bridge::{decode, encode, store::Store, Command, Engine, Offer};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use serde_json::{json, Value};

fn invoke(
    engine: &mut Engine,
    run: &mut Run,
    i: usize,
    value: Value,
) -> anyhow::Result<(Value, Vec<CoordinatorSend>)> {
    engine.handle(
        &mut run.participants[i].coordinator,
        serde_json::from_value::<Command>(value)?,
        TEST_ENCRYPTION_KEY,
    )
}

#[test]
fn two_of_two_signet_sp_roundtrip_rejects_tampering_and_duplicate_signers() {
    ceremony(true, false);
}

#[test]
fn two_of_two_single_receiver() {
    ceremony(false, false);
}

#[test]
fn two_inputs_two_distinct_receivers() {
    ceremony(true, true);
}

fn ceremony(batch: bool, multiple_inputs: bool) {
    let mut rng = ChaCha20Rng::from_seed([27; 32]);
    let mut env = RemoteSigningEnv::default();
    let mut run = Run::start_after_remote_keygen(
        &[1, 1],
        2,
        "bridge test",
        KeyPurpose::Bitcoin(Network::Signet),
        &mut env,
        &mut rng,
    );
    run.replenish_all_nonces(2, &mut env, &mut rng);
    let access = run.participants[0]
        .coordinator
        .iter_access_structures()
        .next()
        .unwrap();
    let ar = access.access_structure_ref();
    let recipient = SilentPaymentRecipient {
        scan_key: public(scalar(3)),
        spend_key: public(scalar(4)),
    };
    // Two outputs with the same scan key exercise the batch counter contract as well.
    let mut recipients = vec![(
        20_000,
        recipient,
        recipient.address(Network::Signet).unwrap(),
    )];
    if batch {
        let recipient = if multiple_inputs {
            SilentPaymentRecipient { scan_key: public(scalar(5)), spend_key: public(scalar(6)) }
        } else { recipient };
        recipients.push((
            30_000,
            recipient,
            recipient.address(Network::Signet).unwrap(),
        ));
    }
    let inputs = if multiple_inputs {
        vec![(BitcoinBip32Path::external(0), 60_000), (BitcoinBip32Path::external(1), 40_000)]
    } else { vec![(BitcoinBip32Path::external(0), 100_000)] };
    let task = WireSignTask::BitcoinTransaction(template(
        access.master_appkey(),
        &inputs,
        &recipients,
        if batch { 49_000 } else { 79_000 },
    ));
    let task = encode(&task).unwrap();
    let id = "01".repeat(32);
    let mut engines = [Engine::default(), Engine::default()];
    for (i, engine) in engines.iter_mut().enumerate() {
        let device = *run.participants[i].devices.keys().next().unwrap();
        let req = json!({"method":"ecdh","session_id":id,"key_id":ar.key_id.to_string(),"access_structure_id":ar.access_structure_id.to_string(),"device_id":device.to_string(),"task":task});
        let (_, sends) = invoke(engine, &mut run, i, req.clone()).unwrap();
        run.extend_from_coordinator(i, sends);
        let (_, retry) = invoke(engine, &mut run, i, req.clone()).unwrap();
        assert!(retry.is_empty());
        let mut conflicting = req;
        conflicting["task"] = json!("00");
        assert!(invoke(engine, &mut run, i, conflicting).is_err());
    }
    run.run_until_finished(&mut env, &mut rng).unwrap();
    let mut offers = vec![];
    for (i, engine) in engines.iter_mut().enumerate() {
        let (offer, _) = invoke(
            engine,
            &mut run,
            i,
            json!({"method":"offer","session_id":id}),
        )
        .unwrap();
        offers.push(serde_json::from_value::<Offer>(offer).unwrap());
    }
    let mut bad = offers.clone();
    let mut shares =
        decode::<Vec<frostsnap_core::silent_payments::EcdhShare>>(&bad[1].ecdh).unwrap();
    shares[0].proof[0] ^= 1;
    bad[1].ecdh = encode(&shares).unwrap();
    assert!(invoke(
        &mut engines[0],
        &mut run,
        0,
        json!({"method":"sign","session_id":id,"offers":bad})
    )
    .is_err());
    assert!(invoke(
        &mut engines[0],
        &mut run,
        0,
        json!({"method":"sign","session_id":id,"offers":[offers[0],offers[0]]})
    )
    .is_err());
    for (i, engine) in engines.iter_mut().enumerate() {
        let (_, sends) = invoke(
            engine,
            &mut run,
            i,
            json!({"method":"sign","session_id":id,"offers":offers}),
        )
        .unwrap();
        run.extend_from_coordinator(i, sends);
    }
    run.run_until_finished(&mut env, &mut rng).unwrap();
    let shares: Vec<_> = (0..2)
        .map(|i| {
            invoke(
                &mut engines[i],
                &mut run,
                i,
                json!({"method":"shares","session_id":id}),
            )
            .unwrap()
            .0["shares"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert!(invoke(
        &mut engines[0],
        &mut run,
        0,
        json!({"method":"combine","session_id":id,"offers":offers,"shares":[shares[0],shares[0]]})
    )
    .is_err());
    let (result, _) = invoke(
        &mut engines[0],
        &mut run,
        0,
        json!({"method":"combine","session_id":id,"offers":offers,"shares":shares}),
    )
    .unwrap();
    let tx: bitcoin::Transaction = consensus::deserialize(
        &frostsnap_core::hex::decode(result["transaction"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(tx.input.len(), inputs.len());
    for input in &tx.input {
        assert_eq!(input.witness.len(), 1);
        assert_eq!(input.witness[0].len(), 64);
    }
    assert_eq!(tx.output.len(), recipients.len() + 1);
    for (output, recipient) in tx.output.iter().zip(&recipients) {
        assert_eq!(output.value.to_sat(), recipient.0);
    }
    assert_eq!(tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>(), 99_000);
    if batch {
        assert_ne!(tx.output[0].script_pubkey, tx.output[1].script_pubkey);
    }
    assert_eq!(tx.compute_txid().to_string(), result["txid"]);
}

#[test]
fn import_does_not_copy_nonces_and_store_is_locked_and_replayable() {
    let mut rng = ChaCha20Rng::from_seed([22; 32]);
    let mut env = RemoteSigningEnv::default();
    let mut run = Run::start_after_remote_keygen(
        &[1, 1],
        2,
        "import test",
        KeyPurpose::Bitcoin(Network::Signet),
        &mut env,
        &mut rng,
    );
    run.replenish_all_nonces(2, &mut env, &mut rng);
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("app.sqlite");
    let db = rusqlite::Connection::open(&source).unwrap();
    db.execute_batch("CREATE TABLE fs_coordinator_mutations (id INTEGER PRIMARY KEY,mutation BLOB,version INTEGER);").unwrap();
    let key = run.participants[0].coordinator.iter_keys().next().unwrap();
    let mutation = Mutation::Keygen(KeyMutation::NewKey {
        key_name: key.key_name.clone(),
        purpose: key.purpose,
        complete_key: key.complete_key.clone(),
    });
    db.execute(
        "INSERT INTO fs_coordinator_mutations VALUES(1,?1,0)",
        [bincode::encode_to_vec(mutation, bincode::config::standard()).unwrap()],
    )
    .unwrap();
    // An incompatible signing record is deliberately not imported/deserialized.
    db.execute(
        "INSERT INTO fs_coordinator_mutations VALUES(2,?1,0)",
        [vec![1u8, 255]],
    )
    .unwrap();
    let directory = temp.path().join("state");
    let mut store = Store::open(&directory).unwrap();
    assert_eq!(store.import_app(&source).unwrap(), 1);
    assert!(Store::open(&directory).is_err());
    let device = *run.participants[0].devices.keys().next().unwrap();
    let requests = store
        .core
        .maybe_request_nonce_replenishment(&[device].into(), 2, &mut rng);
    assert!(!requests.replenish_requests[&device].is_empty());
    store
        .transaction(|_, engine| {
            engine.sessions.clear();
            Ok(())
        })
        .unwrap()
        .unwrap();
    drop(store);
    let mut store = Store::open(&directory).unwrap();
    assert_eq!(store.core.iter_keys().count(), 1);
    assert!(store.import_app(&source).is_err());
    assert_eq!(
        db.query_row("SELECT count(*) FROM fs_coordinator_mutations", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        2
    );
}

#[test]
fn codec_rejects_trailing_bytes_and_unknown_methods() {
    let mut encoded = encode(&vec![1u8, 2, 3]).unwrap();
    encoded.push_str("00");
    assert!(decode::<Vec<u8>>(&encoded).is_err());
    assert!(serde_json::from_value::<Command>(json!({"method":"flash"})).is_err());
}
