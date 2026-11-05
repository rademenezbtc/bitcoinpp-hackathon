//! Generates an ECDH-only request with an imaginary input and public test recipient.
//! Never use this fixture as a funded payment proposal.
use anyhow::{Context, Result};
use bitcoin::Network;
use frostsnap_core::{
    device::KeyPurpose,
    silent_payments::SilentPaymentRecipient,
    test::silent_payments::{public, scalar, template},
    tweak::BitcoinBip32Path,
    WireSignTask,
};
use frostsnap_sp_bridge::{encode, store::Store, PROTOCOL};
use serde_json::json;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let state = args.next().context("state directory required")?;
    let device = args.next().context("device ID required")?;
    let store = Store::open(std::path::Path::new(&state))?;
    let access = store
        .core
        .iter_access_structures()
        .find(|a| {
            store.core.iter_keys().any(|k| {
                k.key_id == a.access_structure_ref().key_id
                    && k.purpose == KeyPurpose::Bitcoin(Network::Signet)
            })
        })
        .context("no Signet wallet")?;
    let ar = access.access_structure_ref();
    let recipient = SilentPaymentRecipient {
        scan_key: public(scalar(3)),
        spend_key: public(scalar(4)),
    };
    let task = WireSignTask::BitcoinTransaction(template(
        access.master_appkey(),
        &[(BitcoinBip32Path::external(0), 100_000)],
        &[(
            20_000,
            recipient,
            recipient.address(Network::Signet).unwrap(),
        )],
        79_000,
    ));
    let id = frostsnap_core::hex::encode(&rand::random::<[u8; 32]>());
    println!(
        "{}",
        json!({"protocol":PROTOCOL,"id":"hardware-ecdh-test","command":{
            "method":"ecdh","session_id":id,"key_id":ar.key_id.to_string(),
            "access_structure_id":ar.access_structure_id.to_string(),"device_id":device,"task":encode(&task)?
        }})
    );
    Ok(())
}
