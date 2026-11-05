//! Transport-independent adapter for PR #640. No Marmot or private signing shares here.
use anyhow::{anyhow, bail, ensure, Context, Result};
use bitcoin::{consensus, Amount, Network, Witness};
use frostsnap_core::{
    bitcoin_transaction::{LocalSpk, PushInput, TransactionTemplate},
    coordinator::{
        remote_signing::{self, RemoteSignSessionId, SpSubset},
        CoordinatorSend, FrostCoordinator, KeyContext, ParticipantBinonces,
        ParticipantSignatureShares,
    },
    device::KeyPurpose,
    message::signing::SpEcdhSessionId,
    silent_payments::{complete_sp_task, EcdhShare, SilentPaymentRecipient},
    tweak::BitcoinBip32Path,
    AccessStructureRef, DeviceId, KeyId, SymmetricKey, WireSignTask,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub mod store;
pub const PROTOCOL: &str = "frostsnap-sp-bridge/1";
pub const CORE_REVISION: &str = "538b0ec0832de92de98b1f58c556a0ea559ab9f4";
pub const MAX_FRAME: usize = 2 * 1024 * 1024;

pub fn encode<T: bincode::Encode>(value: &T) -> Result<String> {
    Ok(frostsnap_core::hex::encode(&bincode::encode_to_vec(
        value,
        bincode::config::standard(),
    )?))
}
pub fn decode<T: bincode::Decode<()>>(hex: &str) -> Result<T> {
    ensure!(hex.len() <= MAX_FRAME, "payload too large");
    let bytes = frostsnap_core::hex::decode(hex)?;
    let (value, used) = bincode::decode_from_slice(
        &bytes,
        bincode::config::standard().with_limit::<MAX_FRAME>(),
    )?;
    ensure!(used == bytes.len(), "trailing bytes in payload");
    Ok(value)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    /// Bincode hex of ParticipantBinonces, pinned to CORE_REVISION.
    pub binonces: String,
    /// Bincode hex of Vec<EcdhShare>; contains complete proofs, not commitments.
    pub ecdh: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundingInput {
    pub transaction: String,
    pub vout: u32,
    pub internal: bool,
    pub index: u32,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub address: String,
    pub amount_sat: u64,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub index: u32,
    pub amount_sat: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Wallets,
    Prepare {
        key_id: String,
        inputs: Vec<FundingInput>,
        recipients: Vec<Recipient>,
        change: Option<Change>,
    },
    Ecdh {
        session_id: String,
        key_id: String,
        access_structure_id: String,
        device_id: String,
        task: String,
    },
    Offer {
        session_id: String,
    },
    Sign {
        session_id: String,
        offers: Vec<Offer>,
    },
    Shares {
        session_id: String,
    },
    Combine {
        session_id: String,
        offers: Vec<Offer>,
        shares: Vec<String>,
    },
    Cancel {
        session_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub key_id: String,
    pub access_structure_id: String,
    pub device_id: String,
    pub task: String,
    pub ecdh_id: String,
    pub cancelled: bool,
}
impl Session {
    fn id(&self) -> Result<RemoteSignSessionId> {
        Ok(RemoteSignSessionId(session_bytes(&self.id)?))
    }
    fn device(&self) -> Result<DeviceId> {
        Ok(self.device_id.parse()?)
    }
    fn access(&self) -> Result<AccessStructureRef> {
        Ok(AccessStructureRef {
            key_id: self.key_id.parse()?,
            access_structure_id: self.access_structure_id.parse()?,
        })
    }
}
fn session_bytes(id: &str) -> Result<[u8; 32]> {
    ensure!(
        id.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "session_id must use lowercase hex"
    );
    frostsnap_core::hex::decode(id)?
        .try_into()
        .map_err(|_| anyhow!("session_id must be 32 bytes of hex"))
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Engine {
    pub sessions: Vec<Session>,
}
impl Engine {
    fn session(&self, id: &str) -> Result<&Session> {
        let s = self
            .sessions
            .iter()
            .find(|s| s.id == id)
            .context("unknown session")?;
        ensure!(!s.cancelled, "session was cancelled; use a new session_id");
        Ok(s)
    }

    pub fn handle(
        &mut self,
        core: &mut FrostCoordinator,
        command: Command,
        encryption_key: SymmetricKey,
    ) -> Result<(Value, Vec<CoordinatorSend>)> {
        let mut sends = vec![];
        let result = match command {
            Command::Wallets => json!(core.iter_keys().filter(|k| k.purpose == KeyPurpose::Bitcoin(Network::Signet))
                .map(|k| json!({"key_id":k.key_id.to_string(),"name":k.key_name,
                    "access_structures": k.complete_key.access_structures.values().map(|a| json!({
                        "id":a.access_structure_id().to_string(),"threshold":a.threshold(),
                        "participants":a.device_to_share_indicies().iter().map(|(d,i)|json!({
                            "device_id":d.to_string(),"share_index":u32::try_from(*i).unwrap(),
                            "account_verifying_share":frostsnap_core::tweak::BitcoinAccount::default()
                                .derive_account_key(&a.app_shared_key()).key().share_image(*i).image.to_string()
                        })).collect::<Vec<_>>()
                    })).collect::<Vec<_>>()
                })).collect::<Vec<_>>()),
            Command::Prepare { key_id, inputs, recipients, change } => {
                let key = signet_key(core, &key_id)?;
                ensure!(!inputs.is_empty() && inputs.len() <= 100, "need 1..100 inputs");
                ensure!(!recipients.is_empty() && recipients.len() <= 100, "need 1..100 recipients");
                let mut template = TransactionTemplate::new();
                let mut seen = BTreeSet::new();
                let mut input_sum = 0u64;
                let mut output_sum = 0u64;
                for input in inputs {
                    ensure!(input.index < (1 << 31), "hardened address index unsupported");
                    let tx: bitcoin::Transaction = consensus::deserialize(&frostsnap_core::hex::decode(&input.transaction)?)?;
                    let prev = tx.output.get(input.vout as usize).context("vout out of range")?;
                    ensure!(seen.insert((tx.compute_txid(),input.vout)), "duplicate input");
                    input_sum = input_sum.checked_add(prev.value.to_sat()).context("input amount overflow")?;
                    let path = if input.internal { BitcoinBip32Path::internal(input.index) } else { BitcoinBip32Path::external(input.index) };
                    template.push_owned_input(PushInput::spend_tx_output(&tx,input.vout), LocalSpk {
                        master_appkey:key.complete_key.master_appkey,bip32_path:path
                    }).map_err(|e|anyhow!("input does not belong to declared path: {e:?}"))?;
                }
                for r in recipients {
                    ensure!(r.amount_sat >= 330, "SP output below dust threshold");
                    output_sum = output_sum.checked_add(r.amount_sat).context("output amount overflow")?;
                    let recipient = SilentPaymentRecipient::from_address(&r.address,Network::Signet).context("invalid signet SP address")?;
                    template.push_silent_payment_output(Amount::from_sat(r.amount_sat),recipient,r.address);
                }
                if let Some(change) = change {
                    ensure!(change.index < (1 << 31) && change.amount_sat >= 330, "invalid change");
                    output_sum = output_sum.checked_add(change.amount_sat).context("output amount overflow")?;
                    template.push_owned_output(Amount::from_sat(change.amount_sat),LocalSpk {
                        master_appkey:key.complete_key.master_appkey,bip32_path:BitcoinBip32Path::internal(change.index)
                    });
                }
                ensure!(input_sum >= output_sum, "outputs exceed inputs");
                json!({"task":encode(&WireSignTask::BitcoinTransaction(template))?,"fee_sat":input_sum-output_sum})
            }
            Command::Ecdh { session_id, key_id, access_structure_id, device_id, task } => {
                session_bytes(&session_id)?;
                signet_key(core,&key_id)?;
                if let Some(existing) = self.sessions.iter().find(|s|s.id == session_id) {
                    ensure!(!existing.cancelled && existing.key_id == key_id && existing.access_structure_id == access_structure_id
                        && existing.device_id == device_id && existing.task == task, "conflicting session retry");
                    return Ok((json!({"status":"already_requested"}),sends));
                }
                for s in &self.sessions {
                    ensure!(s.cancelled || !core.get_completed_signature_shares(s.id()?).is_empty(), "another session is active");
                }
                let mut session = Session { id:session_id,key_id,access_structure_id,device_id,task,ecdh_id:String::new(),cancelled:false };
                let access = session.access()?;
                // Fail gracefully on an incorrect local unlock key; the upstream call expects success.
                ensure!(core.root_shared_key(access,encryption_key).is_some(), "wrong local wallet unlock key");
                let (id,out) = core.start_remote_sp_ecdh(access,decode(&session.task)?,session.device()?,encryption_key,&mut rand::thread_rng())?;
                session.ecdh_id = encode(&id)?;
                self.sessions.push(session);
                sends.extend(out);
                json!({"status":"confirm_ecdh_on_device"})
            }
            Command::Offer { session_id } => {
                let s = self.session(&session_id)?;
                let offer = core.offer_to_sign_sp(s.id()?,s.access()?,decode(&s.task)?,s.device()?,decode::<SpEcdhSessionId>(&s.ecdh_id)?)?;
                json!(Offer { binonces:encode(&offer.participant_binonces)?,ecdh:encode(&offer.sp_ecdh)? })
            }
            Command::Sign { session_id, offers } => {
                let s = self.session(&session_id)?;
                let (binonces,sp) = completed(core,s,&offers)?;
                let req = core.sign_with_nonce_reservation(s.id()?,s.device()?,&binonces,Some(&sp),encryption_key)?;
                sends.extend(req);
                json!({"status":"confirm_transaction_on_device","completed_task":encode(&sp.completed_task)?})
            }
            Command::Shares { session_id } => {
                let s = self.session(&session_id)?;
                let shares = core.get_completed_signature_shares(s.id()?);
                let share = shares.get(&s.device()?).context("signature not ready")?;
                json!({"shares":encode(share)?})
            }
            Command::Combine { session_id, offers, shares } => {
                let s = self.session(&session_id)?;
                let (binonces,sp) = completed(core,s,&offers)?;
                let shares: Vec<ParticipantSignatureShares> = shares.iter().map(|s|decode(s)).collect::<Result<_>>()?;
                let ids: BTreeSet<_> = shares.iter().map(|s|s.share_index).collect();
                ensure!(ids.len() == shares.len() && ids == binonces.iter().map(|b|b.share_index).collect(), "signature share set differs from selected signers");
                let key = context(core,s)?;
                let sigs = remote_signing::combine_signatures(sp.completed_task.clone(),&key,&binonces,&shares.iter().collect::<Vec<_>>())?;
                let WireSignTask::BitcoinTransaction(template) = sp.completed_task else { bail!("not a transaction") };
                let mut tx = template.to_rust_bitcoin_tx();
                ensure!(sigs.len() == tx.input.len(), "signature count mismatch");
                for (input,sig) in tx.input.iter_mut().zip(sigs) {
                    input.witness = Witness::from_slice(&[sig.0]);
                }
                json!({"txid":tx.compute_txid().to_string(),"transaction":consensus::encode::serialize_hex(&tx)})
            }
            Command::Cancel { session_id } => {
                let s = self.session(&session_id)?.clone();
                core.cancel_sp_ecdh(decode(&s.ecdh_id)?);
                core.cancel_remote_sign_session(s.id()?);
                self.sessions.iter_mut().find(|x|x.id==session_id).unwrap().cancelled=true;
                json!({"status":"cancelled"})
            }
        };
        Ok((result, sends))
    }
}
fn signet_key<'a>(
    core: &'a FrostCoordinator,
    id: &str,
) -> Result<&'a frostsnap_core::coordinator::CoordFrostKey> {
    let key = core
        .get_frost_key(id.parse::<KeyId>()?)
        .context("unknown wallet")?;
    ensure!(
        key.purpose == KeyPurpose::Bitcoin(Network::Signet),
        "bridge is signet-only"
    );
    Ok(key)
}
fn context(core: &FrostCoordinator, s: &Session) -> Result<KeyContext> {
    let key = signet_key(core, &s.key_id)?;
    let a = key
        .complete_key
        .access_structures
        .get(&s.access()?.access_structure_id)
        .context("unknown access structure")?;
    Ok(KeyContext {
        app_shared_key: a.app_shared_key(),
        purpose: key.purpose,
    })
}
fn completed(
    core: &FrostCoordinator,
    s: &Session,
    offers: &[Offer],
) -> Result<(Vec<ParticipantBinonces>, SpSubset)> {
    ensure!(
        !offers.is_empty() && offers.len() <= 100,
        "invalid offer count"
    );
    let binonces: Vec<ParticipantBinonces> = offers
        .iter()
        .map(|o| decode(&o.binonces))
        .collect::<Result<_>>()?;
    ensure!(
        binonces
            .iter()
            .map(|b| b.share_index)
            .collect::<BTreeSet<_>>()
            .len()
            == binonces.len(),
        "duplicate signer"
    );
    let shares = offers
        .iter()
        .map(|o| decode::<Vec<EcdhShare>>(&o.ecdh))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let completed_task =
        complete_sp_task(&decode(&s.task)?, &context(core, s)?, &binonces, &shares)
            .map_err(|e| anyhow!(e))?;
    Ok((
        binonces,
        SpSubset {
            completed_task,
            shares,
        },
    ))
}
