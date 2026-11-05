use anyhow::{bail, ensure, Context, Result};
use frostsnap_coordinator::{AppMessageBody, DesktopSerial, DeviceChange, UsbSerialManager};
use frostsnap_core::{
    coordinator::{CoordinatorSend, CoordinatorToUserMessage, CoordinatorToUserSigningMessage},
    SymmetricKey,
};
use frostsnap_sp_bridge::{store::Store, Command, CORE_REVISION, MAX_FRAME, PROTOCOL};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    sync::mpsc,
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    id: String,
    command: Value,
}
fn emit(value: Value) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
fn route(sends: Vec<CoordinatorSend>, usb: &UsbSerialManager) -> Result<()> {
    for send in sends {
        match send {
            m @ CoordinatorSend::ToDevice { .. } => usb.usb_sender().send_from_core([m]),
            CoordinatorSend::ToUser(CoordinatorToUserMessage::Signing(event)) => {
                let event = match event {
                    CoordinatorToUserSigningMessage::GotSpEcdhShares { from, .. } => {
                        json!({"event":"ecdh_ready","device_id":from.to_string()})
                    }
                    CoordinatorToUserSigningMessage::GotShare { from, .. } => {
                        json!({"event":"signature_ready","device_id":from.to_string()})
                    }
                    _ => continue,
                };
                emit(event)?;
            }
            _ => {}
        }
    }
    Ok(())
}
fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut state = None;
    let mut source = None;
    let mut expected = None;
    let mut desktop = false;
    let mut offline = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--state" => {
                state = Some(PathBuf::from(
                    args.next().context("missing state directory")?,
                ))
            }
            "--import-app-db" => {
                source = Some(PathBuf::from(
                    args.next().context("missing source database")?,
                ))
            }
            "--expected-firmware" => {
                expected = Some(args.next().context("missing firmware digest")?)
            }
            "--desktop-dev-key" => desktop = true,
            "--offline" => offline = true,
            "--help" => {
                println!("frostsnap_sp_bridge --state DIR --desktop-dev-key [--import-app-db FILE] [--expected-firmware HEX | --offline]\nSignet only. Close Frostsnap first. JSON lines on stdin/stdout; no network listener.\nThe desktop dev key matches upstream's temporary DesktopSecureKeyProvider, not a production keystore.");
                return Ok(());
            }
            _ => bail!("unknown argument {arg}"),
        }
    }
    ensure!(
        desktop,
        "explicit --desktop-dev-key required for this development bridge"
    );
    if !offline {
        ensure!(
            expected
                .as_ref()
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())),
            "--expected-firmware must identify the reviewed SP firmware"
        );
    }
    let mut store = Store::open(&state.context("--state required")?)?;
    if let Some(source) = source {
        let n = store.import_app(&source)?;
        eprintln!("Imported {n} signet wallet(s); nonce state was not copied.");
    }
    let mut usb = UsbSerialManager::new(Box::new(DesktopSerial));
    usb.usb_sender().set_enabled(!offline);
    let mut ready = BTreeSet::new();
    let (tx, rx) = mpsc::sync_channel(16);
    std::thread::spawn(move || {
        let mut input = io::stdin().lock();
        loop {
            let mut bytes = Vec::new();
            let read = (&mut input)
                .take((MAX_FRAME + 1) as u64)
                .read_until(b'\n', &mut bytes);
            match read {
                Ok(0) => break,
                Ok(_) if bytes.len() > MAX_FRAME => {
                    let _ = tx.send(Err("request exceeds frame limit".to_string()));
                    break;
                }
                Ok(_) => {
                    if tx
                        .send(String::from_utf8(bytes).map_err(|e| e.to_string()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e.to_string()));
                    break;
                }
            }
        }
    });
    emit(
        json!({"event":"ready","protocol":PROTOCOL,"core_revision":CORE_REVISION,"network":"signet"}),
    )?;
    loop {
        if !offline {
            for change in usb.poll_ports() {
                match change {
                    DeviceChange::NameChange { id, name } => usb.accept_device_name(id, name),
                    DeviceChange::Registered { id, name } => {
                        let digest = usb.firmware_digest_for_device(id).map(|h| h.to_string());
                        let compatible = digest == expected;
                        emit(
                            json!({"event":"device","device_id":id.to_string(),"name":name,"firmware":digest,"compatible":compatible}),
                        )?;
                        if compatible {
                            ready.insert(id);
                            let sends = store.core.maybe_request_nonce_replenishment(
                                &BTreeSet::from([id]),
                                4,
                                &mut rand::thread_rng(),
                            );
                            usb.usb_sender().send_from_core(sends);
                        }
                    }
                    DeviceChange::Disconnected { id } => {
                        ready.remove(&id);
                        emit(json!({"event":"disconnected","device_id":id.to_string()}))?;
                    }
                    DeviceChange::AppMessage(message) if ready.contains(&message.from) => {
                        if let AppMessageBody::Core(body) = message.body {
                            match store.transaction(|core, _| {
                                core.recv_device_message(message.from, *body)
                                    .map_err(|e| anyhow::anyhow!("{e:?}"))
                            })? {
                                Ok(sends) => route(sends, &usb)?,
                                Err(e) => {
                                    emit(json!({"event":"device_error","error":e.to_string()}))?
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(line) => {
                let request = line
                    .map_err(anyhow::Error::msg)
                    .and_then(|s| Ok(serde_json::from_str::<Request>(&s)?));
                let request = match request {
                    Ok(r) => r,
                    Err(e) => {
                        emit(json!({"id":null,"error":e.to_string()}))?;
                        continue;
                    }
                };
                let id = request.id;
                let result = (|| -> Result<_> {
                    ensure!(request.protocol == PROTOCOL, "unsupported protocol");
                    let command: Command = serde_json::from_value(request.command)?;
                    match &command {
                        Command::Ecdh { device_id, .. } => ensure!(
                            ready.contains(&device_id.parse()?),
                            "device is not connected with expected SP firmware"
                        ),
                        Command::Sign { session_id, .. } => {
                            let s = store
                                .engine
                                .sessions
                                .iter()
                                .find(|s| &s.id == session_id)
                                .context("unknown session")?;
                            ensure!(
                                ready.contains(&s.device_id.parse()?),
                                "device is not connected with expected SP firmware"
                            );
                        }
                        _ => {}
                    }
                    Ok(command)
                })();
                let result = match result {
                    Ok(command) => {
                        if let Command::Cancel { session_id } = &command {
                            if let Some(s) =
                                store.engine.sessions.iter().find(|s| &s.id == session_id)
                            {
                                usb.usb_sender().send_cancel(s.device_id.parse()?);
                            }
                        }
                        store.transaction(|core, engine| {
                            engine.handle(core, command, SymmetricKey([0; 32]))
                        })?
                    }
                    Err(e) => Err(e),
                };
                match result {
                    Ok((result, sends)) => {
                        route(sends, &usb)?;
                        emit(json!({"id":id,"result":result}))?;
                    }
                    Err(e) => emit(json!({"id":id,"error":e.to_string()}))?,
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    usb.usb_sender().send_cancel_all();
    Ok(())
}
