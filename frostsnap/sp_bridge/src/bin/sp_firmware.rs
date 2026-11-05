//! Development-device updater. Uses the upstream confirmation and USB upgrade protocol.
use anyhow::{bail, ensure, Context, Result};
use frostsnap_coordinator::{
    firmware_upgrade::FirmwareUpgradeProtocol, AppMessageBody, Completion, DesktopSerial,
    DeviceChange, FirmwareBin, FirmwareVersion, UiProtocol, UsbSerialManager, ValidatedFirmwareBin,
};
use frostsnap_core::DeviceId;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey};
use std::{
    collections::{BTreeSet, HashMap},
    time::{Duration, Instant},
};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let image = args
        .next()
        .context("usage: sp_firmware IMAGE EXPECTED_BODY_SHA256 DEVICE_ID [DEVICE_ID...]")?;
    let expected = args
        .next()
        .context("expected firmware body digest required")?;
    let selected: BTreeSet<DeviceId> = args
        .map(|s| s.parse().map_err(anyhow::Error::from))
        .collect::<Result<_>>()?;
    ensure!(!selected.is_empty(), "explicit device IDs required");
    let bytes = std::fs::read(image)?;
    let signer = frostsnap_factory::secure_boot::verify_firmware(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid firmware signature: {e:?}"))?;
    // This is the public development identity bundled upstream, never a production key.
    let pem = include_str!("../../../../frostsnap_factory/bootloader/dev/secure-boot-key.pem");
    let dev = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))?;
    ensure!(
        signer == rsa::RsaPublicKey::from(&dev),
        "firmware is not signed by the expected development key"
    );
    let firmware = ValidatedFirmwareBin::new(FirmwareBin::new(Box::leak(bytes.into_boxed_slice())))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    ensure!(
        firmware.digest().to_string() == expected,
        "firmware digest does not match reviewed image"
    );
    ensure!(
        firmware.version().is_none(),
        "this tool is for development firmware only"
    );
    eprintln!("Target firmware: {expected}. Close all Frostsnap apps before proceeding.");
    let mut usb = UsbSerialManager::new(Box::new(DesktopSerial)).with_firmware_bin(firmware);
    let mut found = HashMap::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while found.len() < selected.len() {
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for selected devices"
        );
        for change in usb.poll_ports() {
            match change {
                DeviceChange::NameChange { id, name } => usb.accept_device_name(id, name),
                DeviceChange::Connected {
                    id,
                    firmware_digest,
                    ..
                } => {
                    ensure!(
                        selected.contains(&id),
                        "unselected device {id} is connected; unplug it"
                    );
                    found.insert(id, FirmwareVersion::new(firmware_digest));
                }
                DeviceChange::Disconnected { id } => {
                    found.remove(&id);
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let need = found
        .iter()
        .filter(|(_, fw)| fw.digest != firmware.digest())
        .map(|(id, _)| *id)
        .collect();
    let mut protocol = FirmwareUpgradeProtocol::new(found, need, firmware, ());
    eprintln!("Confirm the matching firmware digest on each selected device.");
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if Instant::now() >= deadline {
            usb.usb_sender().send_cancel_all();
            bail!("confirmation timed out");
        }
        for change in usb.poll_ports() {
            match change {
                DeviceChange::Disconnected { id } => protocol.disconnected(id),
                DeviceChange::Connected { id, .. } if !selected.contains(&id) => {
                    usb.usb_sender().send_cancel_all();
                    bail!("unselected device joined during update");
                }
                DeviceChange::AppMessage(msg) => {
                    if let AppMessageBody::Misc(m) = msg.body {
                        protocol.process_comms_message(msg.from, m);
                    }
                }
                _ => {}
            }
        }
        for msg in protocol.poll() {
            usb.usb_sender().send(msg);
        }
        match protocol.is_complete() {
            Some(Completion::Success) => break,
            Some(Completion::Abort { .. }) => {
                usb.usb_sender().send_cancel_all();
                bail!("device update aborted before flashing");
            }
            None => {}
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    for progress in usb.run_firmware_upgrade()? {
        eprintln!("Upload {:.0}%", 100.0 * progress?);
    }
    // Upload completion is not proof of successful boot. Reconnect and check every digest.
    usb.disconnect_all();
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut confirmed = BTreeSet::new();
    while confirmed != selected {
        ensure!(
            Instant::now() < deadline,
            "upload finished, but firmware boot could not be verified"
        );
        for change in usb.poll_ports() {
            match change {
                DeviceChange::NameChange { id, name } => usb.accept_device_name(id, name),
                DeviceChange::Connected {
                    id,
                    firmware_digest,
                    ..
                } if selected.contains(&id) => {
                    ensure!(
                        firmware_digest == firmware.digest(),
                        "device {id} booted a different firmware"
                    );
                    confirmed.insert(id);
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("Verified SP firmware on {} device(s).", confirmed.len());
    Ok(())
}
