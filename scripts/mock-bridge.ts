#!/usr/bin/env bun
// Fake frostsnap_sp_bridge for rehearsals without hardware. Mirrors the real
// bridge's wire shapes (frostsnap/sp_bridge/src/main.rs + lib.rs @ 538b0ec):
//   events: ready, device{compatible}, ecdh_ready{device_id}, signature_ready{device_id}
//   ecdh → confirm_ecdh_on_device | already_requested; sign → {status, completed_task}
//   combine → {txid, transaction}. Payloads are fake hex. Devices auto-approve.
//   MOCK_DEVICE=devA MOCK_SHARE=1 bun scripts/mock-bridge.ts [--reject-sign] [--tamper-task]
import { createInterface } from "node:readline";
import { createHash } from "node:crypto";

const arg = (k: string, d = "") => { const i = process.argv.indexOf(`--${k}`); return i >= 0 ? process.argv[i + 1] : d; };
const device = arg("device", process.env.MOCK_DEVICE ?? "devA");
const share = Number(arg("share", process.env.MOCK_SHARE ?? "1"));
const rejectSign = process.argv.includes("--reject-sign");
const tamperTask = process.argv.includes("--tamper-task");
const offline = process.argv.includes("--offline");
const hex = (s: string) => Buffer.from(s).toString("hex");
const out = (o: unknown) => process.stdout.write(JSON.stringify(o) + "\n");

type S = { task: string; ecdhReady?: boolean; offer?: any; signReady?: boolean; cancelled?: boolean };
const sessions = new Map<string, S>();
out({ event: "ready", protocol: "frostsnap-sp-bridge/1", core_revision: "538b0ec0832de92de98b1f58c556a0ea559ab9f4", network: "signet" });
if (!offline) out({ event: "device", device_id: device, name: `Mock ${device}`, firmware: "512ec13bf0c839d6d5c97f425d8db7f3caa2eb1f479cafac93dcdb01a484e2ef", compatible: true });

createInterface({ input: process.stdin }).on("line", (line) => {
  const { id, protocol, command: c } = JSON.parse(line);
  const ok = (result: unknown) => out({ id, result });
  const err = (error: string) => out({ id, error });
  if (protocol !== "frostsnap-sp-bridge/1") return err("unsupported protocol");
  const live = (sid: string) => { const s = sessions.get(sid); if (!s) throw new Error("unknown session"); if (s.cancelled) throw new Error("session was cancelled; use a new session_id"); return s; };
  try {
    switch (c.method) {
      case "wallets":
        return ok([{ key_id: "key-mock", name: "Mock signet", access_structures: [{ id: "as-mock", threshold: 2,
          participants: [{ device_id: "devA", share_index: 1, account_verifying_share: "02aa" }, { device_id: "devB", share_index: 2, account_verifying_share: "02bb" }] }] }]);
      case "prepare":
        if (c.key_id !== "key-mock") throw new Error("unknown wallet");
        if (!c.recipients?.length) throw new Error("need 1..100 recipients");
        return ok({ task: hex(JSON.stringify({ i: c.inputs.length, r: c.recipients })), fee_sat: 153 });
      case "ecdh": {
        if (!/^[0-9a-f]{64}$/.test(c.session_id)) throw new Error("session_id must be 32 bytes of hex");
        if (c.device_id !== device) throw new Error("device is not connected with expected SP firmware");
        const s = sessions.get(c.session_id);
        if (s) {
          if (s.cancelled || s.task !== c.task) throw new Error("conflicting session retry");
          return ok({ status: "already_requested" });
        }
        for (const x of sessions.values()) if (!x.cancelled && !x.signReady) throw new Error("another session is active");
        sessions.set(c.session_id, { task: c.task });
        setTimeout(() => { sessions.get(c.session_id)!.ecdhReady = true; out({ event: "ecdh_ready", device_id: device }); }, 100);
        return ok({ status: "confirm_ecdh_on_device" });
      }
      case "offer": {
        const s = live(c.session_id);
        if (!s.ecdhReady) throw new Error("ECDH shares not received from device");
        s.offer ??= { binonces: hex(`binonces-${device}-${c.session_id.slice(0, 6)}`), ecdh: hex(`ecdh+dleq-${device}-${s.task.slice(0, 8)}`) };
        return ok(s.offer);
      }
      case "sign": {
        const s = live(c.session_id);
        if (!s.offer) throw new Error("no offer");
        if (!Array.isArray(c.offers) || new Set(c.offers.map((o: any) => o.binonces)).size !== c.offers.length) throw new Error("duplicate signer");
        if (!c.offers.some((o: any) => o.ecdh === s.offer.ecdh && o.binonces === s.offer.binonces)) throw new Error("own offer missing");
        if (rejectSign) throw new Error("user rejected on device");
        const completed = createHash("sha256").update(s.task + c.offers.map((o: any) => o.ecdh).sort().join() + (tamperTask ? "x" : "")).digest("hex");
        setTimeout(() => { s.signReady = true; out({ event: "signature_ready", device_id: device }); }, 100);
        return ok({ status: "confirm_transaction_on_device", completed_task: completed });
      }
      case "shares": {
        const s = live(c.session_id);
        if (!s.signReady) throw new Error("signature not ready");
        return ok({ shares: hex(`sigshare-${share}`) });
      }
      case "combine":
        live(c.session_id);
        if (c.shares?.length !== c.offers?.length) throw new Error("signature share set differs from selected signers");
        return ok({ txid: "cd".repeat(32), transaction: "02000000" + "00".repeat(40) });
      case "cancel":
        live(c.session_id).cancelled = true;
        return ok({ status: "cancelled" });
      default:
        throw new Error(`unknown variant \`${c.method}\``);
    }
  } catch (e: any) {
    err(e.message);
  }
});
