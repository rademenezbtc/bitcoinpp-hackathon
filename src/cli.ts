#!/usr/bin/env bun
// marmot-vault CLI — one process per Mac.
//
//   bun run vault init  --name B --bridge <path/to/frostsnap_sp_bridge> [--role coordinator]
//   bun run vault member --name B <npub|hex> <shareIndex>      (repeat for every signer)
//   bun run vault coordinator --name B <npub|hex>              (signers only)
//   bun run vault run   --name B
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { getPublicKey, nip19 } from "nostr-tools";
import { PrivateKeySigner } from "applesauce-signers";
import { FrostsnapBridge } from "./frostsnap-bridge.ts";
import { VaultNode } from "./node.ts";
import { VaultApp, type AppConfig } from "./vault-app.ts";
import { relayNetwork } from "./net-pool.ts";
import { FileBytesStore } from "./file-store.ts";

const DEFAULT_RELAYS = ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"];
const DEFAULT_FIRMWARE = "512ec13bf0c839d6d5c97f425d8db7f3caa2eb1f479cafac93dcdb01a484e2ef";

interface FileConfig extends AppConfig {
  bridge: { binary: string; state: string; expectedFirmware: string; extraArgs?: string[] };
}

// ------------------------------------------------------------------ args
const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (k: string, d?: string) => {
  const i = argv.indexOf(`--${k}`);
  return i >= 0 ? argv[i + 1] : d;
};
const positional = argv.slice(1).filter((a, i, all) => !a.startsWith("--") && !(all[i - 1]?.startsWith("--")));
const name = flag("name") ?? die("--name is required (e.g. --name A)");
const home = resolve(flag("home", join(homedir(), ".marmot-vault"))!, name);
const cfgPath = join(home, "config.json");
const expand = (p: string) => resolve(p.replace(/^~(?=\/|$)/, homedir()));

function die(msg: string): never {
  console.error(msg);
  process.exit(1);
}
const toHex = (k: string) => (k.startsWith("npub") ? (nip19.decode(k).data as string) : /^[0-9a-f]{64}$/.test(k) ? k : die(`not a pubkey: ${k}`));
const loadCfg = (): FileConfig => (existsSync(cfgPath) ? JSON.parse(readFileSync(cfgPath, "utf8")) : die(`no config at ${cfgPath} — run init first`));
const saveCfg = (c: FileConfig) => writeFileSync(cfgPath, JSON.stringify(c, null, 2), { mode: 0o600 });

function identity() {
  const keyPath = join(home, "nostr.key");
  if (!existsSync(keyPath)) {
    mkdirSync(home, { recursive: true, mode: 0o700 });
    writeFileSync(keyPath, bytesToHex(crypto.getRandomValues(new Uint8Array(32))), { mode: 0o600 });
    writeFileSync(join(home, "client-id"), bytesToHex(crypto.getRandomValues(new Uint8Array(32))), { mode: 0o600 });
  }
  chmodSync(home, 0o700);
  const sk = hexToBytes(readFileSync(keyPath, "utf8").trim());
  const pubkey = getPublicKey(sk);
  return { sk, pubkey, npub: nip19.npubEncode(pubkey), clientId: readFileSync(join(home, "client-id"), "utf8").trim() };
}

function bridgeArgs(c: FileConfig["bridge"], offline: boolean) {
  const state = expand(c.state);
  mkdirSync(state, { recursive: true, mode: 0o700 });
  chmodSync(state, 0o700);
  return ["--state", state, "--desktop-dev-key", ...(offline ? ["--offline"] : ["--expected-firmware", c.expectedFirmware]), ...(c.extraArgs ?? [])];
}

/** Flatten the bridge `wallets` result:
 *  [{key_id, name, access_structures:[{id, threshold, participants:[{device_id, share_index, account_verifying_share}]}]}] */
function summarizeWallets(w: any) {
  const out: { keyId: string; name?: string; accessStructureId: string; threshold: number; devices: { deviceId: string; shareIndex: number }[] }[] = [];
  for (const k of Array.isArray(w) ? w : [])
    for (const a of k.access_structures ?? [])
      out.push({
        keyId: k.key_id, name: k.name, accessStructureId: a.id, threshold: Number(a.threshold),
        devices: (a.participants ?? []).map((p: any) => ({ deviceId: p.device_id, shareIndex: Number(p.share_index) })),
      });
  return out;
}

// ------------------------------------------------------------------ commands
async function init() {
  const id = identity();
  const binary = expand(flag("bridge") ?? die("--bridge <path to frostsnap_sp_bridge> is required"));
  const role = (flag("role", "signer") as "signer" | "coordinator");
  const cfg: FileConfig = existsSync(cfgPath) ? loadCfg() : {
    name, role, network: "signet", relays: DEFAULT_RELAYS, shareIndex: 0, threshold: 2,
    pin: { keyId: "", accessStructureId: "" }, coordinator: role === "coordinator" ? id.pubkey : "", members: {},
    gateBeforeSign: true, sessionTimeoutMin: 20,
    bridge: { binary, state: flag("state", "~/frostsnap-sp-bridge-state")!, expectedFirmware: flag("firmware", DEFAULT_FIRMWARE)! },
  };
  cfg.bridge.binary = binary;
  if (flag("device")) cfg.deviceId = flag("device");

  console.log("asking the bridge (offline) for wallets…");
  const b = new FrostsnapBridge(binary, bridgeArgs(cfg.bridge, true));
  b.on("diagnostic", (d) => { if (!/exited: 0/.test(String(d))) console.log(`  bridge: ${String(d).trim()}`); });
  b.on("notification", (n: any) => { if (n.event === "ready" && n.core_revision) cfg.pin.coreRevision = n.core_revision; });
  try {
    const w = await b.request({ method: "wallets" }, 20_000);
    writeFileSync(join(home, "wallets.json"), JSON.stringify(w, null, 2));
    const ws = summarizeWallets(w);
    const pick = flag("wallet") ? ws.filter((x) => x.keyId === flag("wallet")) : ws;
    if (pick.length === 1) {
      const [x] = pick;
      cfg.pin.keyId = x.keyId;
      cfg.pin.accessStructureId = x.accessStructureId;
      if (x.threshold) cfg.threshold = Number(x.threshold);
      const mine = x.devices.find((d) => d.deviceId === cfg.deviceId);
      if (mine) cfg.shareIndex = mine.shareIndex;
      console.log(`wallet "${x.name ?? ""}" ${x.keyId}\n  access structure ${x.accessStructureId}, ${cfg.threshold}-of-${x.devices.length || "?"}, core ${cfg.pin.coreRevision?.slice(0, 10) ?? "?"}`);
      for (const d of x.devices) console.log(`  device ${d.deviceId}  share ${d.shareIndex}${d.deviceId === cfg.deviceId ? "  ← this Mac" : ""}`);
    } else {
      console.log(`found ${ws.length} signet wallet(s)${ws.length ? " — rerun init with --wallet <key_id>" : " — did the --import-app-db step succeed?"}`);
      for (const x of ws) console.log(`  ${x.keyId}  "${x.name ?? ""}"  ${x.threshold}-of-${x.devices.length}`);
    }
  } catch (e: any) {
    console.log(`could not read wallets: ${e.message}`);
  } finally {
    b.close();
  }
  if (cfg.shareIndex) cfg.members[id.pubkey] = cfg.shareIndex;
  saveCfg(cfg);
  console.log(`\nconfig: ${cfgPath}`);
  console.log(`\nTHIS MAC'S MARMOT IDENTITY (send to your teammates):\n  ${id.npub}\n  ${id.pubkey}`);
  if (!cfg.shareIndex) console.log(`\n⚠ share index unknown — rerun init with --device <this Mac's device id>, or set "shareIndex" in the config`);
}

function member() {
  const [key, idx] = positional;
  if (!key || !idx) die("usage: member --name X <npub|hex> <shareIndex>");
  const c = loadCfg();
  c.members[toHex(key)] = Number(idx);
  saveCfg(c);
  console.log(`members: ${JSON.stringify(c.members, null, 2)}`);
}

function coordinator() {
  const [key] = positional;
  if (!key) die("usage: coordinator --name X <npub|hex>");
  const c = loadCfg();
  c.coordinator = toHex(key);
  saveCfg(c);
  console.log(`coordinator = ${c.coordinator}`);
}

async function run() {
  const id = identity();
  const cfg = loadCfg();
  const problems = [
    !cfg.pin.keyId && "pin.keyId", !cfg.pin.accessStructureId && "pin.accessStructureId",
    !cfg.shareIndex && "shareIndex", !cfg.coordinator && "coordinator",
    cfg.members[id.pubkey] !== cfg.shareIndex && "members (this Mac's own entry)",
    Object.keys(cfg.members).length < cfg.threshold && `members (need ${cfg.threshold})`,
  ].filter(Boolean);
  if (problems.length) die(`config incomplete: ${problems.join(", ")}\n  ${cfgPath}`);

  const log = (s: string) => console.log(`${new Date().toISOString().slice(11, 19)} ${s}`);
  const network = relayNetwork(cfg.relays, new PrivateKeySigner(id.sk), log); // NIP-42 auth with the same identity
  const node = new VaultNode(cfg.name, network, cfg.relays, {
    secretKey: id.sk, clientId: id.clientId,
    groupStateStore: new FileBytesStore(join(home, "groups")),
    acceptInvitesFrom: [cfg.coordinator], log,
  });

  const bridge = new FrostsnapBridge(expand(cfg.bridge.binary), bridgeArgs(cfg.bridge, false));
  const app = new VaultApp(cfg, node, bridge, log);
  await node.start();
  log(`marmot identity ${id.npub} (${cfg.role}, share ${cfg.shareIndex}) on ${cfg.relays.join(", ")}`);
  node.on("joined", (g) => log(`✓ joined vault group ${g.slice(0, 12)}…`));

  try {
    log(`wallets: ${JSON.stringify(summarizeWallets(await bridge.request({ method: "wallets" }, 20_000)))}`);
  } catch (e: any) {
    log(`✗ bridge wallets failed: ${e.message}`);
  }

  if (cfg.role === "coordinator" && !node.groupId) {
    await node.createGroup(`Marmot Vault ${cfg.pin.keyId.slice(0, 8)}`);
    log(`created vault group ${node.groupId!.slice(0, 12)}…`);
    await inviteAll(node, cfg, id.pubkey, log);
  } else if (!node.groupId) {
    log(`waiting for an invite from coordinator ${nip19.npubEncode(cfg.coordinator)}`);
  }

  const help = cfg.role === "coordinator"
    ? "commands: status | invite [npub] | propose <file.json> | sign | retry | cancel | quit"
    : "commands: status | retry | cancel | quit";
  log(help);
  const rl = createInterface({ input: process.stdin });
  rl.on("line", async (line) => {
    const [c, ...rest] = line.trim().split(/\s+/);
    try {
      if (!c) return;
      if (c === "status") console.log(JSON.stringify(app.status(), null, 2));
      else if (c === "invite" && cfg.role === "coordinator") rest[0] ? await node.invite(toHex(rest[0])) : await inviteAll(node, cfg, id.pubkey, log);
      else if (c === "propose" && cfg.role === "coordinator") await app.propose(await loadProposal(rest[0] ?? die("propose <file.json>")));
      else if (c === "sign" && cfg.role === "coordinator") await app.requestSignatures();
      else if (c === "retry") { if (app.signer?.sharesSent === false && app.signer.signing) await app.fetchShares(); else if (app.signer && !app.signer.myOffer) await app.requestEcdh(); }
      else if (c === "cancel") await app.cancel();
      else if (c === "quit") { bridge.close(); process.exit(0); }
      else log(help);
    } catch (e: any) {
      log(`✗ ${e?.message ?? e}`);
    }
  });
  rl.on("close", () => { bridge.close(); process.exit(0); });
}

async function inviteAll(node: VaultNode, cfg: FileConfig, self: string, log: (s: string) => void) {
  for (const pk of Object.keys(cfg.members).filter((p) => p !== self)) {
    try {
      await node.invite(pk);
      log(`✓ invited share ${cfg.members[pk]} (${nip19.npubEncode(pk).slice(0, 16)}…)`);
    } catch (e: any) {
      log(`✗ invite share ${cfg.members[pk]}: ${e.message} — type \`invite\` to retry`);
    }
  }
}

/** proposal.json: { inputs:[{txid, vout, internal, index} | {transaction, vout, …}], recipients:[{address, amount_sat}], change?:{index, amount_sat} } */
async function loadProposal(file: string) {
  const p = JSON.parse(readFileSync(expand(file), "utf8"));
  for (const i of p.inputs) {
    if (!i.transaction) {
      if (!i.txid) die("each input needs txid or transaction");
      const r = await fetch(`https://mempool.space/signet/api/tx/${i.txid}/hex`);
      if (!r.ok) die(`could not fetch ${i.txid} from mempool.space/signet (${r.status})`);
      i.transaction = (await r.text()).trim();
    }
    i.internal ??= false;
  }
  return p;
}

const commands: Record<string, () => unknown> = { init, member, coordinator, run };
(commands[cmd] ?? (() => die("commands: init | member | coordinator | run")))();
