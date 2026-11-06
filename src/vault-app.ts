// Session logic for one Mac: a signer (and optionally the coordinator) driving
// its LOCAL Frostsnap SP bridge, with Marmot carrying the opaque payloads.
//
// Rules from the bridge README that this enforces:
//  - authenticated senders are bound to configured share indices
//  - wallet / access structure / protocol (and core revision when known) are pinned
//  - proposal and subset are frozen; messages are de-duplicated
//  - one incomplete session per bridge; fresh 32-byte session id per attempt
//  - invites are only accepted from the configured coordinator (membership ≠ signing authority)
import { createHash } from "node:crypto";
import type { VaultNode, InboundRumor } from "./node.ts";
import {
  BRIDGE_PROTOCOL, FS_KIND, decodeFs, encodeFs, isSessionId, newSessionId,
  type BridgeOffer, type FsMsg, type Pin,
} from "./fs-schema.ts";

export interface BridgeLike {
  request<T = unknown>(command: Record<string, unknown>, timeoutMs?: number): Promise<T>;
  on(event: "notification" | "diagnostic", fn: (x: any) => void): unknown;
  close(): void;
}

export interface AppConfig {
  name: string;
  role: "coordinator" | "signer";
  network: "signet";
  relays: string[];
  /** This Mac's FROST share index and the device id its bridge talks to. */
  shareIndex: number;
  deviceId?: string;
  threshold: number;
  pin: Omit<Pin, "protocol">;
  /** Nostr pubkey (hex) of the coordinator. */
  coordinator: string;
  /** Nostr pubkey (hex) → share index, for every signer including this one. */
  members: Record<string, number>;
  /** Coordinator only: wait for an explicit `sign` command after offers are in (milestone 1). */
  gateBeforeSign?: boolean;
  /** Minutes before an unfinished session is cancelled. */
  sessionTimeoutMin?: number;
}

type Proposal = Extract<FsMsg, { t: "fs.proposal" }>;

interface SignerSession {
  id: string;
  proposal: Proposal;
  myOffer?: BridgeOffer;
  offersSeen: Map<number, BridgeOffer>; // from authenticated members
  signing?: boolean;
  subset?: number[];
  derived: Map<number, string>; // share index → completed_task hash
  sharesSent?: boolean;
  sharesSeen: Set<number>; // whose signature shares went out (any member)
  complete?: { txid: string; txHex: string };
  cancelled?: string;
  done?: boolean;
}

interface CoordSession {
  id: string;
  offers: Map<number, BridgeOffer>;
  subset?: number[];
  shares: Map<number, unknown>;
  completed?: boolean;
  complete?: { txid: string; txHex: string };
  timer?: ReturnType<typeof setTimeout>;
}

const short = (s: string) => `${s.slice(0, 8)}…`;

export class VaultApp {
  private seen = new Set<string>(); // session ids ever accepted (never reused)
  private dedupe = new Set<string>();
  signer?: SignerSession;
  coord?: CoordSession;
  private waiters: { event: string; sessionId: string; resolve: (n: any) => void }[] = [];
  private listeners = new Set<() => void>();
  /** Recent log lines, for the dashboard. */
  logLines: { at: number; text: string }[] = [];
  log: (s: string) => void;

  constructor(
    public cfg: AppConfig,
    public node: VaultNode,
    public bridge: BridgeLike,
    log: (s: string) => void = console.log,
  ) {
    this.log = (text: string) => {
      log(text);
      this.logLines.push({ at: Date.now(), text });
      if (this.logLines.length > 300) this.logLines.shift();
      this.changed();
    };
    bridge.on("notification", (n) => this.onNotification(n));
    bridge.on("diagnostic", (d) => this.log(`bridge: ${String(d).trim()}`));
    node.on("rumor", (r) => this.onRumor(r).catch((e) => this.log(`✗ ${e?.message ?? e}`)));
  }

  /** Subscribe to state changes (dashboard). Returns an unsubscribe function. */
  onChange(fn: () => void) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
  private changed() {
    for (const fn of this.listeners) try { fn(); } catch {}
  }

  get isCoordinator() {
    return this.cfg.role === "coordinator";
  }

  // ------------------------------------------------------------ bridge events
  /** Core revision announced by our own bridge (`ready` event). */
  bridgeRevision?: string;
  deviceReady = false;

  private onNotification(n: any) {
    switch (n.event) {
      case "ready":
        this.bridgeRevision = n.core_revision;
        this.log(`bridge ready: ${n.protocol} @ ${String(n.core_revision).slice(0, 10)} (${n.network})`);
        if (this.cfg.pin.coreRevision && n.core_revision !== this.cfg.pin.coreRevision)
          this.log(`✗ bridge core revision ${n.core_revision} ≠ pinned ${this.cfg.pin.coreRevision} — proposals will be refused`);
        break;
      case "device":
        if (!n.compatible) {
          this.log(`✗ device ${short(n.device_id)} has firmware ${n.firmware ?? "unknown"} — not the expected SP firmware; it won't be used`);
          break;
        }
        if (!this.cfg.deviceId) this.cfg.deviceId = n.device_id;
        if (n.device_id === this.cfg.deviceId) {
          this.deviceReady = true;
          this.log(`✓ device ${short(n.device_id)} (${n.name}) connected with the expected SP firmware`);
        } else this.log(`device ${short(n.device_id)} connected but this Mac is configured for ${short(this.cfg.deviceId)}`);
        break;
      case "disconnected":
        if (n.device_id === this.cfg.deviceId) { this.deviceReady = false; this.log("✗ device disconnected"); }
        break;
      case "device_error":
        this.log(`✗ device error: ${n.error}`);
        break;
      default:
        this.log(`bridge event: ${JSON.stringify(n)}`);
    }
    this.waiters = this.waiters.filter((w) => {
      if (w.event === n.event && (!n.device_id || n.device_id === this.cfg.deviceId)) { w.resolve(n); return false; }
      return true;
    });
  }

  private waitEvent(event: string, sessionId: string, timeoutMs: number) {
    return new Promise<any>((resolve, reject) => {
      const w = { event, sessionId, resolve };
      this.waiters.push(w);
      setTimeout(() => {
        if (this.waiters.includes(w)) {
          this.waiters = this.waiters.filter((x) => x !== w);
          reject(new Error(`no ${event} within ${timeoutMs / 1000}s — approve on the device, or type \`retry\``));
        }
      }, timeoutMs);
    });
  }

  // ------------------------------------------------------------ inbound
  private async onRumor(r: InboundRumor) {
    if (r.kind !== FS_KIND) return;
    if (this.dedupe.has(r.id)) return;
    this.dedupe.add(r.id);
    const m = decodeFs(r.content);
    if (!m) return;
    const fromCoord = r.from === this.cfg.coordinator;
    const memberIdx = this.cfg.members[r.from];

    switch (m.t) {
      case "fs.proposal":
        if (!fromCoord) return this.log(`✗ proposal from non-coordinator ${short(r.from)} ignored`);
        return this.reportFailure(m.sessionId, () => this.signerOnProposal(m));
      case "fs.offer":
        if (memberIdx === undefined || memberIdx !== m.shareIndex)
          return this.log(`✗ offer for share ${m.shareIndex} from ${short(r.from)} (bound to ${memberIdx ?? "nobody"}) ignored`);
        if (this.signer?.id === m.sessionId && !this.signer.offersSeen.has(m.shareIndex)) { this.signer.offersSeen.set(m.shareIndex, m.offer); this.changed(); }
        if (this.isCoordinator) await this.coordOnOffer(m);
        return;
      case "fs.sign_request":
        if (!fromCoord) return this.log(`✗ sign request from non-coordinator ignored`);
        return this.reportFailure(m.sessionId, () => this.signerOnSignRequest(m));
      case "fs.derived":
        if (memberIdx === undefined || memberIdx !== m.shareIndex) return;
        if (this.signer?.id === m.sessionId && !this.signer.derived.has(m.shareIndex)) { this.signer.derived.set(m.shareIndex, m.completedTaskHash); this.changed(); }
        if (this.isCoordinator && this.coord?.id === m.sessionId) this.log(`share ${m.shareIndex} derived completed task ${m.completedTaskHash.slice(0, 12)}…`);
        return;
      case "fs.shares":
        if (memberIdx === undefined || memberIdx !== m.shareIndex) return this.log(`✗ shares from unbound sender ignored`);
        if (this.signer?.id === m.sessionId) { this.signer.sharesSeen.add(m.shareIndex); this.changed(); }
        if (this.isCoordinator) await this.coordOnShares(m);
        return;
      case "fs.cancel":
        if (!fromCoord && memberIdx === undefined) return;
        return this.onCancel(m.sessionId, `${m.reason} (by ${fromCoord ? "coordinator" : `share ${memberIdx}`})`, false);
      case "fs.complete":
        if (!fromCoord) return;
        if (this.signer?.id === m.sessionId) { this.signer.done = true; this.signer.complete = { txid: m.txid, txHex: m.txHex }; }
        return this.log(`✓ session ${short(m.sessionId)} complete: txid ${m.txid}`);
      case "fs.status":
        return this.log(`share ${m.shareIndex}: ${m.note}`);
    }
  }

  /** Signer-side failures (device rejected, bridge error) are told to the group, not just logged. */
  private async reportFailure(sessionId: string, fn: () => Promise<unknown>) {
    try {
      await fn();
    } catch (e: any) {
      const note = `✗ ${e?.message ?? e}`;
      this.log(note);
      await this.send({ t: "fs.status", sessionId, shareIndex: this.cfg.shareIndex, note });
    }
  }

  private send(m: FsMsg) {
    return this.node.sendRumor(FS_KIND, encodeFs(m));
  }

  private pinOk(p: Pin) {
    const c = this.cfg.pin;
    if (p.protocol !== BRIDGE_PROTOCOL) return `protocol ${p.protocol}`;
    if (p.keyId !== c.keyId) return "key id";
    if (p.accessStructureId !== c.accessStructureId) return "access structure";
    if (c.coreRevision && p.coreRevision && p.coreRevision !== c.coreRevision) return "core revision";
    if (this.bridgeRevision && p.coreRevision && p.coreRevision !== this.bridgeRevision) return "core revision (local bridge)";
    return null;
  }

  // ------------------------------------------------------------ signer
  private async signerOnProposal(p: Proposal) {
    if (!isSessionId(p.sessionId)) return this.log("✗ proposal with malformed session id ignored");
    const bad = this.pinOk(p.pin);
    if (bad) return this.log(`✗ proposal for a different ${bad} — refusing`);
    if (this.seen.has(p.sessionId)) return; // replay
    if (this.signer && !this.signer.done)
      return this.send({ t: "fs.status", sessionId: p.sessionId, shareIndex: this.cfg.shareIndex, note: `busy with ${short(this.signer.id)}` });
    if (!this.cfg.deviceId || !this.deviceReady) throw new Error("device not connected with the expected SP firmware — plug it in, then ask the coordinator to propose again");

    this.seen.add(p.sessionId);
    this.signer = { id: p.sessionId, proposal: p, offersSeen: new Map(), derived: new Map(), sharesSeen: new Set() };
    this.log(`→ proposal ${short(p.sessionId)}: ${p.summary.recipients.map((r) => `${r.amount_sat} sat → ${r.address.slice(0, 14)}…${r.address.slice(-6)}`).join(", ")}${p.feeSat !== undefined ? `, fee ${p.feeSat} sat` : ""}`);
    this.log("  APPROVE THE ECDH REQUEST ON THE DEVICE (check recipient and amount on its screen)");
    await this.requestEcdh();
  }

  /** (Re)send the identical ecdh request — the bridge answers `already_requested` without re-prompting. */
  async requestEcdh() {
    const s = this.signer;
    if (!s) return;
    const ready = this.waitEvent("ecdh_ready", s.id, 10 * 60_000);
    const status: any = await this.bridge.request({
      method: "ecdh", session_id: s.id, key_id: this.cfg.pin.keyId,
      access_structure_id: this.cfg.pin.accessStructureId, device_id: this.cfg.deviceId, task: s.proposal.task,
    }, 120_000);
    this.log(`  ecdh: ${status?.status ?? JSON.stringify(status)}`);
    if (status?.status === "already_requested") {
      // Approval may already have happened (event missed): try the offer directly.
      try { return await this.fetchOffer(); } catch { /* not yet approved — keep waiting */ }
    }
    await ready;
    await this.fetchOffer();
  }

  async fetchOffer() {
    const s = this.signer;
    if (!s || s.myOffer) return;
    const offer = await this.bridge.request<BridgeOffer>({ method: "offer", session_id: s.id }, 60_000);
    if (!offer?.binonces || !offer?.ecdh) throw new Error(`unexpected offer result ${JSON.stringify(offer)}`);
    s.myOffer = offer;
    this.log(`✓ device approved ECDH — sending offer (share ${this.cfg.shareIndex})`);
    await this.send({ t: "fs.offer", sessionId: s.id, shareIndex: this.cfg.shareIndex, offer });
  }

  private async signerOnSignRequest(m: Extract<FsMsg, { t: "fs.sign_request" }>) {
    const s = this.signer;
    if (!s || s.id !== m.sessionId) return this.log(`✗ sign request for unknown session ${short(m.sessionId)}`);
    if (s.signing) return; // subset is frozen at the first request
    if (!m.subset.includes(this.cfg.shareIndex)) return this.log(`not in subset ${m.subset.join(",")}`);
    if (new Set(m.subset).size !== this.cfg.threshold || m.subset.length !== this.cfg.threshold)
      return this.abort(s.id, `subset ${m.subset} is not ${this.cfg.threshold} distinct shares`);
    const idx = m.offers.map((o) => o.shareIndex);
    if (idx.slice().sort().join() !== m.subset.slice().sort().join()) return this.abort(s.id, "offers don't match subset");
    // Relays may deliver the sign request before another signer's offer: wait briefly.
    for (let i = 0; i < 60 && m.offers.some((o) => o.shareIndex !== this.cfg.shareIndex && !s.offersSeen.has(o.shareIndex)); i++)
      await new Promise((r) => setTimeout(r, 500));
    if (s.signing) return;
    for (const o of m.offers) {
      const expected = o.shareIndex === this.cfg.shareIndex ? s.myOffer : s.offersSeen.get(o.shareIndex);
      if (!expected) return this.abort(s.id, `never saw an offer from share ${o.shareIndex}`);
      if (expected.binonces !== o.offer.binonces || expected.ecdh !== o.offer.ecdh)
        return this.abort(s.id, `offer for share ${o.shareIndex} differs from what that signer sent`);
    }
    s.signing = true;
    s.subset = m.subset;
    this.log(`→ sign request, subset [${m.subset}] — bridge verifies all DLEQ proofs and derives the SP output`);
    this.log("  CHECK THE OUTPUT ON THE DEVICE, THEN APPROVE THE TRANSACTION");
    const ready = this.waitEvent("signature_ready", s.id, 10 * 60_000);
    const res: any = await this.bridge.request({ method: "sign", session_id: s.id, offers: this.orderedOffers(m.offers) }, 120_000);
    this.log(`  sign: ${res?.status ?? JSON.stringify(res)}`);
    if (typeof res?.completed_task !== "string") throw new Error(`sign returned no completed_task: ${JSON.stringify(res)}`);
    const hash = createHash("sha256").update(res.completed_task).digest("hex");
    s.derived.set(this.cfg.shareIndex, hash);
    await this.send({ t: "fs.derived", sessionId: s.id, shareIndex: this.cfg.shareIndex, completedTaskHash: hash });
    await ready;
    await this.fetchShares();
  }

  /** Shares are released only once every signer in the subset derived the identical completed task. */
  private async derivationsAgree(s: SignerSession) {
    for (let i = 0; i < 240 && s.subset!.some((x) => !s.derived.has(x)) && !s.done; i++) await new Promise((r) => setTimeout(r, 500));
    if (s.done) return false;
    const missing = s.subset!.filter((x) => !s.derived.has(x));
    if (missing.length) { await this.abort(s.id, `no derivation from share(s) ${missing} within 2 min`); return false; }
    const hashes = new Set(s.subset!.map((x) => s.derived.get(x)));
    if (hashes.size !== 1) { await this.abort(s.id, "signers derived DIFFERENT transactions — refusing to release shares"); return false; }
    this.log(`✓ all ${s.subset!.length} signers derived the identical completed transaction (${[...hashes][0]!.slice(0, 12)}…)`);
    return true;
  }

  async fetchShares() {
    const s = this.signer;
    if (!s || s.sharesSent || !s.signing) return;
    if (!(await this.derivationsAgree(s))) return;
    if (s.sharesSent) return;
    const res = await this.bridge.request<{ shares: unknown }>({ method: "shares", session_id: s.id }, 60_000);
    s.sharesSent = true;
    this.log(`✓ device signed — sending shares (share ${this.cfg.shareIndex})`);
    await this.send({ t: "fs.shares", sessionId: s.id, shareIndex: this.cfg.shareIndex, shares: res.shares });
  }

  private orderedOffers(offers: { shareIndex: number; offer: BridgeOffer }[]) {
    return [...offers].sort((a, b) => a.shareIndex - b.shareIndex).map((o) => o.offer);
  }

  // ------------------------------------------------------------ coordinator
  /** Build the task with the coordinator's bridge and send one proposal to everyone. */
  async propose(args: { inputs: any[]; recipients: { address: string; amount_sat: number }[]; change?: { index: number; amount_sat: number } }) {
    if (!this.isCoordinator) throw new Error("only the coordinator proposes");
    if (this.coord && !this.coord.completed) throw new Error(`session ${short(this.coord.id)} still open — \`cancel\` first`);
    if (args.recipients.length !== 1) this.log("note: milestone 1 targets exactly one SP recipient");
    const prep = await this.bridge.request<{ task: string; fee_sat?: number }>({
      method: "prepare", key_id: this.cfg.pin.keyId, inputs: args.inputs.map(({ transaction, vout, internal, index }) => ({ transaction, vout, internal, index })), recipients: args.recipients, ...(args.change ? { change: args.change } : {}),
    }, 60_000);
    if (typeof prep?.task !== "string") throw new Error(`unexpected prepare result ${JSON.stringify(prep)}`);
    const id = newSessionId();
    this.coord = { id, offers: new Map(), shares: new Map() };
    this.coord.timer = setTimeout(() => this.cancel("timeout"), (this.cfg.sessionTimeoutMin ?? 20) * 60_000);
    this.log(`→ proposing session ${short(id)} (fee ${prep.fee_sat ?? "?"} sat) to ${Object.keys(this.cfg.members).length} signers`);
    await this.send({
      t: "fs.proposal", sessionId: id, task: prep.task, feeSat: prep.fee_sat,
      pin: { protocol: BRIDGE_PROTOCOL, ...this.cfg.pin },
      summary: { recipients: args.recipients, change: args.change, inputs: args.inputs.map((i) => ({ txid: i.txid ?? "?", vout: i.vout })) },
    });
    return id;
  }

  private async coordOnOffer(m: Extract<FsMsg, { t: "fs.offer" }>) {
    const c = this.coord;
    if (!c || c.id !== m.sessionId || c.subset) return;
    if (c.offers.has(m.shareIndex)) return;
    c.offers.set(m.shareIndex, m.offer);
    this.log(`✓ offer from share ${m.shareIndex} (${c.offers.size}/${this.cfg.threshold})`);
    if (c.offers.size >= this.cfg.threshold) {
      this.log(`✓ ${c.offers.size} hardware-approved ECDH offers collected for ${short(c.id)}`);
      if (this.cfg.gateBeforeSign) this.log("  MILESTONE 1 GATE: type `sign` to send the sign request (devices verify proofs + derive the output before approval)");
      else await this.requestSignatures();
    }
  }

  /** Freeze the subset and send the SAME offers to every signer in it. */
  async requestSignatures() {
    const c = this.coord;
    if (!c) throw new Error("no open session");
    if (c.subset) throw new Error("subset already frozen");
    if (c.offers.size < this.cfg.threshold) throw new Error(`only ${c.offers.size}/${this.cfg.threshold} offers`);
    c.subset = [...c.offers.keys()].sort((a, b) => a - b).slice(0, this.cfg.threshold);
    await this.send({ t: "fs.sign_request", sessionId: c.id, subset: c.subset, offers: c.subset.map((i) => ({ shareIndex: i, offer: c.offers.get(i)! })) });
  }

  private async coordOnShares(m: Extract<FsMsg, { t: "fs.shares" }>) {
    const c = this.coord;
    if (!c || c.id !== m.sessionId || !c.subset?.includes(m.shareIndex) || c.shares.has(m.shareIndex) || c.completed) return;
    c.shares.set(m.shareIndex, m.shares);
    this.log(`✓ signature shares from share ${m.shareIndex} (${c.shares.size}/${c.subset.length})`);
    if (c.shares.size < c.subset.length) return;
    const offers = c.subset.map((i) => c.offers.get(i)!);
    const shares = c.subset.flatMap((i) => { const s = c.shares.get(i); return Array.isArray(s) ? s : [s]; });
    const res: any = await this.bridge.request({ method: "combine", session_id: c.id, offers, shares }, 60_000);
    const txHex = res?.transaction ?? res?.tx_hex ?? res?.tx ?? res?.signed_transaction ?? res?.hex;
    const txid = res?.txid;
    if (typeof txHex !== "string" || typeof txid !== "string") throw new Error(`unexpected combine result ${JSON.stringify(res)}`);
    c.completed = true;
    c.complete = { txid, txHex };
    clearTimeout(c.timer);
    this.log(`✓ signed transaction ${txid}`);
    this.log(`  NOT broadcast. To broadcast on Signet: paste the hex at https://mempool.space/signet/tx/push`);
    this.log(`  ${txHex}`);
    await this.send({ t: "fs.complete", sessionId: c.id, txid, txHex });
  }

  // ------------------------------------------------------------ cancel
  async cancel(reason = "cancelled by operator") {
    const id = this.coord?.id ?? this.signer?.id;
    if (!id) return this.log("nothing to cancel");
    await this.send({ t: "fs.cancel", sessionId: id, reason, by: this.cfg.shareIndex });
  }

  private async abort(id: string, reason: string) {
    this.log(`✗ ${reason} — cancelling`);
    await this.send({ t: "fs.cancel", sessionId: id, reason, by: this.cfg.shareIndex });
  }

  private async onCancel(id: string, reason: string, _local: boolean) {
    let touched = false;
    if (this.signer?.id === id && !this.signer.done) {
      touched = true;
      this.signer.done = true;
      this.signer.cancelled = reason;
      try { await this.bridge.request({ method: "cancel", session_id: id }, 15_000); } catch (e: any) { this.log(`bridge cancel: ${e.message}`); }
    }
    if (this.coord?.id === id && !this.coord.completed) {
      touched = true;
      this.coord.completed = true;
      clearTimeout(this.coord.timer);
    }
    if (touched) this.log(`✗ session ${short(id)} cancelled: ${reason}`);
  }

  /** Everything the dashboard shows, from this Mac's point of view. */
  snapshot() {
    const s = this.signer, c = this.coord, t = this.cfg.threshold;
    const members = Object.entries(this.cfg.members)
      .map(([pubkey, shareIndex]) => ({ pubkey, shareIndex, me: pubkey === this.node.pubkey, coordinator: pubkey === this.cfg.coordinator }))
      .sort((a, b) => a.shareIndex - b.shareIndex);
    let session: any = null;
    if (s) {
      const offers = new Set([...s.offersSeen.keys(), ...(c?.id === s.id ? c.offers.keys() : [])]);
      const subset = s.subset ?? (c?.id === s.id ? c.subset : undefined);
      const signedSet = new Set([...s.sharesSeen, ...(s.sharesSent ? [this.cfg.shareIndex] : [])]);
      const complete = s.complete ?? (c?.id === s.id ? c.complete : undefined);
      const live = !s.cancelled && !complete;
      const per: Record<number, any> = {};
      for (const m of members) {
        const i = m.shareIndex;
        per[i] = {
          ecdh: offers.has(i) ? "done" : live ? "approve" : "idle",
          derived: s.derived.get(i) ?? null,
          sign: signedSet.has(i) ? "done" : live && subset?.includes(i) ? "approve" : "idle",
        };
      }
      const hashes = subset ? subset.map((i) => s.derived.get(i)) : [];
      const derivedMatch = hashes.length && hashes.every(Boolean) ? new Set(hashes).size === 1 : null;
      const stage = s.cancelled ? "cancelled" : complete ? "complete"
        : subset && signedSet.size >= subset.length ? "combining"
        : subset ? (derivedMatch ? "signing" : "deriving")
        : offers.size >= t ? "gate" : "ecdh";
      session = {
        id: s.id, recipients: s.proposal.summary.recipients, change: s.proposal.summary.change ?? null,
        inputs: s.proposal.summary.inputs, feeSat: s.proposal.feeSat ?? null,
        stage, per, subset: subset ?? null, derivedMatch, complete: complete ?? null, cancelled: s.cancelled ?? null,
        offers: offers.size, signed: signedSet.size,
      };
    }
    return {
      me: { name: this.cfg.name, pubkey: this.node.pubkey, shareIndex: this.cfg.shareIndex, role: this.cfg.role },
      isCoordinator: this.isCoordinator, threshold: t, members, relays: this.cfg.relays,
      group: this.node.groupId ?? null, deviceReady: this.deviceReady, deviceId: this.cfg.deviceId ?? null,
      bridgeRevision: this.bridgeRevision ?? null, gateBeforeSign: !!this.cfg.gateBeforeSign,
      canPropose: this.isCoordinator && (!c || !!c.completed), canSign: this.isCoordinator && !!c && !c.completed && !c.subset && c.offers.size >= t,
      session,
    };
  }

  status() {
    const s = this.signer, c = this.coord;
    return {
      me: { name: this.cfg.name, pubkey: this.node.pubkey, shareIndex: this.cfg.shareIndex, deviceId: this.cfg.deviceId, group: this.node.groupId },
      signer: s && { session: s.id, myOffer: !!s.myOffer, offersSeen: [...s.offersSeen.keys()], signing: !!s.signing, sharesSent: !!s.sharesSent, done: !!s.done },
      coordinator: c && { session: c.id, offers: [...c.offers.keys()], subset: c.subset, shares: [...c.shares.keys()], completed: !!c.completed },
    };
  }
}
