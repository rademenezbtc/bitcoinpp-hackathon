// A Marmot participant (coordinator or signer) wrapping marmot-ts.
// Handles key packages, invites, joining, and sending/receiving app rumors.
import { EventEmitter } from "eventemitter3";
import { PrivateKeySigner } from "applesauce-signers";
import { bytesToHex } from "@noble/hashes/utils.js";
import { getEventHash } from "nostr-tools/pure";
import {
  MarmotClient,
  createApplicationMessageIntent,
  deserializeApplicationData,
  type NostrNetworkInterface,
} from "@internet-privacy/marmot-ts";
import { InMemoryKeyValueStore } from "@internet-privacy/marmot-ts/extra";
import { CEREMONY_KIND, decode, encode, type CeremonyMsg } from "./schema.ts";

export interface Inbound {
  from: string; // sender nostr pubkey (MLS-authenticated)
  msg: CeremonyMsg;
}
export interface InboundRumor {
  from: string; // MLS-authenticated sender pubkey
  kind: number;
  content: string;
  id: string;
  local: boolean; // true when it's our own message, dispatched in-process
}

export interface NodeOptions {
  /** Persisted Nostr secret key; random if omitted. */
  secretKey?: Uint8Array;
  /** Stable key-package slot (64 hex chars); random if omitted. */
  clientId?: string;
  /** Group-state store; in-memory if omitted. */
  groupStateStore?: any;
  /** Only join groups whose Welcome was sent by one of these pubkeys. Empty/undefined = accept any. */
  acceptInvitesFrom?: string[];
  log?: (s: string) => void;
}

export class VaultNode extends EventEmitter<{ message: [Inbound]; rumor: [InboundRumor]; joined: [string] }> {
  client!: MarmotClient;
  signer: PrivateKeySigner;
  pubkey!: string;
  groupId?: string;
  private watching = new Set<string>();
  private log: (s: string) => void;
  /**
   * One queue for every MLS state change (sends, ingests, invites). marmot-ts
   * 0.9 loses messages ("Desired gen in the past") when a send overlaps an
   * ingest on the same group, so nothing here runs concurrently.
   */
  private queue: Promise<unknown> = Promise.resolve();
  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  constructor(
    public name: string,
    private network: NostrNetworkInterface,
    public relays: string[],
    private opts: NodeOptions = {},
  ) {
    super();
    this.signer = new PrivateKeySigner(opts.secretKey);
    this.log = opts.log ?? ((s) => console.log(`[${name}] ${s}`));
  }

  async start() {
    this.pubkey = await this.signer.getPublicKey();
    this.client = new MarmotClient({
      signer: this.signer,
      network: this.network,
      groupStateStore: this.opts.groupStateStore ?? new InMemoryKeyValueStore(),
      keyPackageStore: new InMemoryKeyValueStore(),
      clientId: this.opts.clientId ?? bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
    });
    // Rejoin groups persisted from an earlier run.
    for (const g of await this.client.groups.loadAll()) {
      this.groupId = bytesToHex(g.id);
      this.watchGroup(g);
      this.log(`resumed group ${this.groupId.slice(0, 12)}…`);
    }
    await this.publishKeyPackage();
    this.listenForInvites();
    return this;
  }

  /** (Re)publish our key package so the coordinator can invite us. Returns false if no relay took it. */
  async publishKeyPackage() {
    try {
      await this.client.keyPackages.create({ relays: this.relays });
      const mine = await this.client.network.request(this.relays, [{ kinds: [30443], authors: [this.pubkey], limit: 1 }]);
      return mine.length > 0;
    } catch (e: any) {
      this.log(`key package publish failed: ${e?.message ?? e}`);
      return false;
    }
  }

  /** Coordinator: create the vault group. */
  async createGroup(name: string) {
    const group = await this.client.groups.create(name, {
      description: "BlackIce signing group",
      relays: this.relays,
      adminPubkeys: [this.pubkey],
    });
    this.groupId = bytesToHex(group.id);
    this.watchGroup(group);
    return this.groupId;
  }

  /** Coordinator: invite a member by nostr pubkey (looks up its key package). */
  async invite(pubkey: string) {
    const kps = await this.client.network.request(this.relays, [{ kinds: [30443], authors: [pubkey] }]);
    const kp = kps.sort((a, b) => b.created_at - a.created_at)[0];
    if (!kp) throw new Error(`no key package on relays for ${pubkey.slice(0, 8)}… — is its app running?`);
    await this.exclusive(() => this.client.groups.invite(this.groupId!, kp));
  }

  /** Send an app rumor of any kind to the group; also delivered to our own handlers. */
  async sendRumor(kind: number, content: string) {
    if (!this.groupId) throw new Error(`${this.name} is not in a group yet`);
    const r: any = { kind, pubkey: this.pubkey, created_at: Math.floor(Date.now() / 1000), tags: [], content };
    r.id = getEventHash(r);
    const gid = this.groupId;
    await this.exclusive(() => this.client.groups.send(gid, createApplicationMessageIntent(r)));
    queueMicrotask(() => this.dispatch({ from: this.pubkey, kind, content, id: r.id, local: true }));
  }

  /** Legacy ceremony messages (schema v2 demo). */
  async send(msg: CeremonyMsg) {
    await this.sendRumor(CEREMONY_KIND, encode(msg));
  }

  private dispatch(r: InboundRumor) {
    this.emit("rumor", r);
    if (r.kind === CEREMONY_KIND && !r.local) {
      const msg = decode(r.content);
      if (msg) this.emit("message", { from: r.from, msg });
    }
  }

  private listenForInvites() {
    const allow = this.opts.acceptInvitesFrom?.filter(Boolean) ?? [];
    this.client.network
      .subscription(this.relays, [{ kinds: [1059], "#p": [this.pubkey] }])
      .subscribe({
        next: async (ev) => {
          try {
            await this.client.invites.ingestEvent(ev);
            await this.client.invites.decryptGiftWraps();
            for (const welcomeRumor of await this.client.invites.getUnread()) {
              await this.client.invites.markAsRead(welcomeRumor.id);
              if (allow.length && !allow.includes(welcomeRumor.pubkey)) {
                this.log(`ignored invite from unknown ${welcomeRumor.pubkey.slice(0, 8)}…`);
                continue;
              }
              let group: any;
              try {
                ({ group } = await this.client.joinGroupFromWelcome({ welcomeRumor }));
              } catch (e: any) {
                // Relays replay old invites; ones sealed to a key package from an earlier run can't be opened.
                if (/no matching|matching key package/i.test(e?.message ?? "")) {
                  if (!this.groupId) this.log("ignored an old invite (made for a previous run) — waiting for a fresh one");
                  continue;
                }
                throw e;
              }
              this.groupId = bytesToHex(group.id);
              this.watchGroup(group);
              this.emit("joined", this.groupId);
            }
          } catch (e: any) {
            this.log(`invite handling failed: ${e?.message ?? e}`);
          }
        },
      });
  }

  private watchGroup(group: any) {
    const gid = bytesToHex(group.id);
    if (this.watching.has(gid)) return;
    this.watching.add(gid);

    group.on("applicationMessage", (data: Uint8Array) => {
      const rumor = deserializeApplicationData(data);
      if (rumor.pubkey === this.pubkey) return; // own messages are dispatched locally
      this.dispatch({ from: rumor.pubkey, kind: rumor.kind, content: rumor.content, id: rumor.id, local: false });
    });

    // Feed kind 445 group events into MLS through the same queue as sends.
    const seen = new Set<string>();
    this.client.network
      .subscription(group.relays, [{ kinds: [445], "#h": [bytesToHex(group.groupData.nostrGroupId)] }])
      .subscribe({
        next: (event) => {
          if (seen.has(event.id)) return;
          seen.add(event.id);
          this.exclusive(async () => {
            for await (const r of group.ingest([event])) {
              if (r.kind === "unreadable")
                this.log(`unreadable group event: ${(r as any).errors?.map((e: any) => e?.message ?? String(e)).join("; ")}`);
            }
          }).catch((e) => this.log(`ingest error: ${e?.message ?? e}`));
        },
      });
  }
}
