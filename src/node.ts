// A Marmot participant (coordinator or FROST device) wrapping marmot-ts.
// Handles key packages, invites, joining, and sending/receiving ceremony messages.
import { EventEmitter } from "eventemitter3";
import { PrivateKeySigner } from "applesauce-signers";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  MarmotClient,
  createApplicationMessageIntent,
  deserializeApplicationData,
  type NostrNetworkInterface,
} from "@internet-privacy/marmot-ts";
import { InMemoryKeyValueStore } from "@internet-privacy/marmot-ts/extra";
import { CEREMONY_KIND, decode, encode, type CeremonyMsg } from "./schema.ts";

export interface Inbound {
  from: string; // sender nostr pubkey (authenticated by MLS)
  msg: CeremonyMsg;
}

export class VaultNode extends EventEmitter<{ message: [Inbound]; joined: [string] }> {
  client!: MarmotClient;
  signer: PrivateKeySigner;
  pubkey!: string;
  groupId?: string;
  private watching = new Set<string>();

  constructor(
    public name: string,
    private network: NostrNetworkInterface,
    public relays: string[],
  ) {
    super();
    this.signer = new PrivateKeySigner();
  }

  async start() {
    this.pubkey = await this.signer.getPublicKey();
    this.client = new MarmotClient({
      signer: this.signer,
      network: this.network,
      groupStateStore: new InMemoryKeyValueStore(),
      keyPackageStore: new InMemoryKeyValueStore(),
      clientId: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
    });
    await this.client.keyPackages.create({ relays: this.relays });
    this.listenForInvites();
    return this;
  }

  /** Coordinator: create the vault group. */
  async createGroup(name: string) {
    const group = await this.client.groups.create(name, {
      description: "Marmot Vault signing group",
      relays: this.relays,
      adminPubkeys: [this.pubkey],
    });
    this.groupId = bytesToHex(group.id);
    this.watchGroup(group);
    return this.groupId;
  }

  /** Coordinator: invite a device by its nostr pubkey (looks up its key package). */
  async invite(pubkey: string) {
    const [kp] = await this.client.network.request(this.relays, [
      { kinds: [30443], authors: [pubkey], limit: 1 },
    ]);
    if (!kp) throw new Error(`no key package for ${pubkey.slice(0, 8)}`);
    await this.client.groups.invite(this.groupId!, kp);
  }

  async send(msg: CeremonyMsg) {
    if (!this.groupId) throw new Error(`${this.name} is not in a group`);
    const rumor = await this.makeRumor(encode(msg));
    await this.client.groups.send(this.groupId, createApplicationMessageIntent(rumor));
  }

  private async makeRumor(content: string) {
    const { getEventHash } = await import("nostr-tools/pure");
    const r: any = {
      kind: CEREMONY_KIND,
      pubkey: this.pubkey,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content,
    };
    r.id = getEventHash(r);
    return r;
  }

  private listenForInvites() {
    this.client.network
      .subscription(this.relays, [{ kinds: [1059], "#p": [this.pubkey] }])
      .subscribe({
        next: async (ev) => {
          await this.client.invites.ingestEvent(ev);
          await this.client.invites.decryptGiftWraps();
          for (const welcomeRumor of await this.client.invites.getUnread()) {
            const { group } = await this.client.joinGroupFromWelcome({ welcomeRumor });
            await this.client.invites.markAsRead(welcomeRumor.id);
            this.groupId = bytesToHex(group.id);
            this.watchGroup(group);
            this.emit("joined", this.groupId);
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
      if (rumor.kind !== CEREMONY_KIND) return;
      const msg = decode(rumor.content);
      if (msg) this.emit("message", { from: rumor.pubkey, msg });
    });

    // Feed kind 445 group events into MLS. Serialize ingestion per group.
    let chain = Promise.resolve();
    this.client.network
      .subscription(group.relays, [{ kinds: [445], "#h": [bytesToHex(group.groupData.nostrGroupId)] }])
      .subscribe({
        next: (event) => {
          chain = chain.then(async () => {
            for await (const r of group.ingest([event])) {
              if (r.kind === "unreadable") console.warn(`[${this.name}] unreadable event`);
            }
          }).catch((e) => console.error(`[${this.name}] ingest error`, e));
        },
      });
  }
}
