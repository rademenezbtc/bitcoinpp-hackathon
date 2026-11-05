// Wraps a marmot-ts network so the dashboard can show exactly what crosses the
// wire: every event this Mac publishes or receives from relays.
import type { NostrEvent } from "applesauce-core/helpers/event";
import type { NostrNetworkInterface } from "@internet-privacy/marmot-ts/client";

export interface WireEvent {
  dir: "out" | "in";
  at: number;
  id: string;
  kind: number;
  pubkey: string;
  tags: string[][];
  bytes: number;
  content: string;
}

export function tapNetwork(net: NostrNetworkInterface, onWire: (w: WireEvent) => void): NostrNetworkInterface {
  const seen = new Set<string>();
  const emit = (dir: WireEvent["dir"], e: NostrEvent) => {
    const key = `${dir}:${e.id}`;
    if (seen.has(key) || (dir === "in" && seen.has(`out:${e.id}`))) return;
    seen.add(key);
    onWire({ dir, at: Date.now(), id: e.id, kind: e.kind, pubkey: e.pubkey, tags: e.tags, bytes: e.content.length, content: e.content });
  };
  return {
    ...net,
    async publish(relays, event) {
      emit("out", event);
      return net.publish(relays, event);
    },
    request: (relays, filters) => net.request(relays, filters).then((evs) => (evs.forEach((e) => emit("in", e)), evs)),
    subscription(relays, filters) {
      const inner = net.subscription(relays, filters);
      return {
        subscribe(observer) {
          return inner.subscribe({ ...observer, next: (e) => { emit("in", e); observer.next?.(e); } });
        },
      };
    },
    getUserInboxRelays: (pk) => net.getUserInboxRelays(pk),
  } as NostrNetworkInterface;
}
