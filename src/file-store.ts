// Minimal on-disk GenericKeyValueStore<Uint8Array> (one file per key, 0600).
// Used for MLS group state so a restarted process stays in the group.
import { mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync, existsSync, chmodSync } from "node:fs";
import { join } from "node:path";

export class FileBytesStore {
  constructor(private dir: string) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(dir, 0o700);
  }
  private path(key: string) {
    return join(this.dir, Buffer.from(key).toString("hex"));
  }
  async getItem(key: string): Promise<Uint8Array | null> {
    const p = this.path(key);
    return existsSync(p) ? new Uint8Array(readFileSync(p)) : null;
  }
  async setItem(key: string, value: Uint8Array) {
    writeFileSync(this.path(key), value, { mode: 0o600 });
    return value;
  }
  async removeItem(key: string) {
    rmSync(this.path(key), { force: true });
  }
  async clear() {
    for (const f of readdirSync(this.dir)) rmSync(join(this.dir, f), { force: true });
  }
  async keys() {
    return readdirSync(this.dir).map((f) => Buffer.from(f, "hex").toString());
  }
}
