/** Node 24 / Bun adapter. Runs locally on EACH signer's Mac, never on a relay. */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";

export const PROTOCOL = "frostsnap-sp-bridge/1";
export interface Offer { binonces: string; ecdh: string }
export class FrostsnapBridge extends EventEmitter {
  private child: ChildProcessWithoutNullStreams;
  private pending = new Map<string, {resolve:(value: unknown)=>void; reject:(error:Error)=>void; timer:ReturnType<typeof setTimeout>}>();
  private stopped = false;
  constructor(binary: string, args: string[]) {
    super();
    this.child = spawn(binary, args, {stdio:"pipe"});
    createInterface({input:this.child.stdout}).on("line", line => {
      try {
        const message = JSON.parse(line);
        if (message.event) { this.emit("notification", message); return; }
        const request = this.pending.get(message.id);
        if (!request) return;
        this.pending.delete(message.id);
        clearTimeout(request.timer);
        if (message.error) request.reject(new Error(message.error));
        else request.resolve(message.result);
      } catch (error) { this.fail(new Error(`Invalid bridge response: ${String(error)}`)); }
    });
    this.child.stderr.on("data", chunk => this.emit("diagnostic", chunk.toString()));
    this.child.on("error", error => this.fail(error));
    this.child.on("exit", (code,signal) => this.fail(new Error(`Bridge exited: ${code ?? signal}`)));
  }
  request<T=unknown>(command: Record<string, unknown>, timeoutMs=30_000): Promise<T> {
    if (this.stopped) return Promise.reject(new Error("Bridge is stopped"));
    const id = randomUUID();
    return new Promise((resolve,reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("Bridge request timed out; query the existing session before retrying"));
      }, timeoutMs);
      this.pending.set(id,{resolve:value=>resolve(value as T),reject,timer});
      this.child.stdin.write(JSON.stringify({protocol:PROTOCOL,id,command})+"\n", error => {
        if (error) this.fail(error);
      });
    });
  }
  close() { this.child.stdin.end(); }
  private fail(error: Error) {
    this.stopped = true;
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(error); }
    this.pending.clear();
    this.emit("diagnostic", error.message);
  }
}
