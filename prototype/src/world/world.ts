// The emulated world: PDSes, the Spaces host, a DID registry, a virtual
// clock, and every installation. It implements the installations' Network
// and offers the user-level actions scenarios and the UI drive.

import { type Cbor, ref } from "../protocol/encoding";
import { type KeyPair, Rng, sign } from "../protocol/crypto";
import { Installation, type Network } from "../protocol/installation";
import type { Snapshot, WriteOp } from "../protocol/repo";
import { approvalPayload } from "../protocol/trust";
import { type Approval, type Binding, COL, type Did, asCbor } from "../protocol/types";
import { Host } from "./host";
import { Pds, type Session } from "./pds";

export type LogEntry = { at: number; text: string };
export type StolenKeys = { sign: KeyPair; enc: KeyPair; deviceId: string; binding: Binding };

export class World implements Network {
  t = 0;
  readonly rng: Rng;
  readonly registry = new Map<Did, Uint8Array>();
  readonly pdses = new Map<string, Pds>();
  readonly pdsOf = new Map<Did, Pds>();
  readonly host = new Host("host.example");
  readonly installations = new Map<string, Installation>();
  readonly log: LogEntry[] = [];
  private counter = 0;

  constructor(seed = "peep") {
    this.rng = Rng.fromLabel(seed);
  }

  // ---- Network ---------------------------------------------------------------

  now(): number {
    return this.t;
  }

  repoKey(did: Did): Uint8Array | null {
    return this.registry.get(did) ?? null;
  }

  enumerate(observer: string, did: Did): Snapshot | null {
    return this.pdsOf.get(did)?.enumerate(observer, did) ?? null;
  }

  private sessionPds(sessionId: string): [Pds, Session] | null {
    for (const p of this.pdses.values()) {
      const s = p.sessions.get(sessionId);
      if (s) return [p, s];
    }
    return null;
  }

  credential(sessionId: string, space: string): number | null {
    const found = this.sessionPds(sessionId);
    if (!found) return null;
    return this.host.issueCredential(space, found[1].did, found[1].alive, this.t);
  }

  readSpace(observer: string, credentialExpiry: number, did: Did, space: string): Snapshot | null {
    if (credentialExpiry <= this.t) return null;
    const pds = this.pdsOf.get(did);
    if (!pds?.repos.has(`${did}|${space}`)) return null;
    return pds.enumerate(observer, did, space);
  }

  write(sessionId: string, ops: WriteOp[], space?: string): void {
    const found = this.sessionPds(sessionId);
    if (!found) throw new Error("world: unknown session");
    found[0].write(sessionId, ops, space);
  }

  spaceWriters(space: string): Did[] {
    const out: Did[] = [];
    for (const p of this.pdses.values())
      for (const name of p.repos.keys()) if (name.endsWith(`|${space}`)) out.push(name.slice(0, -space.length - 1));
    return out;
  }

  // ---- setup -------------------------------------------------------------------

  pds(name: string): Pds {
    let p = this.pdses.get(name);
    if (!p) {
      p = new Pds(name, this.rng.derive(`pds/${name}`));
      this.pdses.set(name, p);
    }
    return p;
  }

  account(name: string, pdsName = "pds.example"): Did {
    const did = `did:plc:${name}`;
    const p = this.pds(pdsName);
    this.registry.set(did, p.createAccount(did));
    this.pdsOf.set(did, p);
    this.note(`${name} created an account at ${pdsName}`);
    return did;
  }

  /** Install the app. With `link`, the new device is approved by `link` and
   * pairs with it; without, it publishes its record alone (first device, or
   * an unlinked one). */
  install(did: Did, deviceName: string, opts: { link?: Installation; clockOffset?: number; keys?: StolenKeys } = {}): Installation {
    const id = `${did.replace("did:plc:", "")}/${deviceName}`;
    const inst = new Installation(this, id, deviceName, did, this.rng.derive(`install/${id}/${++this.counter}`), opts.clockOffset ?? 0, opts.keys);
    inst.sessionId = this.pdsOf.get(did)!.login(did, "app", id).id;
    this.installations.set(id, inst);
    if (opts.link) {
      opts.link.approve(inst);
      inst.pairFrom(opts.link);
      this.note(`${opts.link.id} linked ${id}`);
    } else {
      inst.publishOwnRecord();
      this.note(`${id} installed`);
    }
    this.settle();
    return inst;
  }

  // ---- user and attacker actions ----------------------------------------------------

  /** The user removes a device at their PDS: end its session (unless they
   * can't identify it), then delete its record with a one-off delete
   * authorization. */
  removeDevice(target: Installation | Binding, opts: { endSession?: boolean } = {}): void {
    const binding = target instanceof Installation ? target.binding : target;
    const pds = this.pdsOf.get(binding.account)!;
    if (target instanceof Installation && opts.endSession !== false && target.sessionId) pds.endSession(target.sessionId);
    const auth = pds.login(binding.account, "delete-auth", "delete authorization");
    pds.write(auth.id, [{ action: "delete", collection: COL.device, rkey: binding.device.deviceId }]);
    this.note(`${binding.account} removed device ${binding.device.deviceId.slice(0, 6)}`);
    this.settle();
  }

  /** Someone with the password deletes every device and enrolls their own. */
  takeover(did: Did, deviceName = "attacker"): Installation {
    const pds = this.pdsOf.get(did)!;
    const s = pds.login(did, "password", "attacker");
    const devices = [...pds.repo(did).records.keys()].filter((k) => k.startsWith(COL.device + "/"));
    pds.write(s.id, devices.map((k) => ({ action: "delete" as const, collection: COL.device, rkey: k.slice(COL.device.length + 1) })));
    const id = `${did.replace("did:plc:", "")}/${deviceName}`;
    const inst = new Installation(this, id, deviceName, did, this.rng.derive(`install/${id}/${++this.counter}`));
    inst.sessionId = s.id;
    this.installations.set(id, inst);
    inst.publishOwnRecord();
    this.note(`attacker took over ${did}: deleted ${devices.length} device(s), enrolled ${id}`);
    this.settle();
    return inst;
  }

  /** Copy an installation's keys, as a thief or an unwiped old device would. */
  stealKeys(inst: Installation): StolenKeys {
    return { sign: inst.signKey, enc: inst.encKey, deviceId: inst.binding.device.deviceId, binding: inst.binding };
  }

  /** Publish an approval signed with `signer`'s keys for `target`, through
   * any session with create access to the account (password, app). */
  approveWith(signer: StolenKeys, target: Installation, sessionId: string): void {
    const unsigned = { version: 1 as const, signer: signer.binding, target: target.binding };
    const approval: Approval = { ...unsigned, proof: sign(signer.sign.secretKey, approvalPayload(unsigned)) };
    const value: Cbor = { $type: COL.approval, value: asCbor(approval) };
    this.write(sessionId, [{ action: "create", collection: COL.approval, rkey: ref(asCbor(approval)), value }]);
    this.note(`approval signed with ${signer.binding.account}'s old key ${signer.deviceId.slice(0, 6)} for ${target.id}`);
    this.settle();
  }

  setOnline(inst: Installation, online: boolean): void {
    inst.online = online;
    this.note(`${inst.id} went ${online ? "online" : "offline"}`);
    if (online) this.settle();
  }

  advance(hours: number): void {
    this.t += hours;
    this.settle();
  }

  /** Let every online installation sync until nothing changes. */
  settle(maxRounds = 40): void {
    for (let i = 0; i < maxRounds; i++) {
      let changed = false;
      for (const inst of this.installations.values()) changed = inst.sync() || changed;
      if (!changed) return;
    }
    throw new Error("world: settle did not converge");
  }

  note(text: string): void {
    this.log.push({ at: this.t, text });
  }
}
