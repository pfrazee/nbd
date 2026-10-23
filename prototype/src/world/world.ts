// The emulated world: PDSes, the Spaces host, a DID registry, a virtual
// clock, and every installation. It implements the installations' Network
// and offers the user-level actions scenarios and the UI drive.

import { type Cbor, ref } from "../protocol/encoding";
import { type KeyPair, Rng, sign } from "../protocol/crypto";
import { Installation, type InstallationState, type Network } from "../protocol/installation";
import type { RecordPath, Snapshot, WriteOp } from "../protocol/repo";
import { approvalPayload } from "../protocol/trust";
import { type Approval, type Binding, COL, type Did, asCbor } from "../protocol/types";
import { Adversary } from "./adversary";
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
  /** Hours each installation's reads of repos lag behind the present. */
  readonly lag = new Map<string, number>();
  readonly adversary = new Adversary((did) => this.pdsOf.get(did));
  readonly stolen: StolenKeys[] = [];
  readonly backups: { name: string; from: string; at: number; state: InstallationState }[] = [];
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
    return this.pdsOf.get(did)?.enumerate(observer, did, undefined, this.lag.get(observer) ?? 0) ?? null;
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
    return pds.enumerate(observer, did, space, this.lag.get(observer) ?? 0);
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
      p = new Pds(name, this.rng.derive(`pds/${name}`), () => this.t);
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
    const k = { sign: inst.signKey, enc: inst.encKey, deviceId: inst.binding.device.deviceId, binding: inst.binding };
    this.stolen.push(k);
    this.note(`keys of ${inst.id} copied`);
    return k;
  }

  // ---- malicious PDS -------------------------------------------------------------

  /** An installation the PDS itself operates for `did`, with a session that
   * can write anything. Its device record is published only where the
   * caller puts it. */
  private pdsDevice(did: Did, deviceName: string): Installation {
    const pds = this.pdsOf.get(did)!;
    const id = `${did.replace("did:plc:", "")}/${deviceName}`;
    const inst = new Installation(this, id, deviceName, did, this.rng.derive(`install/${id}/${++this.counter}`));
    inst.sessionId = pds.login(did, "password", `${pds.name} operator`).id;
    this.installations.set(id, inst);
    return inst;
  }

  /** First-contact substitution: `victim` (and the substitute itself) see
   * `did`'s repo with every device replaced by one the PDS controls. */
  substituteDevices(did: Did, victim: Installation, deviceName = "attacker"): Installation {
    const sub = this.pdsDevice(did, deviceName);
    const record = sub.deviceRecord() as { collection: string; rkey: string; value: Cbor };
    this.adversary.add({
      kind: "forge", did, observers: [victim.id, sub.id], revOffset: 0,
      describe: `${this.pdsOf.get(did)!.name} shows ${victim.id} a substitute device for ${did}`,
      transform: (records) => {
        const out = new Map<RecordPath, Cbor>();
        for (const [k, v] of records) if (!k.startsWith(COL.device + "/") && !k.startsWith(COL.approval + "/")) out.set(k, v);
        out.set(`${record.collection}/${record.rkey}`, record.value);
        return out;
      },
    });
    this.note(`${this.pdsOf.get(did)!.name} substitutes ${sub.id} for ${did}, shown to ${victim.id}`);
    this.settle();
    return sub;
  }

  /** The PDS resets `did` (deleting every device, enrolling its own) while
   * showing the account's own installations the old state. */
  hiddenReset(did: Did, deviceName = "attacker"): Installation {
    const pds = this.pdsOf.get(did)!;
    const own = [...this.installations.values()].filter((i) => i.did === did).map((i) => i.id);
    this.adversary.add({ kind: "withhold", did, observers: own, rev: pds.repo(did).rev, describe: `${pds.name} hides ${did}'s newer commits from its own devices` });
    const sub = this.pdsDevice(did, deviceName);
    const devices = [...pds.repo(did).records.keys()].filter((k) => k.startsWith(COL.device + "/"));
    pds.write(sub.sessionId!, [
      ...devices.map((k) => ({ action: "delete" as const, collection: COL.device, rkey: k.slice(COL.device.length + 1) })),
      sub.deviceRecord(),
    ]);
    this.note(`${pds.name} reset ${did} to ${sub.id}, hidden from ${own.join(", ")}`);
    this.settle();
    return sub;
  }

  /** Show `victim` a history where `target`'s record was deleted. */
  hideDeviceFrom(target: Binding, victim: Installation): void {
    const path = `${COL.device}/${target.device.deviceId}`;
    this.adversary.add({
      kind: "forge", did: target.account, observers: [victim.id], revOffset: 1,
      describe: `${this.pdsOf.get(target.account)!.name} hides ${target.device.deviceId.slice(0, 6)} from ${victim.id}`,
      transform: (records) => {
        const out = new Map(records);
        out.delete(path);
        return out;
      },
    });
    this.note(`${this.pdsOf.get(target.account)!.name} forks ${target.account}'s history for ${victim.id}`);
    this.settle();
  }

  setLag(inst: Installation, hours: number): void {
    if (hours > 0) this.lag.set(inst.id, hours);
    else this.lag.delete(inst.id);
    this.note(`${inst.id} now sees repos ${hours}h late`);
    this.settle();
  }

  // ---- backups -------------------------------------------------------------------

  backup(inst: Installation, name = `${inst.id} backup`): void {
    this.backups.push({ name, from: inst.id, at: this.t, state: inst.exportState() });
    this.note(`${inst.id} backed up`);
  }

  /** `from` is lost; a new installation restores its keys and the backup. */
  restore(from: Installation, backupIndex: number, deviceName = `${from.name}-restored`): Installation {
    const b = this.backups[backupIndex];
    from.online = false;
    if (from.sessionId) this.pdsOf.get(from.did)!.endSession(from.sessionId);
    this.installations.delete(from.id);
    const id = `${from.did.replace("did:plc:", "")}/${deviceName}`;
    const inst = new Installation(this, id, deviceName, from.did, this.rng.derive(`install/${id}/${++this.counter}`), from.clockOffset,
      { sign: from.signKey, enc: from.encKey, deviceId: from.binding.device.deviceId });
    inst.sessionId = this.pdsOf.get(from.did)!.login(from.did, "app", id).id;
    this.installations.set(id, inst);
    inst.importState(b.state);
    this.note(`${from.id} was lost; ${id} restored ${b.name} from ${b.at.toFixed(0)}h`);
    this.settle();
    return inst;
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
