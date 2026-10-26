// The emulated world: PDSes, the Spaces host, a DID registry, a virtual
// clock, and every installation. It implements the installations' Network
// and offers the user-level actions scenarios and the UI drive.

import { type Cbor, ref } from "../protocol/encoding";
import { type KeyPair, Rng, sign } from "../protocol/crypto";
import { Installation, type InstallationState, type InviteEvent, type Network } from "../protocol/installation";
import type { RecordPath, Snapshot, WriteOp } from "../protocol/repo";
import { approvalPayload } from "../protocol/trust";
import { type Approval, type Binding, COL, type Did, type Policy, asCbor, label } from "../protocol/types";
import { Adversary } from "./adversary";
import { Host } from "./host";
import { Pds, type Session } from "./pds";

export type LogEntry = { at: number; text: string };

/** Public-repo operations in the Python model's terms (model/nbd_trust.py
 * World): bindings are [account, deviceId]. */
export type TraceBinding = [string, string];
export type TraceOp =
  | { op: "add"; b: TraceBinding }
  | { op: "approve"; s: TraceBinding; t: TraceBinding }
  | { op: "delete"; b: TraceBinding }
  | { op: "wait"; h: number }
  | { op: "skew"; who: string; h: number }
  /** An attempt to publish an invite or capture record (inviters policy).
   * `space` is the space URI here; fuzz traces replace it with the walk's
   * space label and keep only what the model's replay needs. */
  | InviteOp
  /** A resend of the oldest saved invite (`invite` is what was resent). */
  | { op: "flush"; by: TraceBinding; abandoned: boolean; published: boolean; invite: InviteOp };

export type InviteOp = {
  op: "invite"; by: TraceBinding; space: string; account: string; bindings: TraceBinding[];
  vouched: boolean; pending: boolean; captures: boolean; published: boolean;
};

/** Ground truth about one published invite record. `firstMet`: the inviting
 * installation had no pin for the account when it made the record; `devices`
 * are the device IDs it vouched for; `admits`: the account was not a member
 * of the space when it was published; `seq`: when the record was made;
 * `captures`: the rkey of the pending record a capture completes. */
export type InviteFact = {
  space: string; inviter: Did; device: string; account: Did; firstMet: boolean; devices: string[]; admits: boolean;
  pending: boolean; rkey: string; captures: string | null; at: number; seq: number;
};

/** Ground truth for the disclosure check: who really controls each device. */
export type Provenance = {
  attacker: Set<string>; // device IDs an attacker or malicious PDS controls
  stolenAt: Map<string, number>; // device ID -> when its keys were copied
  publishedAt: Map<string, number>; // device ID -> when its record first became visible
  publishedSeq: Map<string, number>; // the same, as a position in the event sequence
  /** `standing`: when signed, the account still had a device record the
   * attacker does not control, so it was not a full reset. */
  approvals: { signer: string; target: string; at: number; compromised: boolean; standing: boolean }[];
  invites: InviteFact[];
};

const tb = (b: Binding): TraceBinding => [b.account.replace("did:plc:", ""), b.device.deviceId];
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
  /** Write faults per installation: "reject" fails before applying; "lost-ack"
   * applies the write, then fails as a lost acknowledgement would. */
  readonly faults = new Map<string, { mode: "reject" | "lost-ack"; collection?: string; count: number }>();
  readonly provenance: Provenance = { attacker: new Set(), stolenAt: new Map(), publishedAt: new Map(), publishedSeq: new Map(), approvals: [], invites: [] };
  /** Orders events that happen at the same world time. */
  private seq = 0;

  tick(): number {
    return ++this.seq;
  }

  private published(deviceId: string): void {
    this.provenance.publishedAt.set(deviceId, this.t);
    this.provenance.publishedSeq.set(deviceId, this.tick());
  }
  /** When set, public-repo operations are appended here for replay. */
  trace: TraceOp[] | null = null;
  private counter = 0;

  /** The grant rule every installation follows; set at creation. */
  readonly policy: Policy;

  constructor(seed = "nbd", opts: { policy?: Policy } = {}) {
    this.rng = Rng.fromLabel(seed);
    this.policy = opts.policy ?? "baseline";
  }

  // ---- Network ---------------------------------------------------------------

  accountSpaces(did: Did): string[] {
    const out: string[] = [];
    const prefix = `${did}|`;
    for (const name of this.pdsOf.get(did)?.repos.keys() ?? []) if (name.startsWith(prefix)) out.push(name.slice(prefix.length));
    return out;
  }

  /** When each invite record was made, as an event sequence position. */
  private invitesMade = new Map<string, number>();

  invitePrepared(_by: Binding, rkey: string): void {
    if (!this.invitesMade.has(rkey)) this.invitesMade.set(rkey, this.tick());
  }

  /** Called before a published record admits its account. */
  invited(e: InviteEvent): void {
    const r = e.record;
    const op: InviteOp = {
      op: "invite", by: tb(e.by), space: e.space, account: r.account.replace("did:plc:", ""), bindings: r.bindings.map(tb),
      vouched: r.vouched, pending: r.pending, captures: r.captures !== null, published: e.published,
    };
    this.trace?.push(e.stage === "attempt" ? op : { op: "flush", by: tb(e.by), abandoned: e.abandoned, published: e.published, invite: op });
    const what = r.captures ? "captured the pending invite of" : r.pending ? "invited (pending)" : "invited";
    if (!e.published) {
      this.note(`${label(e.by)} ${e.abandoned ? "abandoned its invite of" : "could not publish its invite of"} ${r.account} to ${this.host.spaceName(e.space)}`);
      return;
    }
    const admits = r.captures === null && !this.host.membership(e.space, r.account)?.eligible;
    this.provenance.invites.push({
      space: e.space, inviter: e.by.account, device: e.by.device.deviceId, account: r.account, firstMet: e.firstMet,
      devices: e.vouched.map((b) => b.device.deviceId), admits, pending: r.pending, rkey: e.rkey, captures: r.captures,
      at: this.t, seq: this.invitesMade.get(e.rkey) ?? this.tick(),
    });
    this.note(`${label(e.by)} ${what} ${r.account} to ${this.host.spaceName(e.space)}${r.vouched ? `, vouching for ${r.bindings.length} device(s)` : ""}`);
  }

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

  write(sessionId: string, ops: WriteOp[], space?: string): number {
    const found = this.sessionPds(sessionId);
    if (!found) throw new Error("world: unknown session");
    const f = this.faults.get(found[1].label);
    const hit = f && f.count > 0 && (!f.collection || ops.some((o) => o.collection === f.collection));
    if (hit) f.count--;
    if (hit && f.mode === "reject") throw new Error("world: write rejected");
    const rev = found[0].write(sessionId, ops, space).commit.rev;
    if (hit && f.mode === "lost-ack") throw new Error("world: acknowledgement lost");
    return rev;
  }

  /** Make an installation's next `count` writes (to `collection`, if given) fail. */
  fault(inst: Installation, mode: "reject" | "lost-ack", count: number, collection?: string): void {
    this.faults.set(inst.id, { mode, collection, count });
    this.note(`${inst.id}'s next ${count} write(s)${collection ? ` to ${collection.split(".").pop()}` : ""} will ${mode === "reject" ? "be rejected" : "lose their acknowledgement"}`);
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
  install(did: Did, deviceName: string, opts: { link?: Installation; clockOffset?: number; keys?: StolenKeys; startOver?: boolean } = {}): Installation {
    const id = `${did.replace("did:plc:", "")}/${deviceName}`;
    const inst = new Installation(this, id, deviceName, did, this.rng.derive(`install/${id}/${++this.counter}`), opts.clockOffset ?? 0, opts.keys);
    inst.sessionId = this.pdsOf.get(did)!.login(did, "app", id).id;
    this.installations.set(id, inst);
    if (opts.link) {
      // Linking needs the approver to publish. A write whose acknowledgement
      // was lost may still have landed: read the repo back before giving up.
      const landed = () => this.pdsOf.get(did)!.repo(did).records.has(`${COL.device}/${inst.binding.device.deviceId}`);
      if (!opts.link.approve(inst) && !landed()) {
        this.installations.delete(id);
        this.pdsOf.get(did)!.endSession(inst.sessionId);
        throw new Error(`${opts.link.id} could not publish the approval`);
      }
      this.trace?.push({ op: "approve", s: tb(opts.link.binding), t: tb(inst.binding) }, { op: "add", b: tb(inst.binding) });
      const linker = opts.link.binding.device.deviceId;
      this.provenance.approvals.push({ signer: linker, target: inst.binding.device.deviceId, at: this.t, compromised: this.compromised(linker), standing: this.standing(did) });
      if (this.provenance.attacker.has(linker)) this.provenance.attacker.add(inst.binding.device.deviceId);
      inst.pairFrom(opts.link);
      this.note(`${opts.link.id} linked ${id}`);
    } else {
      if (opts.startOver) inst.beginStartOver();
      inst.publishOwnRecord();
      this.trace?.push({ op: "add", b: tb(inst.binding) });
      this.note(`${id} installed`);
    }
    this.published(inst.binding.device.deviceId);
    this.settle();
    return inst;
  }

  // ---- user and attacker actions ----------------------------------------------------

  /** The user, starting over on `inst`, removes every device on its list at
   * their PDS, then the app treats any that remain or appear as alarms
   * (device-enrollment.md#total-device-loss). */
  finishStartOver(inst: Installation): void {
    for (const b of inst.trust.state.startOver?.list?.values() ?? []) {
      const other = [...this.installations.values()].find((i) => i.binding.device.deviceId === b.device.deviceId);
      this.removeDevice(other ?? b);
    }
    inst.finishStartOver();
    this.note(`${inst.id} finished starting over`);
    this.settle();
  }

  /** The user removes a device at their PDS: end its session (unless they
   * can't identify it), then delete its record with a one-off delete
   * authorization. */
  removeDevice(target: Installation | Binding, opts: { endSession?: boolean } = {}): void {
    const binding = target instanceof Installation ? target.binding : target;
    const pds = this.pdsOf.get(binding.account)!;
    if (target instanceof Installation && opts.endSession !== false && target.sessionId) pds.endSession(target.sessionId);
    const auth = pds.login(binding.account, "delete-auth", "delete authorization");
    pds.write(auth.id, [{ action: "delete", collection: COL.device, rkey: binding.device.deviceId }]);
    this.trace?.push({ op: "delete", b: tb(binding) });
    this.note(`${binding.account} removed device ${binding.device.deviceId.slice(0, 6)}`);
    this.settle();
  }

  /** Someone with the password deletes every device and enrolls their own. */
  takeover(did: Did, deviceName = "attacker"): Installation {
    const pds = this.pdsOf.get(did)!;
    const s = pds.login(did, "password", "attacker");
    const devices = [...pds.repo(did).records.keys()].filter((k) => k.startsWith(COL.device + "/"));
    for (const k of devices) this.trace?.push({ op: "delete", b: [did.replace("did:plc:", ""), k.slice(COL.device.length + 1)] });
    pds.write(s.id, devices.map((k) => ({ action: "delete" as const, collection: COL.device, rkey: k.slice(COL.device.length + 1) })));
    const id = `${did.replace("did:plc:", "")}/${deviceName}`;
    const inst = new Installation(this, id, deviceName, did, this.rng.derive(`install/${id}/${++this.counter}`));
    inst.sessionId = s.id;
    this.installations.set(id, inst);
    inst.publishOwnRecord();
    this.provenance.attacker.add(inst.binding.device.deviceId);
    this.published(inst.binding.device.deviceId);
    this.trace?.push({ op: "add", b: tb(inst.binding) });
    this.note(`attacker took over ${did}: deleted ${devices.length} device(s), enrolled ${id}`);
    this.settle();
    return inst;
  }

  /** Someone with the password publishes their own device beside the
   * account's others. Contacts see it unlinked unless something approves it. */
  attackerDevice(did: Did, deviceName: string): Installation {
    const pds = this.pdsOf.get(did)!;
    const id = `${did.replace("did:plc:", "")}/${deviceName}`;
    const inst = new Installation(this, id, deviceName, did, this.rng.derive(`install/${id}/${++this.counter}`));
    inst.sessionId = pds.login(did, "password", "attacker").id;
    this.installations.set(id, inst);
    inst.publishOwnRecord();
    this.provenance.attacker.add(inst.binding.device.deviceId);
    this.published(inst.binding.device.deviceId);
    this.trace?.push({ op: "add", b: tb(inst.binding) });
    this.note(`attacker added ${id} with the password`);
    this.settle();
    return inst;
  }

  /** Copy an installation's keys, as a thief or an unwiped old device would. */
  stealKeys(inst: Installation): StolenKeys {
    const k = { sign: inst.signKey, enc: inst.encKey, deviceId: inst.binding.device.deviceId, binding: inst.binding };
    this.stolen.push(k);
    if (!this.provenance.stolenAt.has(k.deviceId)) this.provenance.stolenAt.set(k.deviceId, this.t);
    this.note(`keys of ${inst.id} copied`);
    return k;
  }

  /** The account has a device record the attacker does not control. */
  standing(did: Did): boolean {
    for (const k of this.pdsOf.get(did)!.repo(did).records.keys())
      if (k.startsWith(COL.device + "/") && !this.provenance.attacker.has(k.slice(COL.device.length + 1))) return true;
    return false;
  }

  /** Controlled by an attacker, or its keys copied. */
  compromised(deviceId: string): boolean {
    return this.provenance.attacker.has(deviceId) || this.provenance.stolenAt.has(deviceId);
  }

  /** Recreate a deleted device record: through the device's own session if it
   * survived removal, otherwise through someone with the password. */
  recreateRecord(inst: Installation): void {
    const pds = this.pdsOf.get(inst.did)!;
    const own = inst.sessionId ? pds.sessions.get(inst.sessionId) : undefined;
    const session = own?.alive && own.kind !== "delete-auth" ? own.id : pds.login(inst.did, "password", "recreate").id;
    pds.write(session, [inst.deviceRecord()]);
    this.trace?.push({ op: "add", b: tb(inst.binding) });
    this.note(`${inst.id}'s record recreated`);
    this.settle();
  }

  /** Rotate an account's repo signing key; the DID document follows. */
  rotateRepoKey(did: Did): void {
    this.registry.set(did, this.pdsOf.get(did)!.rotateKey(did));
    this.note(`${did} rotated its repo signing key`);
    this.settle();
  }

  /** Move an account to another PDS. Repos keep their revisions; records in
   * `drop` are not carried over, which revokes those devices. Every session
   * at the old PDS ends, and the account's installations sign in again. */
  migrate(did: Did, to: string, drop: string[] = []): void {
    const from = this.pdsOf.get(did)!;
    const dest = this.pds(to);
    const repos = [...from.repos.values()].filter((r) => r.did === did).map((r) => ({
      name: r.name, rev: r.rev,
      records: new Map([...r.records].filter(([k]) => !drop.some((d) => k === `${COL.device}/${d}`))),
    }));
    for (const d of drop) this.trace?.push({ op: "delete", b: [did.replace("did:plc:", ""), d] });
    const kinds = new Map(from.liveSessions(did).map((s) => [s.id, s.kind]));
    from.release(did);
    this.registry.set(did, dest.adopt(did, repos));
    this.pdsOf.set(did, dest);
    for (const i of this.installations.values()) {
      if (i.did !== did || !i.sessionId) continue;
      const kind = kinds.get(i.sessionId);
      i.sessionId = kind && kind !== "delete-auth" ? dest.login(did, kind, i.id).id : null;
    }
    this.note(`${did} migrated from ${from.name} to ${to}${drop.length ? `, dropping ${drop.length} device record(s)` : ""}`);
    this.settle();
  }

  /** Roll `victim` back: serve it `did`'s repo as of `back` commits ago. */
  rollback(did: Did, victim: Installation, back: number): void {
    const pds = this.pdsOf.get(did)!;
    const rev = Math.max(1, pds.repo(did).rev - back);
    this.adversary.add({ kind: "withhold", did, observers: [victim.id], rev, describe: `${pds.name} serves ${victim.id} ${did}'s repo at revision ${rev}` });
    this.note(`${pds.name} rolls ${victim.id} back to ${did}@${rev}`);
    this.settle();
  }

  /** Move an installation's clock. Forward jumps while it is not running
   * shorten its holds, which NBD's goals exclude; scenarios and the walker
   * move clocks backward or set distinct clock domains. */
  skew(inst: Installation, hours: number): void {
    inst.clockOffset += hours;
    this.trace?.push({ op: "skew", who: inst.binding.device.deviceId, h: hours });
    this.note(`${inst.id}'s clock moved ${hours}h`);
    this.settle();
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
    this.provenance.attacker.add(inst.binding.device.deviceId);
    this.published(inst.binding.device.deviceId);
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
    this.trace?.push({ op: "approve", s: tb(signer.binding), t: tb(target.binding) });
    this.provenance.approvals.push({ signer: signer.deviceId, target: target.binding.device.deviceId, at: this.t, compromised: true, standing: this.standing(target.did) });
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
    this.trace?.push({ op: "wait", h: hours });
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

  /** Every device binding ever published, in order of first appearance. */
  allBindings(): Binding[] {
    const out = new Map<string, Binding>();
    for (const pds of this.pdses.values())
      for (const repo of pds.repos.values()) {
        if (repo.name.includes("|")) continue;
        for (const snap of repo.history)
          for (const [k, v] of snap.records)
            if (k.startsWith(COL.device + "/")) {
              const b = (v as { value: Binding }).value;
              out.set(`${b.account}/${b.device.deviceId}/${ref(asCbor(b))}`, b);
            }
      }
    return [...out.values()];
  }

  note(text: string): void {
    this.log.push({ at: this.t, text });
  }
}
