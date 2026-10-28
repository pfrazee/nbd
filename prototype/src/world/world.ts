// The emulated world: PDSes, the Spaces host, a DID registry, a virtual
// clock, and every installation. It implements the installations' Network
// and offers the user-level actions scenarios and the UI drive.

import { type Cbor, ref } from "../protocol/encoding";
import { type KeyPair, Rng, sign } from "../protocol/crypto";
import { Installation, type InstallationState, type InviteEvent, type Network } from "../protocol/installation";
import type { RecordPath, Snapshot, WriteOp } from "../protocol/repo";
import { approvalPayload } from "../protocol/trust";
import { type Approval, type Binding, COL, type Did, type Invite, type Policy, asCbor, label } from "../protocol/types";
import type { HistoryResponse, WitnessApi } from "../protocol/witness";
import { Adversary } from "./adversary";
import { Host } from "./host";
import { Pds, type Session, revAt } from "./pds";
import { Relay, RogueWitness, Witness } from "./relay";

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
  authorizes: TraceBinding[]; pending: boolean; captures: boolean; published: boolean;
};

/** Ground truth about one published invite record. `firstMet`: the inviting
 * installation had no pin for the account when it made the record; `devices`
 * are the device IDs it first met through this record (newly vouched);
 * `authorizes`: the device IDs the record authorizes in its space; `admits`:
 * the account was not a member of the space when it was published; `seq`:
 * when the record was made, `publishedSeq` when it was published;
 * `captures`: the rkey of the pending record a capture completes. */
export type InviteFact = {
  space: string; inviter: Did; device: string; account: Did; firstMet: boolean; devices: string[]; authorizes: string[];
  admits: boolean; pending: boolean; rkey: string; captures: string | null; at: number; seq: number; publishedSeq: number;
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
  /** Every invite or capture record made, published or not: who made it,
   * whether it first met the account, and the device IDs it vouched for. */
  prepared: { inviter: Did; device: string; account: Did; space: string; rkey: string; firstMet: boolean; devices: string[]; seq: number }[];
  /** Every binding of another account an installation newly accepted:
   * when, through what, and (witness policy) the revision of the witnessed
   * commit it relied on and the witness that reported it. */
  accepts: { inst: string; device: string; account: Did; target: string; world: number; order: number; rev: number | null; via: string; witness: string | null }[];
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
  readonly backups: { name: string; from: string; at: number; state: InstallationState; origin: { at: number; order: number } }[] = [];
  /** Write faults per installation: "reject" fails before applying; "lost-ack"
   * applies the write, then fails as a lost acknowledgement would. */
  readonly faults = new Map<string, { mode: "reject" | "lost-ack"; collection?: string; count: number }>();
  readonly provenance: Provenance = { attacker: new Set(), stolenAt: new Map(), publishedAt: new Map(), publishedSeq: new Map(), approvals: [], invites: [], prepared: [], accepts: [] };
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

  /** The grant rule every installation follows; set at creation. The
   * default is the specified rule (inviters); "baseline" is the rule before
   * it, kept for comparison and for the model's SpecClient traces. */
  readonly policy: Policy;

  /** Witness policy: the reference relay and each application's witness. */
  readonly relay: Relay | null;
  readonly witnesses = new Map<string, Witness>();
  private rogues = new Map<string, RogueWitness>();

  constructor(seed = "nbd", opts: { policy?: Policy } = {}) {
    this.rng = Rng.fromLabel(seed);
    this.policy = opts.policy ?? "inviters";
    this.relay = this.policy === "witness" ? new Relay((did) => this.registry.get(did) ?? null, () => this.t) : null;
    if (this.relay) for (const app of ["lantern", "other", "attacker"]) this.witnessOf(app);
  }

  // ---- witness policy -----------------------------------------------------------

  /** The witness of application `app` (created on first use). */
  witnessOf(app: string): Witness {
    let w = this.witnesses.get(app);
    if (!w) {
      if (!this.relay) throw new Error("world: no relay outside the witness policy");
      w = new Witness(`witness.${app}`, app, this.relay, (id, did) => this.pdsOf.get(did)?.serveFetch(id, did) ?? null, () => this.t);
      // Witnesses in this world have followed the relay from its start.
      this.witnesses.set(app, w);
    }
    return w;
  }

  /** A new application whose witness starts following the relay now: it
   * holds no history from before, which it reports as a gap. */
  lateWitness(app: string): Witness {
    if (!this.relay) throw new Error("world: no relay outside the witness policy");
    if (this.witnesses.has(app)) throw new Error(`world: ${app} already has a witness`);
    this.relay.ingest();
    const w = new Witness(`witness.${app}`, app, this.relay, (id, did) => this.pdsOf.get(did)?.serveFetch(id, did) ?? null, () => this.t, { late: true });
    this.witnesses.set(app, w);
    this.note(`${w.id} starts following the relay at seq ${w.cursor}`);
    return w;
  }

  /** Application `app`'s witness loses its state and is rebuilt: it starts
   * following the relay again now, holding no history from before, which it
   * reports as a gap. Its operating conditions carry over; its subscription
   * is open. */
  rebuildWitness(app: string): Witness {
    if (!this.relay) throw new Error("world: no relay outside the witness policy");
    const old = this.witnessOf(app);
    this.relay.ingest();
    const w = new Witness(old.id, app, this.relay, (id, did) => this.pdsOf.get(did)?.serveFetch(id, did) ?? null, () => this.t, { late: true });
    w.clockOffset = old.clockOffset;
    w.reachable = old.reachable;
    w.lag = old.lag;
    w.pageSize = old.pageSize;
    this.witnesses.set(app, w);
    this.note(`${w.id} is rebuilt, following the relay again from seq ${w.cursor}`);
    this.settle();
    return w;
  }

  witness(observer: string): WitnessApi | null {
    const inst = this.installations.get(observer);
    if (!inst || !this.relay) return null;
    const w = this.witnessOf(inst.app);
    if (!w.reachable) return null;
    const d = this.transit.get(observer) ?? 0;
    if (!d) return w;
    // Answers delayed in transit: each computed when its request arrives
    // and delivered `d` hours later, whichever request the client is on.
    return {
      id: w.id,
      history: (o, did, from, limit, req) => {
        const slot = `${o} ${did}`;
        const q = this.answers.get(slot) ?? [];
        this.answers.set(slot, q);
        if (!q.some((x) => x.req === req)) q.push({ req, at: this.t + d, r: w.history(o, did, from, limit, req) });
        const i = q.findIndex((x) => x.at <= this.t + 1e-9);
        return i < 0 ? null : q.splice(i, 1)[0].r;
      },
      commitAt: (o, did, rev) => w.commitAt(o, did, rev),
      latest: (o, did) => w.latest(o, did),
    };
  }

  /** Hours each witness answer to an installation spends in transit. */
  private readonly transit = new Map<string, number>();
  /** Answers in transit, by installation and account. They survive the
   * installation restarting, which must discard them. */
  private readonly answers = new Map<string, { req: string | undefined; at: number; r: HistoryResponse }[]>();

  /** Witness answers to `inst` spend `hours` in transit: each is computed
   * when its request arrives and delivered that much later. */
  witnessTransit(inst: Installation, hours: number): void {
    if (hours > 0) this.transit.set(inst.id, hours);
    else this.transit.delete(inst.id);
    this.note(`witness answers to ${inst.id} now spend ${hours}h in transit`);
    this.settle();
  }

  otherWitnesses(observer: string): WitnessApi[] {
    const inst = this.installations.get(observer);
    const out: WitnessApi[] = [...this.witnesses.values()].filter((w) => w.app !== inst?.app && w.reachable);
    for (const p of this.pdses.values()) {
      let r = this.rogues.get(p.name);
      if (!r) this.rogues.set(p.name, (r = new RogueWitness(`witness.${p.name}`, (o, did) => this.pdsOf.get(did) === p ? p.enumerate(o, did) : null)));
      out.push(r);
    }
    return out;
  }

  accepted(by: Installation, b: Binding, rev: number | null, via: string): void {
    this.provenance.accepts.push({
      inst: by.id, device: by.binding.device.deviceId, account: b.account, target: b.device.deviceId, world: this.t, order: this.tick(), rev, via,
      witness: rev === null || !this.relay ? null : this.witnessOf(by.app).id,
    });
  }

  /** Move relay events to the witnesses. Returns whether anything moved. */
  private pumpRelay(): boolean {
    if (!this.relay) return false;
    let n = this.relay.ingest();
    for (const inst of this.installations.values()) this.witnessOf(inst.app);
    for (const w of this.witnesses.values()) n += w.pump();
    return n > 0;
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

  invitePrepared(by: Binding, rkey: string, record: Invite, firstMet: boolean, vouched: Binding[]): void {
    if (this.invitesMade.has(rkey)) return;
    const seq = this.tick();
    this.invitesMade.set(rkey, seq);
    this.provenance.prepared.push({
      inviter: by.account, device: by.device.deviceId, account: record.account, space: record.space, rkey, firstMet,
      devices: vouched.map((b) => b.device.deviceId), seq,
    });
  }

  /** Called before a published record admits its account. */
  invited(e: InviteEvent): void {
    const r = e.record;
    const op: InviteOp = {
      op: "invite", by: tb(e.by), space: e.space, account: r.account.replace("did:plc:", ""), bindings: r.bindings.map(tb),
      authorizes: r.authorizes.map(tb), pending: r.pending, captures: r.captures !== null, published: e.published,
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
      devices: e.vouched.map((b) => b.device.deviceId), authorizes: r.authorizes.map((b) => b.device.deviceId), admits, pending: r.pending, rkey: e.rkey, captures: r.captures,
      at: this.t, seq: this.invitesMade.get(e.rkey) ?? this.tick(), publishedSeq: this.tick(),
    });
    this.note(`${label(e.by)} ${what} ${r.account} to ${this.host.spaceName(e.space)}${r.authorizes.length ? `, authorizing ${r.authorizes.length} device(s)` : ""}`);
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
      p = new Pds(name, this.rng.derive(`pds/${name}`), () => this.t, { timestampRevs: this.policy === "witness" });
      p.relay = this.relay;
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
  install(did: Did, deviceName: string, opts: { link?: Installation; clockOffset?: number; keys?: StolenKeys; startOver?: boolean; app?: string } = {}): Installation {
    const id = `${did.replace("did:plc:", "")}/${deviceName}`;
    const inst = new Installation(this, id, deviceName, did, this.rng.derive(`install/${id}/${++this.counter}`), opts.clockOffset ?? 0, opts.keys);
    inst.app = opts.app ?? opts.link?.app ?? "lantern";
    inst.sessionId = this.pdsOf.get(did)!.login(did, "app", id).id;
    inst.originOrder = Math.min(inst.originOrder, this.tick());
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
    inst.app = "attacker"; // attacker code trusts the attacker's own witness
    inst.originOrder = Math.min(inst.originOrder, this.tick());
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
    inst.app = "attacker"; // attacker code trusts the attacker's own witness
    inst.originOrder = Math.min(inst.originOrder, this.tick());
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
    inst.app = "attacker"; // attacker code trusts the attacker's own witness
    inst.originOrder = Math.min(inst.originOrder, this.tick());
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

  // ---- malicious PDS against the relay, and witness conditions (witness policy) ----

  /** `records` with every device and approval record replaced by `sub`'s. */
  private substituted(records: Map<RecordPath, Cbor>, sub: Installation): Map<RecordPath, Cbor> {
    const record = sub.deviceRecord() as { collection: string; rkey: string; value: Cbor };
    const out = new Map<RecordPath, Cbor>();
    for (const [k, v] of records) if (!k.startsWith(COL.device + "/") && !k.startsWith(COL.approval + "/")) out.set(k, v);
    out.set(`${record.collection}/${record.rkey}`, record.value);
    return out;
  }

  /** The PDS sends the relay a fork of `did`'s repo in which every device is
   * replaced by one it controls, and serves the same fork to `showTo` (and
   * the impostor), while serving everyone else, including the account's own
   * installations, the real repo. Without a relay (non-witness policies) the
   * served fork is all there is, as in substituteDevices. */
  forkedImpostor(did: Did, showTo: Installation[], deviceName = "impostor"): Installation {
    const pds = this.pdsOf.get(did)!;
    const sub = this.pdsDevice(did, deviceName);
    const transform = (records: Map<RecordPath, Cbor>) => this.substituted(records, sub);
    if (this.relay) pds.relayHooks.push((d, records) => (d === did ? { records: transform(records) } : null));
    this.adversary.add({ kind: "forge", did, observers: [...showTo.map((i) => i.id), sub.id], revOffset: 0, describe: `${pds.name} shows ${showTo.map((i) => i.id).join(", ")} a fork of ${did} with ${sub.id}`, transform });
    pds.repo(did).commit(); // carries the fork to the relay
    this.note(`${pds.name} forks ${did}: ${this.relay ? "the relay and " : ""}${showTo.map((i) => i.id).join(", ")} see ${sub.id} as its only device; its own devices see the real repo`);
    this.settle();
    return sub;
  }

  private syncRoots = new Map<Did, { honest: Map<RecordPath, Cbor>; rev: number; withhold: number; fetch: (w: string, r: import("./pds").Repo) => Snapshot | null | undefined }>();

  /** Publish a `#sync` root in which every device of `did` is replaced by an
   * impostor, hiding the commit from the account's own installations. Only
   * witnesses in `serveTo` are served that root when they fetch it; any
   * other witness is served the replacement (the honest records, signed at
   * the next revision), which the PDS publishes with replaceSyncRoot. */
  publishSyncRoot(did: Did, serveTo: string[], deviceName = "impostor", settle = true): Installation {
    const pds = this.pdsOf.get(did)!;
    const repo = pds.repo(did);
    const own = [...this.installations.values()].filter((i) => i.did === did).map((i) => i.id);
    const withhold = this.adversary.add({ kind: "withhold", did, observers: own, rev: repo.rev, describe: `${pds.name} hides ${did}'s #sync root from its own devices` }).id;
    const sub = this.pdsDevice(did, deviceName);
    const honest = new Map(repo.records);
    repo.records = this.substituted(honest, sub);
    let once = true;
    const kind = (d: Did) => (d === did && once ? { kind: "sync" as const } : null);
    pds.relayHooks.push(kind);
    const r1 = repo.commit();
    once = false;
    const replacement = repo.sign(honest, r1.commit.rev + 1);
    const fetch = (w: string, r: import("./pds").Repo) => {
      if (r.did !== did || r.rev !== r1.commit.rev) return undefined;
      return serveTo.includes(w) || w === this.witnessOf("attacker").id ? r1 : replacement;
    };
    pds.fetchHooks.push(fetch);
    this.syncRoots.set(did, { honest, rev: r1.commit.rev + 1, withhold, fetch });
    this.note(`${pds.name} published a #sync root of ${did} with ${sub.id}, served only to ${serveTo.join(", ") || "no witness"}`);
    if (settle) this.settle();
    return sub;
  }

  /** Publish the replacement root (a `#sync` with the honest records). */
  replaceSyncRoot(did: Did, settle = true): void {
    const pds = this.pdsOf.get(did)!;
    const s = this.syncRoots.get(did);
    if (!s) return;
    this.syncRoots.delete(did);
    const repo = pds.repo(did);
    repo.records = new Map(s.honest);
    let once = true;
    pds.relayHooks.push((d) => (d === did && once ? { kind: "sync" as const } : null));
    repo.commit();
    once = false;
    pds.fetchHooks.splice(pds.fetchHooks.indexOf(s.fetch), 1);
    this.adversary.remove(s.withhold);
    this.note(`${pds.name} replaced ${did}'s #sync root`);
    if (settle) this.settle();
  }

  /** Publish a `#sync` root with an impostor and replace it before any
   * witness fetches it. */
  syncReplaced(did: Did, deviceName = "impostor"): Installation {
    const sub = this.publishSyncRoot(did, [], deviceName, false);
    this.replaceSyncRoot(did, false);
    this.settle();
    return sub;
  }

  /** The PDS withholds `did`'s repo from one witness's fetches. Returns a
   * function that stops it. */
  withholdFetch(did: Did, app: string): () => void {
    const pds = this.pdsOf.get(did)!;
    const id = this.witnessOf(app).id;
    const hook = (w: string, r: import("./pds").Repo) => (r.did === did && w === id ? null : undefined);
    pds.fetchHooks.push(hook);
    this.note(`${pds.name} withholds ${did}'s repo from ${id}`);
    return () => {
      const i = pds.fetchHooks.indexOf(hook);
      if (i >= 0) pds.fetchHooks.splice(i, 1);
    };
  }

  /** The PDS commits a commit that it never sends the relay, replacing
   * every device of `did` with an impostor, and serves it to `showTo`. */
  unrelayedImpostor(did: Did, showTo: Installation[], deviceName = "impostor"): Installation {
    const pds = this.pdsOf.get(did)!;
    const repo = pds.repo(did);
    const sub = this.pdsDevice(did, deviceName);
    const others = [...this.installations.values()].filter((i) => i.did === did && i !== sub && !showTo.includes(i)).map((i) => i.id);
    this.adversary.add({ kind: "withhold", did, observers: others, rev: repo.rev, describe: `${pds.name} hides an unrelayed commit of ${did}` });
    const honest = new Map(repo.records);
    let once = true;
    if (this.relay) pds.relayHooks.push((d) => (d === did && once ? { drop: true } : null));
    repo.records = this.substituted(honest, sub);
    repo.commit();
    once = false;
    this.note(`${pds.name} signed a commit of ${did} with ${sub.id} and never sent it to the relay; it serves it to ${showTo.map((i) => i.id).join(", ")}`);
    this.settle();
    return sub;
  }

  /** The PDS replaces every device of `did` with an impostor in an ordinary
   * commit, hiding it from the account's own installations; undoFlash
   * removes it again. */
  flashImpostor(did: Did, deviceName = "impostor"): { sub: Installation; undo: () => void } {
    const pds = this.pdsOf.get(did)!;
    const repo = pds.repo(did);
    const own = [...this.installations.values()].filter((i) => i.did === did).map((i) => i.id);
    const withhold = this.adversary.add({ kind: "withhold", did, observers: own, rev: repo.rev, describe: `${pds.name} hides ${did}'s brief impostor from its own devices` }).id;
    const sub = this.pdsDevice(did, deviceName);
    const devices = [...repo.records].filter(([k]) => k.startsWith(COL.device + "/"));
    for (const [k] of devices) this.trace?.push({ op: "delete", b: [did.replace("did:plc:", ""), k.slice(COL.device.length + 1)] });
    this.trace?.push({ op: "add", b: tb(sub.binding) });
    pds.write(sub.sessionId!, [...devices.map(([k]) => ({ action: "delete" as const, collection: COL.device, rkey: k.slice(COL.device.length + 1) })), sub.deviceRecord()]);
    this.note(`${pds.name} replaced ${did}'s devices with ${sub.id}, hidden from its own devices`);
    this.settle();
    const undo = () => {
      this.trace?.push({ op: "delete", b: tb(sub.binding) });
      for (const [k] of devices) this.trace?.push({ op: "add", b: [did.replace("did:plc:", ""), k.slice(COL.device.length + 1)] });
      if (!this.pdsOf.get(did)?.hosts(did) || this.pdsOf.get(did) !== pds) return; // migrated away meanwhile
      pds.write(pds.login(did, "password", `${pds.name} operator`).id, [{ action: "delete", collection: COL.device, rkey: sub.binding.device.deviceId }, ...devices.map(([k, v]) => ({ action: "create" as const, collection: COL.device, rkey: k.slice(COL.device.length + 1), value: v }))]);
      this.adversary.remove(withhold);
      this.note(`${pds.name} deleted ${sub.id} and restored ${did}'s devices`);
      this.settle();
    };
    return { sub, undo };
  }

  /** The PDS replaces every device of `did` with an impostor in one commit
   * at revision `rev`, which it chooses (published only by a relay that
   * doesn't check revisions), hidden from the account's own devices. */
  impostorAtRev(did: Did, rev: number, deviceName = "impostor"): Installation {
    const pds = this.pdsOf.get(did)!;
    const repo = pds.repo(did);
    const own = [...this.installations.values()].filter((i) => i.did === did).map((i) => i.id);
    this.adversary.add({ kind: "withhold", did, observers: own, rev: repo.rev, describe: `${pds.name} hides ${did}'s impostor from its own devices` });
    const sub = this.pdsDevice(did, deviceName);
    for (const k of [...repo.records.keys()]) if (k.startsWith(COL.device + "/")) repo.records.delete(k);
    const op = sub.deviceRecord() as { rkey: string; value: Cbor };
    repo.records.set(`${COL.device}/${op.rkey}`, op.value);
    this.note(`${pds.name} replaces ${did}'s devices with ${sub.id} at revision ${rev}, hidden from its own devices`);
    this.commitAtRev(did, rev);
    return sub;
  }

  /** The PDS serves `observers` its commit of `did` at revision `rev`
   * from now on, whatever it commits later. Returns the policy's id. */
  serveAt(did: Did, rev: number, observers: Installation[]): number {
    const pds = this.pdsOf.get(did)!;
    const id = this.adversary.add({ kind: "withhold", did, observers: observers.map((i) => i.id), rev, describe: `${pds.name} serves ${observers.map((i) => i.id).join(", ")} its commit of ${did} at revision ${rev}` }).id;
    this.note(`${pds.name} serves ${observers.map((i) => i.id).join(", ")} its commit of ${did} at revision ${rev}`);
    this.settle();
    return id;
  }

  /** An honest relay drops `did`'s next `n` commits, as under a rate
   * limit: the PDS sent them, and later commits follow them. */
  relayDrops(did: Did, n = 1): void {
    this.relay!.dropNext(did, n);
    this.note(`the relay will drop ${did}'s next ${n === 1 ? "commit" : `${n} commits`}`);
  }

  /** A relay that checks neither that `did`'s revisions increase nor that
   * they are within REV_ALLOWANCE of its clock (the sync specification asks
   * relays to; this one doesn't). */
  uncheckedRelay(did: Did): void {
    this.relay!.unchecked.add(did);
    this.note(`the relay stops checking ${did}'s revisions`);
  }

  /** `did`'s PDS commits once at revision `rev`, outside its sequence (a
   * clock briefly wrong); its later commits continue the usual sequence. */
  commitAtRev(did: Did, rev: number): void {
    const pds = this.pdsOf.get(did)!;
    pds.repo(did).commitAt(rev);
    this.note(`${pds.name} commits ${did} at revision ${rev}`);
    this.settle();
  }

  /** `did`'s PDS clock is `hours` fast for one commit, which a relay that
   * doesn't check revisions publishes. */
  futureCommit(did: Did, hours: number): number {
    this.uncheckedRelay(did);
    const rev = revAt(this.t + hours);
    this.commitAtRev(did, rev);
    return rev;
  }

  /** Witness conditions: an outage of its relay subscription, clients unable
   * to reach it, or processing hours behind. */
  setWitness(app: string, opts: { connected?: boolean; reachable?: boolean; lag?: number; clockOffset?: number; pageSize?: number }): void {
    const w = this.witnessOf(app);
    if (opts.pageSize !== undefined) w.pageSize = opts.pageSize;
    if (opts.clockOffset !== undefined) w.clockOffset = opts.clockOffset;
    if (opts.connected !== undefined) w.setConnected(opts.connected);
    if (opts.reachable !== undefined) w.reachable = opts.reachable;
    if (opts.lag !== undefined) w.lag = opts.lag;
    this.note(`${w.id}: ${Object.entries(opts).map(([k, v]) => `${k} ${v}`).join(", ")}`);
    this.settle();
  }

  /** An honest relay that delivers to one witness `hours` late while its
   * pings still arrive (a slow consumer). Events keep the time the relay
   * sequenced them, so they arrive old. */
  relayDelay(app: string, hours: number): void {
    this.relay!.deliveryDelay.set(this.witnessOf(app).id, hours);
    this.note(`the relay delivers to ${this.witnessOf(app).id} ${hours}h late`);
    this.settle();
  }

  /** Not the reference relay: one that stamps each event with the time it
   * sends it, so a replay or a slow subscriber's backlog carries fresh times
   * (proposal: Reference relay forbids this). */
  relayTimeOnDelivery(on = true): void {
    this.relay!.timeOnDelivery = on;
    this.note(`the relay ${on ? "stamps events with the time it sends them" : "keeps each event's sequencing time"}`);
    this.settle();
  }

  /** `did`'s PDS rolls its repo back to its commit at revision `rev` and
   * sends the relay that same commit again, as a `#sync`. A relay that
   * checks revisions refuses it; one that doesn't publishes revision `rev`
   * a second time, after whatever came between. */
  replayRevision(did: Did, rev: number): void {
    const pds = this.pdsOf.get(did)!;
    pds.replay(did, rev);
    this.note(`${pds.name} rolls ${did} back to revision ${rev} and sends it to the relay again`);
    this.settle();
  }

  /** Out of reach: a dishonest witness that leaves every relay event for
   * `did` after `afterSeq` out of the history it reports, commits and gaps
   * alike. */
  dishonestWitness(app: string, did: Did, afterSeq: number): void {
    const w = this.witnessOf(app);
    const seqs = w.omits.get(did) ?? new Set<number>();
    for (const e of this.relay!.events) if (e.did === did && e.seq > afterSeq) seqs.add(e.seq);
    w.omits.set(did, seqs);
    this.note(`${w.id} colludes with ${did}'s PDS, omitting its commits after relay seq ${afterSeq}`);
  }

  setLag(inst: Installation, hours: number): void {
    if (hours > 0) this.lag.set(inst.id, hours);
    else this.lag.delete(inst.id);
    this.note(`${inst.id} now sees repos ${hours}h late`);
    this.settle();
  }

  // ---- backups -------------------------------------------------------------------

  backup(inst: Installation, name = `${inst.id} backup`): void {
    this.backups.push({ name, from: inst.id, at: this.t, state: inst.exportState(), origin: { at: inst.origin, order: inst.originOrder } });
    this.note(`${inst.id} backed up`);
  }

  /** `from` is lost; a new installation restores its keys and the backup. */
  restore(from: Installation, backupIndex: number, deviceName = `${from.name}-restored`, opts: { app?: string } = {}): Installation {
    const b = this.backups[backupIndex];
    from.online = false;
    if (from.sessionId) this.pdsOf.get(from.did)!.endSession(from.sessionId);
    this.installations.delete(from.id);
    const id = `${from.did.replace("did:plc:", "")}/${deviceName}`;
    const inst = new Installation(this, id, deviceName, from.did, this.rng.derive(`install/${id}/${++this.counter}`), from.clockOffset,
      { sign: from.signKey, enc: from.encKey, deviceId: from.binding.device.deviceId });
    inst.sessionId = this.pdsOf.get(from.did)!.login(from.did, "app", id).id;
    inst.app = opts.app ?? from.app;
    inst.predecessor = from;
    inst.originOrder = Math.min(inst.originOrder, this.tick());
    this.installations.set(id, inst);
    inst.importState(b.state, b.origin);
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
    if (!online && inst.running) {
      inst.running = false;
      const r = inst.runs[inst.runs.length - 1];
      if (r) r.to = this.t;
    }
    this.note(`${inst.id} went ${online ? "online" : "offline"}`);
    if (online) this.settle();
  }

  advance(hours: number): void {
    this.trace?.push({ op: "wait", h: hours });
    // Under the witness policy running installations check at least hourly
    // (proposal: Liveness and deadline), so time passes in hourly settles.
    if (this.relay)
      for (let left = hours; left > 1e-9; ) {
        const d = Math.min(1, left);
        this.t += d;
        left -= d;
        this.settle();
      }
    else {
      this.t += hours;
      this.settle();
    }
  }

  /** Let every online installation sync until nothing changes. */
  settle(maxRounds = 40): void {
    for (let i = 0; i < maxRounds; i++) {
      let changed = this.pumpRelay();
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
