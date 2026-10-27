// Random walks over a World: user, attacker, network, and malicious-PDS
// actions, with the invariant monitor and extra checks after every step.
// Actions are recorded concretely so a failing walk replays and shrinks.
//
// Shared-view walks restrict themselves to what model/nbd_trust.py can
// express (public-repo writes and elapsed time, no lag or forged views) and
// record a trace of the viewer's trust decisions for model/test_traces.py.
//
// Under the inviters policy (device-enrollment.md#grant-standing) a walk has four accounts
// and two spaces with different admins, adds invites and joins only by
// admitted accounts, and its traces also record invite operations, the
// accounts the viewer tracks, and the viewer's grant standing per space.

import { Rng } from "../protocol/crypto";
import type { Installation } from "../protocol/installation";
import { commitment } from "../protocol/grants";
import { type Binding, COL, type Policy, bindingId, hasStanding } from "../protocol/types";
import type { InviteOp, TraceBinding, TraceOp } from "../world/world";
import { World } from "../world/world";
import { InvariantMonitor } from "./invariants";

export type Action = (string | number | boolean)[];
/** `tracked`, `standing`, and `authorized` (space label -> bindings) only
 * under inviters. */
/** A trace op as fixtures record it: a viewer's resend of its oldest saved
 * invite is `{op: "flush"}`, or `{op: "flush", abandoned: true}` if that
 * invite no longer admitted its account and was dropped unsent. */
export type TraceStepOp = Exclude<TraceOp, { op: "flush" }> | { op: "flush"; abandoned?: true };
export type TraceStep = {
  ops: TraceStepOp[]; accepted: TraceBinding[]; holds: string[]; tracked?: string[]; standing?: Record<string, TraceBinding[]>; authorized?: Record<string, TraceBinding[]>;
  /** Witness policy: the viewer's own-account bindings it has alarmed about. */
  ownAlarms?: TraceBinding[];
};
export type Trace = { seed: string; policy?: Policy; spaces?: string[]; viewer: TraceBinding; actions?: Action[]; steps: TraceStep[] };

const ACCOUNTS = ["alice", "bob", "carol"];
/** Erin starts with an account and no devices, so invites of her are pending. */
const INVITER_ACCOUNTS = ["alice", "bob", "carol", "dave", "erin"];
const NO_DEVICE = "erin";
/** Space labels in inviters traces, in the order of `Walk.spaces`. */
const SPACE_LABELS = ["A", "B"];
const WAITS = [1, 24, 48, 71, 72, 100];
const did = (a: string) => `did:plc:${a}`;
/** Witness policy: Alice and Bob use Lantern; the rest another app. */
const appOf = (d: string) => (d === did("alice") || d === did("bob") ? "lantern" : "other");

export class Walk {
  readonly world: World;
  readonly monitor: InvariantMonitor;
  readonly space: string;
  readonly spaces: string[];
  readonly viewer: Installation;
  readonly trace: Trace | null;
  readonly accounts: string[];
  private names = 0;

  constructor(readonly seed: string, readonly shared: boolean, readonly policy: Policy = "inviters") {
    const w = (this.world = new World(seed, { policy }));
    if (shared) w.trace = [];
    const inviters = hasStanding(policy);
    this.accounts = inviters ? INVITER_ACCOUNTS : ACCOUNTS;
    const dids = this.accounts.map((a) => w.account(a, a === "alice" ? "pds.example" : `pds.${a}.example`));
    const phones = dids.filter((d) => d !== did(NO_DEVICE)).map((d) => w.install(d, "phone", { app: appOf(d) }));
    this.viewer = phones[0];
    if (inviters) {
      // Alice and Bob share Club; Carol and Dave share Garden. Alice starts
      // out never having met Carol or Dave, so invites can vouch.
      this.space = phones[0].createSpace("Club");
      phones[0].invite(this.space, phones[1].did);
      phones[1].join(this.space);
      const garden = phones[2].createSpace("Garden");
      phones[2].invite(garden, phones[3].did);
      phones[3].join(garden);
      this.spaces = [this.space, garden];
    } else {
      this.space = phones[0].createSpace("Club");
      for (const p of phones.slice(1)) phones[0].invite(this.space, p.did);
      for (const p of phones) p.join(this.space);
      // A second space with fewer members, so trust reuse across spaces is exercised.
      const garden = phones[0].createSpace("Garden");
      phones[0].invite(garden, phones[1].did);
      phones[1].join(garden);
      this.spaces = [this.space, garden];
    }
    w.settle();
    this.monitor = new InvariantMonitor(w);
    this.trace = shared ? { seed, ...(inviters ? { policy, spaces: SPACE_LABELS } : {}), viewer: [this.viewer.did.slice(8), this.viewer.binding.device.deviceId], steps: [] } : null;
    if (shared) this.record();
  }

  private insts(): Installation[] {
    return [...this.world.installations.values()];
  }

  private name(): string {
    return `d${++this.names}`;
  }

  gen(rng: Rng): Action {
    const w = this.world;
    const insts = this.insts();
    const pick = <T>(xs: T[]): T => xs[rng.int(xs.length)];
    const acct = pick(this.accounts);
    const kinds: [string, number][] = [
      ["link", 4], ["install", 1], ["remove", 3], ["removeQuiet", 1], ["wait", 3], ["join", 2], ["post", 2],
      ["takeover", 1], ["steal", 1], ["approve", 2], ["recreate", 2], ["attackerAdd", 1], ["skew", 1],
      ["forget", 1], ["fault", 1], ["rotate", 1],
    ];
    if (hasStanding(this.policy)) kinds.push(["invite", 3], ["faultInvite", 2]);
    if (this.policy === "witness") {
      // Malicious PDSes against the relay, and witness conditions. The
      // shared view keeps to public-repo writes (a brief impostor is one).
      kinds.push(["flash", 2], ["unflash", 2]);
      if (!this.shared)
        kinds.push(["wfork", 1], ["unrelayed", 1], ["syncReplaced", 1], ["syncRoot", 1], ["replaceRoot", 1], ["withholdFetch", 1],
          ["witnessConn", 1], ["witnessReach", 1], ["witnessLag", 1]);
    }
    if (!this.shared)
      kinds.push(["online", 2], ["lag", 2], ["sub", 1], ["hreset", 1], ["fork", 1], ["rollback", 1], ["stop", 1], ["backup", 1], ["restore", 1], ["member", 1],
        ["tamper", 1], ["migrate", 1]);
    const total = kinds.reduce((s, [, n]) => s + n, 0);
    let r = rng.int(total);
    let kind = kinds[0][0];
    for (const [k, n] of kinds) if ((r -= n) < 0) { kind = k; break; }
    const live = insts.filter((i) => i.online && i.trust.isAccepted(i.binding));
    switch (kind) {
      case "link":
        return live.length ? ["link", pick(live).id, this.name()] : ["wait", 1];
      case "install":
        return ["install", acct, this.name()];
      case "remove":
      case "removeQuiet":
        return insts.length ? [kind, pick(insts).id] : ["wait", 1];
      case "join": {
        const s = rng.int(this.spaces.length);
        const admitted = (i: Installation) => !hasStanding(this.policy) || !!w.host.membership(this.spaces[s], i.did)?.eligible;
        const out = insts.filter((i) => !i.spaces.has(this.spaces[s]) && admitted(i));
        return out.length ? ["join", pick(out).id, s] : ["post", pick(insts).id, s];
      }
      case "post":
        return ["post", pick(insts).id, rng.int(this.spaces.length)];
      case "invite": {
        // The space's admin account invites from an installation in the space.
        // In shared walks an own-account inviter is one the viewer accepted,
        // so the model's replay may take every record from the viewer's
        // account as valid.
        const s = rng.int(this.spaces.length);
        const admin = w.host.admin(this.spaces[s]);
        const by = insts.filter((i) => i.did === admin && i.spaces.has(this.spaces[s])
          && (!this.shared || i.did !== this.viewer.did || this.viewer.trust.state.accepted.has(bindingId(i.binding))));
        const to = this.accounts.filter((a) => did(a) !== admin && !w.host.membership(this.spaces[s], did(a))?.eligible);
        return by.length && to.length ? ["invite", pick(by).id, s, pick(to)] : ["wait", 1];
      }
      case "faultInvite": {
        // Invite publication fails, so invites are saved and resent.
        const admins = insts.filter((i) => this.spaces.some((s) => w.host.admin(s) === i.did));
        return admins.length ? ["fault", pick(admins).id, pick(["reject", "lost-ack"]), 1 + rng.int(3), COL.invite] : ["wait", 1];
      }
      case "forget":
        return ["forget", pick(insts).id, rng.int(this.spaces.length)];
      case "fault":
        return ["fault", pick(insts).id, pick(["reject", "lost-ack"]), 1 + rng.int(3), pick(["com.example.nbd.grant", "com.example.nbd.evidence", "com.example.nbd.keyRequest", ""])];
      case "rotate":
        return ["rotate", acct];
      case "tamper":
        return ["tamper", rng.int(this.spaces.length)];
      case "migrate": {
        const present = [...w.pdsOf.get(did(acct))!.repo(did(acct)).records.keys()].filter((k) => k.startsWith("com.example.nbd.device/"));
        const drop = rng.int(2) === 0 && present.length ? pick(present).split("/")[1] : "";
        return ["migrate", acct, `pds.m${this.name()}.example`, drop];
      }
      case "takeover":
        return ["takeover", acct, `attacker${this.name()}`];
      case "steal":
        return ["steal", pick(insts).id];
      case "approve": {
        if (!w.stolen.length) return ["steal", pick(insts).id];
        const k = rng.int(w.stolen.length);
        const targets = insts.filter((i) => i.did === w.stolen[k].binding.account && i.binding.device.deviceId !== w.stolen[k].deviceId);
        return targets.length ? ["approve", k, pick(targets).id] : ["wait", 1];
      }
      case "recreate": {
        // A removed device, or someone with the password, republishes its record.
        const gone = insts.filter((i) => !w.pdsOf.get(i.did)!.repo(i.did).records.has(`com.example.nbd.device/${i.binding.device.deviceId}`));
        return gone.length ? ["recreate", pick(gone).id] : ["wait", 1];
      }
      case "attackerAdd":
        return ["attackerAdd", acct, `x${this.name()}`];
      case "skew":
        // Clocks only move backward: a forward jump while not running
        // shortens holds, which the goals exclude.
        return ["skew", pick(insts).id, -pick([1, 24, 72])];
      case "rollback":
        return ["rollback", acct, pick(insts).id, 1 + rng.int(3)];
      case "online": {
        const i = pick(insts);
        return ["online", i.id, !i.online];
      }
      case "lag":
        return ["lag", pick(insts).id, pick([0, 1, 6, 24])];
      case "sub": {
        const victims = insts.filter((i) => i.did !== did(acct));
        return victims.length ? ["sub", acct, pick(victims).id, `sub${this.name()}`] : ["wait", 1];
      }
      case "hreset":
        return ["hreset", acct, `pds${this.name()}`];
      case "fork":
        return ["fork", pick(insts).id, pick(insts).id];
      case "stop":
        return w.adversary.policies.length ? ["stop", rng.int(w.adversary.policies.length)] : ["wait", 1];
      case "backup":
        return ["backup", pick(insts).id];
      case "restore":
        return w.backups.length ? ["restore", rng.int(w.backups.length)] : ["backup", pick(insts).id];
      case "member":
        return ["member", acct, rng.int(2) === 0];
      case "flash":
        return ["flash", acct, `f${this.name()}`];
      case "unflash":
        return this.flashes.length ? ["unflash", rng.int(this.flashes.length)] : ["wait", 1];
      case "wfork": {
        const victims = insts.filter((i) => i.did !== did(acct));
        return victims.length ? ["wfork", acct, pick(victims).id, `wf${this.name()}`] : ["wait", 1];
      }
      case "unrelayed": {
        const victims = insts.filter((i) => i.did !== did(acct));
        return victims.length ? ["unrelayed", acct, pick(victims).id, `ur${this.name()}`] : ["wait", 1];
      }
      case "syncReplaced":
        return ["syncReplaced", acct, `sr${this.name()}`];
      case "syncRoot":
        return ["syncRoot", acct, pick(["", "witness.lantern", "witness.other"]), `sy${this.name()}`];
      case "replaceRoot":
        return ["replaceRoot", acct];
      case "withholdFetch":
        return ["withholdFetch", acct, pick(["lantern", "other"])];
      case "witnessConn":
        return ["witnessConn", pick(["lantern", "other"]), rng.int(2) === 0];
      case "witnessReach":
        return ["witnessReach", pick(["lantern", "other"]), rng.int(2) === 0];
      case "witnessLag":
        return ["witnessLag", pick(["lantern", "other"]), pick([0, 1, 6, 30])];
      default:
        return ["wait", pick(WAITS)];
    }
  }

  /** Apply an action; references that no longer resolve make it a no-op. */
  apply(a: Action): void {
    const w = this.world;
    const inst = (id: unknown) => w.installations.get(String(id));
    const [kind] = a;
    if (kind === "wait") w.advance(Number(a[1]));
    else if (kind === "link") {
      const f = inst(a[1]);
      if (f) { try { w.install(f.did, String(a[2]), { link: f }); } catch (e) { if (!/could not publish/.test((e as Error).message)) throw e; } }
    }
    else if (kind === "install") w.install(did(String(a[1])), String(a[2]));
    else if (kind === "remove" || kind === "removeQuiet") { const i = inst(a[1]); if (i) w.removeDevice(i, { endSession: kind === "remove" }); }
    else if (kind === "join") { const i = inst(a[1]); if (i) { i.join(this.spaces[Number(a[2] ?? 0)]); w.settle(); } }
    else if (kind === "invite") { const i = inst(a[1]); if (i) { i.invite(this.spaces[Number(a[2])], did(String(a[3]))); w.settle(); } }
    else if (kind === "post") { const s = this.spaces[Number(a[2] ?? 0)]; const i = inst(a[1]); if (i?.spaces.has(s)) { i.post(s, `m${w.t}`); w.settle(); } }
    else if (kind === "forget") { const i = inst(a[1]); if (i) { i.forgetKey(this.spaces[Number(a[2])]); w.settle(); } }
    else if (kind === "fault") { const i = inst(a[1]); if (i) w.fault(i, a[2] as "reject" | "lost-ack", Number(a[3]), String(a[4]) || undefined); }
    else if (kind === "rotate") w.rotateRepoKey(did(String(a[1])));
    else if (kind === "tamper") { const s = this.spaces[Number(a[1])]; w.host.tamper(s, { commitment: new Uint8Array(32) }); w.settle(); }
    else if (kind === "migrate") w.migrate(did(String(a[1])), String(a[2]), a[3] ? [String(a[3])] : []);
    else if (kind === "takeover") w.takeover(did(String(a[1])), String(a[2]));
    else if (kind === "steal") { const i = inst(a[1]); if (i) w.stealKeys(i); }
    else if (kind === "approve") { const k = w.stolen[Number(a[1])]; const t = inst(a[2]); if (k && t?.sessionId) { try { w.approveWith(k, t, t.sessionId); } catch { /* session ended */ } } }
    else if (kind === "recreate") { const i = inst(a[1]); if (i) w.recreateRecord(i); }
    else if (kind === "attackerAdd") w.attackerDevice(did(String(a[1])), String(a[2]));
    else if (kind === "skew") { const i = inst(a[1]); if (i) w.skew(i, Number(a[2])); }
    else if (kind === "rollback") { const v = inst(a[2]); if (v) w.rollback(did(String(a[1])), v, Number(a[3])); }
    else if (kind === "online") { const i = inst(a[1]); if (i) w.setOnline(i, Boolean(a[2])); }
    else if (kind === "lag") { const i = inst(a[1]); if (i) w.setLag(i, Number(a[2])); }
    else if (kind === "sub") { const v = inst(a[2]); if (v) w.substituteDevices(did(String(a[1])), v, String(a[3])); }
    else if (kind === "hreset") w.hiddenReset(did(String(a[1])), String(a[2]));
    else if (kind === "fork") { const t = inst(a[1]); const v = inst(a[2]); if (t && v) w.hideDeviceFrom(t.binding, v); }
    else if (kind === "stop") { const p = w.adversary.policies[Number(a[1])]; if (p) { w.adversary.remove(p.id); w.settle(); } }
    else if (kind === "backup") { const i = inst(a[1]); if (i) w.backup(i); }
    else if (kind === "restore") { const b = w.backups[Number(a[1])]; const f = b && inst(b.from); if (f) w.restore(f, Number(a[1])); }
    else if (kind === "member") { w.host.setMembership(w.host.admin(this.space), this.space, did(String(a[1])), Boolean(a[2])); w.settle(); }
    else if (kind === "flash") this.flashes.push(w.flashImpostor(did(String(a[1])), String(a[2])).undo);
    else if (kind === "unflash") { const u = this.flashes.splice(Number(a[1]), 1)[0]; u?.(); }
    else if (kind === "wfork") { const v = inst(a[2]); if (v) w.forkedImpostor(did(String(a[1])), [v], String(a[3])); }
    else if (kind === "unrelayed") { const v = inst(a[2]); if (v) w.unrelayedImpostor(did(String(a[1])), [v], String(a[3])); }
    else if (kind === "syncReplaced") w.syncReplaced(did(String(a[1])), String(a[2]));
    else if (kind === "syncRoot") w.publishSyncRoot(did(String(a[1])), a[2] ? [String(a[2])] : [], String(a[3]));
    else if (kind === "replaceRoot") w.replaceSyncRoot(did(String(a[1])));
    else if (kind === "withholdFetch") this.withheld.push(w.withholdFetch(did(String(a[1])), String(a[2])));
    else if (kind === "witnessConn") w.setWitness(String(a[1]), { connected: Boolean(a[2]) });
    else if (kind === "witnessReach") w.setWitness(String(a[1]), { reachable: Boolean(a[2]) });
    else if (kind === "witnessLag") w.setWitness(String(a[1]), { lag: Number(a[2]) });
  }

  /** Undo functions of brief impostors still published. */
  private flashes: (() => void)[] = [];
  private withheld: (() => void)[] = [];

  /** Apply one action and return the first problem it reveals. */
  step(a: Action): string | null {
    this.monitor.before();
    try {
      this.apply(a);
    } catch (e) {
      return `exception: ${(e as Error).message}`;
    }
    const v = this.monitor.after();
    if (v.length) return v[0];
    for (const i of this.world.installations.values())
      for (const s of this.spaces) {
        const sp = i.spaces.get(s);
        const cfg = sp?.host.config;
        if (sp?.key && cfg && bindingId(i.binding) && !eq(commitment(s, cfg.keyId, sp.key), cfg.commitment))
          return `${i.id} holds a key that does not match the commitment`;
      }
    if (this.shared) this.record();
    return null;
  }

  private lastRecords = new Map<string, Map<string, unknown>>();

  /** Public-repo operations since the last step, from what the repos now
   * hold rather than from what actions intended, so faults cannot skew the
   * trace. Deletions, then approvals, then additions; order within a step
   * does not matter to the model, which only judges the end of each step. */
  private repoOps(): TraceOp[] {
    const del: TraceOp[] = [];
    const appr: TraceOp[] = [];
    const add: TraceOp[] = [];
    for (const a of this.accounts) {
      const recs = new Map<string, unknown>(this.world.pdsOf.get(did(a))!.repo(did(a)).records);
      const prev = this.lastRecords.get(a) ?? new Map<string, unknown>();
      const tbOf = (v: unknown): TraceBinding => { const b = (v as { value: Binding }).value; return [a, b.device.deviceId]; };
      for (const [k, v] of prev) if (k.startsWith(COL.device + "/") && !recs.has(k)) del.push({ op: "delete", b: tbOf(v) });
      for (const [k, v] of recs) {
        if (prev.has(k)) continue;
        if (k.startsWith(COL.device + "/")) add.push({ op: "add", b: tbOf(v) });
        else if (k.startsWith(COL.approval + "/")) {
          const ap = (v as { value: { signer: Binding; target: Binding } }).value;
          appr.push({ op: "approve", s: [a, ap.signer.device.deviceId], t: [a, ap.target.device.deviceId] });
        }
      }
      this.lastRecords.set(a, recs);
    }
    return [...del, ...appr, ...add];
  }

  private record(): void {
    const w = this.world;
    // Repo operations, then invites, resends, and time in the order they
    // happened. The viewer's invite attempts appear whether or not they
    // published, and its resends as flush ops; other devices' records appear
    // once published.
    const v = this.viewer.binding.device.deviceId;
    const labelled = (o: InviteOp): InviteOp => ({ ...o, space: SPACE_LABELS[this.spaces.indexOf(o.space)] });
    const timed = w.trace!.splice(0).flatMap((o): TraceStepOp[] => {
      if (o.op === "wait" || o.op === "skew") return [o];
      if (o.op === "invite") return o.by[1] === v || o.published ? [labelled(o)] : [];
      if (o.op === "flush") {
        if (o.by[1] === v) return [o.abandoned ? { op: "flush", abandoned: true } : { op: "flush" }];
        return o.published ? [labelled(o.invite)] : [];
      }
      return [];
    });
    const ops: TraceStepOp[] = [...(this.repoOps() as TraceStepOp[]), ...timed];
    const tb = (b: Binding): TraceBinding => [b.account.slice(8), b.device.deviceId];
    const all = w.allBindings();
    const accepted = all.filter((b: Binding) => this.viewer.trust.isAccepted(b)).map(tb);
    const holds = this.accounts.filter((a) => this.viewer.trust.hold(did(a)));
    if (!hasStanding(this.policy)) {
      this.trace!.steps.push({ ops, accepted, holds });
      return;
    }
    const tracked = this.viewer.trackedAccounts().map((d) => d.slice(8)).sort();
    const standing: Record<string, TraceBinding[]> = {};
    const authorized: Record<string, TraceBinding[]> = {};
    this.spaces.forEach((s, n) => {
      standing[SPACE_LABELS[n]] = all.filter((b) => this.viewer.trust.standing(b, s)).map(tb);
      const ids = this.viewer.trust.state.authorized.get(s);
      authorized[SPACE_LABELS[n]] = all.filter((b) => ids?.has(bindingId(b))).map(tb);
    });
    if (this.policy === "witness") {
      // Own-account watching: the viewer's own bindings it alarmed about as
      // unrecognised, in any witnessed commit so far.
      const alarmed = new Set(this.viewer.trust.state.alarms.filter((x) => x.kind === "unapproved-own").map((x) => x.device));
      const ownAlarms = all.filter((b) => b.account === this.viewer.did && alarmed.has(b.device.deviceId)).map(tb);
      this.trace!.steps.push({ ops, accepted, holds, tracked, standing, authorized, ownAlarms });
      return;
    }
    this.trace!.steps.push({ ops, accepted, holds, tracked, standing, authorized });
  }
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export function replay(seed: string, shared: boolean, actions: Action[], policy: Policy = "inviters"): string | null {
  const walk = new Walk(seed, shared, policy);
  for (let n = 0; n < actions.length; n++) {
    const err = walk.step(actions[n]);
    if (err) return `step ${n}: ${err}`;
  }
  return null;
}

/** Drop actions one at a time while the walk still fails. */
export function shrink(seed: string, shared: boolean, actions: Action[], policy: Policy = "inviters"): Action[] {
  for (let changed = true; changed; ) {
    changed = false;
    for (let n = 0; n < actions.length; n++) {
      const trial = actions.slice(0, n).concat(actions.slice(n + 1));
      if (replay(seed, shared, trial, policy)) {
        actions = trial;
        changed = true;
        break;
      }
    }
  }
  return actions;
}

/** Run one seeded walk. Returns the shrunk failing actions, if any. */
export function walk(seed: string, steps: number, shared: boolean, policy: Policy = "inviters"): { failure: string | null; actions: Action[]; trace: Trace | null } {
  const rng = Rng.fromLabel(`fuzz/${seed}`);
  const w = new Walk(seed, shared, policy);
  const actions: Action[] = [];
  for (let n = 0; n < steps; n++) {
    const a = w.gen(rng);
    actions.push(a);
    if (w.step(a)) {
      const small = shrink(seed, shared, actions, policy);
      return { failure: replay(seed, shared, small, policy), actions: small, trace: null };
    }
  }
  return { failure: null, actions, trace: w.trace };
}
