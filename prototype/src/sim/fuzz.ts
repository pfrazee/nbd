// Random walks over a World: user, attacker, network, and malicious-PDS
// actions, with the invariant monitor and extra checks after every step.
// Actions are recorded concretely so a failing walk replays and shrinks.
//
// Shared-view walks restrict themselves to what model/peep_trust.py can
// express (public-repo writes and elapsed time, no lag or forged views) and
// record a trace of the viewer's trust decisions for model/replay_traces.py.

import { Rng } from "../protocol/crypto";
import type { Installation } from "../protocol/installation";
import { commitment } from "../protocol/grants";
import { type Binding, bindingId } from "../protocol/types";
import type { TraceBinding, TraceOp } from "../world/world";
import { World } from "../world/world";
import { InvariantMonitor } from "./invariants";

export type Action = (string | number | boolean)[];
export type TraceStep = { ops: TraceOp[]; accepted: TraceBinding[]; holds: string[] };
export type Trace = { seed: string; viewer: TraceBinding; actions?: Action[]; steps: TraceStep[] };

const ACCOUNTS = ["alice", "bob", "carol"];
const WAITS = [1, 24, 48, 71, 72, 100];
const did = (a: string) => `did:plc:${a}`;

export class Walk {
  readonly world: World;
  readonly monitor: InvariantMonitor;
  readonly space: string;
  readonly viewer: Installation;
  readonly trace: Trace | null;
  private names = 0;

  constructor(readonly seed: string, readonly shared: boolean) {
    const w = (this.world = new World(seed));
    if (shared) w.trace = [];
    const phones = ACCOUNTS.map((a) => w.install(w.account(a, a === "alice" ? "pds.example" : `pds.${a}.example`), "phone"));
    this.viewer = phones[0];
    this.space = phones[0].createSpace("Club");
    for (const p of phones.slice(1)) phones[0].invite(this.space, p.did);
    for (const p of phones) p.join(this.space);
    w.settle();
    this.monitor = new InvariantMonitor(w);
    this.trace = shared ? { seed, viewer: [this.viewer.did.slice(8), this.viewer.binding.device.deviceId], steps: [] } : null;
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
    const acct = pick(ACCOUNTS);
    const kinds: [string, number][] = [
      ["link", 4], ["install", 1], ["remove", 3], ["removeQuiet", 1], ["wait", 3], ["join", 2], ["post", 2],
      ["takeover", 1], ["steal", 1], ["approve", 2], ["recreate", 2], ["attackerAdd", 1], ["skew", 1],
    ];
    if (!this.shared)
      kinds.push(["online", 2], ["lag", 2], ["sub", 1], ["hreset", 1], ["fork", 1], ["rollback", 1], ["stop", 1], ["backup", 1], ["restore", 1], ["member", 1]);
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
        const out = insts.filter((i) => !i.spaces.has(this.space));
        return out.length ? ["join", pick(out).id] : ["post", pick(insts).id];
      }
      case "post":
        return ["post", pick(insts).id];
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
        const gone = insts.filter((i) => !w.pdsOf.get(i.did)!.repo(i.did).records.has(`com.example.peep.device/${i.binding.device.deviceId}`));
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
    else if (kind === "join") { const i = inst(a[1]); if (i) { i.join(this.space); w.settle(); } }
    else if (kind === "post") { const i = inst(a[1]); if (i?.spaces.has(this.space)) { i.post(this.space, `m${w.t}`); w.settle(); } }
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
  }

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
    for (const i of this.world.installations.values()) {
      const sp = i.spaces.get(this.space);
      const cfg = sp?.host.config;
      if (sp?.key && cfg && bindingId(i.binding) && !eq(commitment(this.space, cfg.keyId, sp.key), cfg.commitment))
        return `${i.id} holds a key that does not match the commitment`;
    }
    if (this.shared) this.record();
    return null;
  }

  private record(): void {
    const w = this.world;
    const ops = w.trace!.splice(0);
    const accepted = w.allBindings().filter((b: Binding) => this.viewer.trust.isAccepted(b))
      .map((b): TraceBinding => [b.account.slice(8), b.device.deviceId]);
    const holds = ACCOUNTS.filter((a) => this.viewer.trust.hold(did(a)));
    this.trace!.steps.push({ ops, accepted, holds });
  }
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export function replay(seed: string, shared: boolean, actions: Action[]): string | null {
  const walk = new Walk(seed, shared);
  for (let n = 0; n < actions.length; n++) {
    const err = walk.step(actions[n]);
    if (err) return `step ${n}: ${err}`;
  }
  return null;
}

/** Drop actions one at a time while the walk still fails. */
export function shrink(seed: string, shared: boolean, actions: Action[]): Action[] {
  for (let changed = true; changed; ) {
    changed = false;
    for (let n = 0; n < actions.length; n++) {
      const trial = actions.slice(0, n).concat(actions.slice(n + 1));
      if (replay(seed, shared, trial)) {
        actions = trial;
        changed = true;
        break;
      }
    }
  }
  return actions;
}

/** Run one seeded walk. Returns the shrunk failing actions, if any. */
export function walk(seed: string, steps: number, shared: boolean): { failure: string | null; actions: Action[]; trace: Trace | null } {
  const rng = Rng.fromLabel(`fuzz/${seed}`);
  const w = new Walk(seed, shared);
  const actions: Action[] = [];
  for (let n = 0; n < steps; n++) {
    const a = w.gen(rng);
    actions.push(a);
    if (w.step(a)) {
      const small = shrink(seed, shared, actions);
      return { failure: replay(seed, shared, small), actions: small, trace: null };
    }
  }
  return { failure: null, actions, trace: w.trace };
}
