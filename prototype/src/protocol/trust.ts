// Local trust (device-enrollment.md#local-trust): first use under the
// single-root rule, approvals D1-D3 with the live-binding rule, revocation
// by verified absence, and re-enrollment holds credited in this
// installation's own clock domain. A port of SpecClient in
// model/peep_trust.py, driven by this installation's verified snapshots
// rather than a shared world.

import { verify } from "./crypto";
import { type Snapshot, recordsIn } from "./repo";
import {
  type Approval, type Binding, COL, type Did, asCbor, bindingId, label, sameBinding, withoutProof,
} from "./types";

export const REENROLL_HOLD = 72; // hours

export type Hold = { candidate: string[]; bindings: Binding[]; credited: number; checkpoint: number };
export type Alarm = { at: number; kind: string; text: string; subject?: Did };
export type Notice = { at: number; kind: string; text: string };

/** What this installation last verified about one account's public repo. */
export type AccountView = {
  rev: number;
  data: string;
  commits: Map<number, string>;
  present: Map<string, Binding>; // deviceId -> binding
  approvals: Approval[];
};

export type TrustState = {
  /** `rev`: the repo revision at which the binding was known present; only
   * a snapshot at least that new can prove it absent. */
  accepted: Map<string, { binding: Binding; evidence: string; rev?: number }>;
  revoked: Map<string, Binding>;
  holds: Map<Did, Hold>;
  candidatesSeen: Map<string, Binding>;
  views: Map<Did, AccountView>;
  approvedByMe: Set<string>;
  noticed: Set<string>;
  alarms: Alarm[];
  notices: Notice[];
};

export function emptyTrust(): TrustState {
  return {
    accepted: new Map(), revoked: new Map(), holds: new Map(), candidatesSeen: new Map(), views: new Map(),
    approvedByMe: new Set(), noticed: new Set(), alarms: [], notices: [],
  };
}

export function cloneTrust(t: TrustState): TrustState {
  return {
    accepted: new Map(t.accepted),
    revoked: new Map(t.revoked),
    holds: new Map([...t.holds].map(([k, h]) => [k, { ...h, candidate: [...h.candidate], bindings: [...h.bindings] }])),
    candidatesSeen: new Map(t.candidatesSeen),
    views: new Map([...t.views].map(([k, v]) => [k, { ...v, commits: new Map(v.commits), present: new Map(v.present), approvals: [...v.approvals] }])),
    approvedByMe: new Set(t.approvedByMe),
    noticed: new Set(t.noticed),
    alarms: [...t.alarms],
    notices: [...t.notices],
  };
}

export function approvalPayload(a: Omit<Approval, "proof">): unknown[] {
  return ["peep/device-approval", 1, asCbor(a)];
}

function isBinding(x: unknown, account: Did): x is Binding {
  const b = x as Binding;
  return !!b && b.account === account && !!b.device && typeof b.device.deviceId === "string"
    && b.device.authPubkey instanceof Uint8Array && b.device.authPubkey.length === 32
    && b.device.encryptPubkey instanceof Uint8Array && b.device.encryptPubkey.length === 32;
}

// Approval records are immutable objects, so signature checks are cached per
// object and account (simulation speed only; it changes no outcome).
const checked = new WeakMap<object, Map<Did, boolean>>();

/** D1: schema, same-account scope, and signature. */
export function validApproval(x: unknown, account: Did): x is Approval {
  const a = x as Approval;
  if (!a || typeof a !== "object") return false;
  let m = checked.get(a);
  const cached = m?.get(account);
  if (cached !== undefined) return cached;
  const ok = a.version === 1 && a.proof instanceof Uint8Array && isBinding(a.signer, account) && isBinding(a.target, account)
    && verify(a.proof, approvalPayload(withoutProof(a)), a.signer.device.authPubkey);
  if (!m) checked.set(a, (m = new Map()));
  m.set(account, ok);
  return ok;
}

export class Trust {
  constructor(
    public state: TrustState,
    private readonly own: Binding,
    private readonly localNow: () => number,
  ) {}

  // ---- queries -------------------------------------------------------------

  isAccepted(b: Binding): boolean {
    const id = bindingId(b);
    return this.state.accepted.has(id) && !this.state.revoked.has(id);
  }

  live(account: Did): Binding[] {
    return [...this.state.accepted.entries()]
      .filter(([id, a]) => a.binding.account === account && !this.state.revoked.has(id))
      .map(([, a]) => a.binding);
  }

  knew(account: Did): boolean {
    return [...this.state.accepted.values()].some((a) => a.binding.account === account);
  }

  hold(account: Did): Hold | undefined {
    return this.state.holds.get(account);
  }

  // ---- observation ---------------------------------------------------------

  /** Incorporate a verified enumeration of `account`'s public repo. Returns
   * false if it was refused (rollback or fork). */
  observe(account: Did, snap: Snapshot): boolean {
    const st = this.state;
    const prev = st.views.get(account);
    const rev = snap.commit.rev;
    if (prev) {
      if (rev < prev.rev) return false; // rollback: refuse
      const seen = prev.commits.get(rev);
      if (seen !== undefined && seen !== snap.commit.data) {
        this.alarmOnce(`fork:${account}:${rev}`, "fork", `${account}'s PDS showed two different commits at revision ${rev}.`, account);
        return false;
      }
    }
    const present = new Map<string, Binding>();
    for (const [rkey, v] of recordsIn(snap, COL.device)) {
      const b = (v as { value?: unknown }).value;
      if (isBinding(b, account) && b.device.deviceId === rkey) present.set(rkey, b);
    }
    const approvals = recordsIn(snap, COL.approval)
      .map(([, v]) => (v as { value?: unknown }).value)
      .filter((a): a is Approval => validApproval(a, account));
    const commits = new Map(prev?.commits ?? []);
    commits.set(rev, snap.commit.data);
    st.views.set(account, { rev, data: snap.commit.data, commits, present, approvals });

    this.revoke(account);
    this.applyApprovals(account);
    if (account === this.own.account) this.ownAccount(account);
    else this.firstUse(account);
    this.reconcileHolds();
    return true;
  }

  private presentBinding(account: Did, b: Binding): boolean {
    const p = this.state.views.get(account)?.present.get(b.device.deviceId);
    return !!p && sameBinding(p, b);
  }

  /** Revocation by verified absence; resurrection alarms. */
  private revoke(account: Did): void {
    const st = this.state;
    const tracked = [...st.accepted.values()].map((a) => a.binding)
      .concat([...st.candidatesSeen.values()])
      .filter((b) => b.account === account);
    const viewRev = st.views.get(account)?.rev ?? 0;
    for (const b of tracked) {
      const id = bindingId(b);
      if (viewRev < (st.accepted.get(id)?.rev ?? 0)) continue; // snapshot predates the binding
      if (!st.revoked.has(id) && !this.presentBinding(account, b)) {
        st.revoked.set(id, b);
        if (sameBinding(b, this.own))
          this.alarmOnce("own-removed", "own-removed", "This device was removed from your account. If this wasn't you, change your password and remove devices you don't recognise.");
      }
    }
    for (const [id, b] of st.revoked) {
      if (b.account === account && this.presentBinding(account, b)) this.alarmOnce(`resurrected:${id}`, "resurrection", `${label(b)} reappeared after it was removed`);
    }
  }

  /** D2/D3: approvals from accepted signers, only while the account has a
   * live accepted binding. A deleted target is accepted already revoked. */
  private applyApprovals(account: Did): void {
    const st = this.state;
    const aps = st.views.get(account)?.approvals ?? [];
    for (;;) {
      if (this.live(account).length === 0) return; // re-enrollment: only the hold accepts
      let added = false;
      for (const ap of aps) {
        const tid = bindingId(ap.target);
        if (st.accepted.has(bindingId(ap.signer)) && !st.accepted.has(tid)) {
          st.accepted.set(tid, { binding: ap.target, evidence: `approved by ${label(ap.signer)}` });
          if (!this.presentBinding(account, ap.target)) st.revoked.set(tid, ap.target);
          added = true;
        }
      }
      if (!added) return;
    }
  }

  private reach(aps: Approval[], starts: Binding[]): Set<string> {
    const seen = new Set(starts.map(bindingId));
    const frontier = [...seen];
    while (frontier.length) {
      const n = frontier.pop()!;
      for (const ap of aps) {
        const t = bindingId(ap.target);
        if (bindingId(ap.signer) === n && !seen.has(t)) {
          seen.add(t);
          frontier.push(t);
        }
      }
    }
    return seen;
  }

  /** The single-root rule over present, unrevoked records. */
  singleRootSet(account: Did): Binding[] | null {
    const view = this.state.views.get(account);
    if (!view) return null;
    const present = [...view.present.values()].filter((b) => !this.state.revoked.has(bindingId(b)));
    if (present.length === 0) return null;
    const aps = view.approvals;
    const presentIds = new Set(present.map(bindingId));
    const incoming = new Set(aps.map((a) => bindingId(a.target)));
    const roots = present.filter((p) => !incoming.has(bindingId(p)));
    if (roots.length > 1) return null;
    let starts: Binding[] = roots;
    if (!starts.length) {
      const nodes = new Map<string, Binding>();
      for (const a of aps) for (const b of [a.signer, a.target]) nodes.set(bindingId(b), b);
      starts = [...nodes.entries()].filter(([id]) => !presentIds.has(id)).map(([, b]) => b);
    }
    if (!starts.length) return null;
    const reached = this.reach(aps, starts);
    return present.every((p) => reached.has(bindingId(p))) ? present : null;
  }

  private firstUse(account: Did): void {
    const st = this.state;
    if (this.live(account).length) return;
    const cand = this.singleRootSet(account);
    if (!this.knew(account)) {
      if (cand) for (const b of cand) st.accepted.set(bindingId(b), { binding: b, evidence: "first use" });
      return;
    }
    if (!cand) return;
    const key = cand.map(bindingId).sort();
    this.tick();
    let held = st.holds.get(account);
    if (!held || held.candidate.join() !== key.join()) {
      for (const b of cand) st.candidatesSeen.set(bindingId(b), b);
      held = { candidate: key, bindings: cand, credited: 0, checkpoint: this.localNow() };
      st.holds.set(account, held);
      this.notice(`hold:${account}:${key.join()}`, "reset",
        `${account} reset their devices. This device will share with their new device from ${fmtHour(this.localNow() + REENROLL_HOLD)}.`);
    }
    if (held.credited >= REENROLL_HOLD) {
      for (const b of cand) st.accepted.set(bindingId(b), { binding: b, evidence: "re-enrolled" });
      st.holds.delete(account);
    }
  }

  /** Own account: approvals only (no first use); notices for changes this
   * installation did not make; alarm on records it has not accepted. */
  private ownAccount(account: Did): void {
    const st = this.state;
    const view = st.views.get(account)!;
    for (const b of view.present.values()) {
      const id = bindingId(b);
      if (sameBinding(b, this.own) || st.approvedByMe.has(id)) continue;
      if (this.isAccepted(b)) {
        const by = view.approvals.find((a) => sameBinding(a.target, b))?.signer;
        this.notice(`added:${id}`, "own-added", `New device ${label(b)}${by ? `, added from ${label(by)}` : ""}. Not you? Remove it.`);
      } else {
        this.alarmOnce(`unapproved:${id}`, "unapproved-own", `A device you don't recognise (${label(b)}) is on your account.`);
      }
    }
    for (const [id, b] of st.revoked) {
      if (b.account === account && !sameBinding(b, this.own)) this.notice(`removed:${id}`, "own-removed", `Device ${label(b)} was removed from your account.`);
    }
  }

  reconcileHolds(): void {
    const st = this.state;
    for (const [account, h] of [...st.holds]) {
      if (this.live(account).length) st.holds.delete(account);
      else if (h.candidate.some((id) => st.revoked.has(id))) st.holds.delete(account);
    }
  }

  /** Credit elapsed local time; a clock that moved back credits nothing. */
  tick(): void {
    const now = this.localNow();
    for (const h of this.state.holds.values()) {
      h.credited += Math.max(0, now - h.checkpoint);
      h.checkpoint = now;
    }
  }

  // ---- transfer ------------------------------------------------------------

  /** Import another own installation's state (pairing, backup). */
  importFrom(other: TrustState): void {
    const st = this.state;
    for (const [id, a] of other.accepted) if (!st.accepted.has(id)) st.accepted.set(id, a);
    for (const [id, b] of other.revoked) st.revoked.set(id, b);
    for (const [id, b] of other.candidatesSeen) st.candidatesSeen.set(id, b);
    for (const [did, v] of other.views) {
      const mine = st.views.get(did);
      if (!mine || v.rev > mine.rev) st.views.set(did, { ...v, commits: new Map(v.commits), present: new Map(v.present), approvals: [...v.approvals] });
    }
    this.tick();
    const now = this.localNow();
    for (const [did, h] of other.holds) {
      const mine = st.holds.get(did);
      if (!mine) st.holds.set(did, { ...h, candidate: [...h.candidate], bindings: [...h.bindings], checkpoint: now });
      else if (mine.candidate.join() === h.candidate.join()) mine.credited = Math.max(mine.credited, h.credited);
    }
    if (st.revoked.has(bindingId(this.own)))
      this.alarmOnce("own-removed", "own-removed", "This device was removed from your account. If this wasn't you, change your password and remove devices you don't recognise.");
    // Callers re-observe current repo state before holds are reconciled.
  }

  // ---- reporting -----------------------------------------------------------

  private alarm(kind: string, text: string, subject?: Did): void {
    this.state.alarms.push({ at: this.localNow(), kind, text, subject });
  }

  private alarmOnce(key: string, kind: string, text: string, subject?: Did): void {
    if (this.state.noticed.has(key)) return;
    this.state.noticed.add(key);
    this.alarm(kind, text, subject);
  }

  notice(key: string, kind: string, text: string): void {
    if (this.state.noticed.has(key)) return;
    this.state.noticed.add(key);
    this.state.notices.push({ at: this.localNow(), kind, text });
  }

  raise(key: string, kind: string, text: string, subject?: Did): void {
    this.alarmOnce(key, kind, text, subject);
  }
}

export function fmtHour(h: number): string {
  const day = Math.floor(h / 24);
  const hour = Math.floor(h % 24);
  return `Day ${day + 1}, ${String(hour).padStart(2, "0")}:00`;
}
