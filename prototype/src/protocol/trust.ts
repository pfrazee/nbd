// Local trust (device-enrollment.md#local-trust): first use under the
// single-root rule, approvals D1-D3 with the live-binding rule, revocation
// by verified absence, and re-enrollment holds credited in this
// installation's own clock domain. A port of SpecClient in
// model/nbd_trust.py, driven by this installation's verified snapshots
// rather than a shared world.
//
// Under the inviters policy (device-enrollment.md#grant-standing) it also keeps grant
// standing's bases, following InviterClient in model/nbd_trust.py: the
// bindings its own account's published records authorize per space, its
// first-contact lineage
// bindings (what a new record may authorize), the approver that accepted
// each binding, a first-contact hold per binding, and pending invites.

import { verify } from "./crypto";
import { type Snapshot, recordsIn } from "./repo";
import {
  type Approval, type Binding, COL, type Did, type Invite, type Policy, asCbor, bindingId, label, sameBinding, withoutProof,
} from "./types";

export const REENROLL_HOLD = 72; // hours
/** How long a pending invite can be captured, in credited hours
 * (core.md#invites). */
export const PENDING_INVITE_TTL = 168;

export type Hold = { candidate: string[]; bindings: Binding[]; credited: number; checkpoint: number };
/** Time credited to one binding since this installation accepted it. */
export type FirstContactHold = { credited: number; checkpoint: number };
/** A pending invite this account made: credited like a hold. `issuer` is
 * the device that made it, the only one that may capture it; `done` once
 * the account was first pinned here, captured or not. */
export type PendingInvite = { space: string; account: Did; issuer: string; credited: number; checkpoint: number; done: boolean };
export type Alarm = { at: number; kind: string; text: string; subject?: Did };
/** `about`, `by`, `account`, and `until` are structured details for
 * interfaces; `text` is the same notice in words. */
export type Notice = { at: number; kind: string; text: string; about?: Binding; by?: Binding; account?: Did; until?: number };

/** What this installation last verified about one account's public repo. */
export type AccountView = {
  rev: number;
  data: string;
  commits: Map<number, string>;
  present: Map<string, Binding>; // deviceId -> binding
  approvals: Approval[];
};

/** Starting over after total device loss (device-enrollment.md#total-device-loss).
 * The account's other bindings found on the first sync are the list the user
 * checks and removes, not alarms; `done` once they have removed them. */
export type StartOver = { list: Map<string, Binding> | null; done: boolean };

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
  startOver: StartOver | null;
  // Grant standing's bases, kept only under the inviters policy.
  /** space -> IDs of bindings a published invite or capture record of this
   * installation's own account authorizes there. Rule 1 standing. */
  authorized: Map<string, Set<string>>;
  /** IDs of the roots of this installation's first-contact lineage: bindings
   * it accepted by first use, or adopted from an own record or an import for
   * an account it had never pinned. A binding is in the lineage if it is a
   * root or was accepted by approval, through any chain, from one (revoked
   * or not). Decides what a new record may authorize, and what an adopted or
   * imported authorization may cover. Re-enrolled and own bindings are never
   * roots. */
  lineage: Set<string>;
  /** account -> spaces this installation's account published an invite
   * record admitting it to (for display; it grants nothing). */
  admitted: Map<Did, Set<string>>;
  /** pending invite record rkey -> the pending invite. Never transferred:
   * only the installation that made it holds it. */
  pending: Map<string, PendingInvite>;
  /** rkeys of pending invites this account abandoned. Transferred, so a
   * stale backup cannot reopen one. */
  abandoned: Set<string>;
  /** binding ID -> ID of the signer whose approval accepted it. */
  approvers: Map<string, string>;
  /** binding ID -> its first-contact hold. */
  fcHolds: Map<string, FirstContactHold>;
};

export function emptyTrust(): TrustState {
  return {
    accepted: new Map(), revoked: new Map(), holds: new Map(), candidatesSeen: new Map(), views: new Map(),
    approvedByMe: new Set(), noticed: new Set(), alarms: [], notices: [], startOver: null,
    authorized: new Map(), lineage: new Set(), admitted: new Map(), pending: new Map(), abandoned: new Set(), approvers: new Map(), fcHolds: new Map(),
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
    startOver: t.startOver && { list: t.startOver.list && new Map(t.startOver.list), done: t.startOver.done },
    authorized: new Map([...t.authorized].map(([s, ids]) => [s, new Set(ids)])),
    lineage: new Set(t.lineage),
    admitted: new Map([...t.admitted].map(([d, s]) => [d, new Set(s)])),
    pending: new Map([...t.pending].map(([k, p]) => [k, { ...p }])),
    abandoned: new Set(t.abandoned),
    approvers: new Map(t.approvers),
    fcHolds: new Map([...t.fcHolds].map(([id, h]) => [id, { ...h }])),
  };
}

/** The payload an invite record's proof signs. */
export function invitePayload(r: Omit<Invite, "proof">): unknown[] {
  return ["nbd/invite", 1, asCbor(r)];
}

/** First-contact holds are kept per binding: each binding a client accepts
 * starts its own. */
const fcKey = (b: Binding): string => bindingId(b);

export function approvalPayload(a: Omit<Approval, "proof">): unknown[] {
  return ["nbd/device-approval", 1, asCbor(a)];
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
    readonly policy: Policy = "inviters",
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

  /** Whether this installation may grant `space`'s key to `b` (inviters
   * policy). Acceptance is unchanged; standing gates only issuance. */
  standing(b: Binding, space: string): boolean {
    return this.standingBasis(b, space) !== null;
  }

  /** Why `b` has grant standing in `space`, or null. */
  standingBasis(b: Binding, space: string): string | null {
    if (!this.isAccepted(b)) return null;
    return this.source(bindingId(b), space, new Set());
  }

  /** Standing's sources, ignoring revocation along the approval chain so a
   * device linked by a since-removed device inherits what it had. */
  private source(id: string, space: string, seen: Set<string>): string | null {
    if (seen.has(id)) return null;
    seen.add(id);
    const st = this.state;
    const a = st.accepted.get(id);
    if (!a) return null;
    if (a.binding.account === this.own.account) return "own";
    if (a.evidence === "re-enrolled") return "re-enrolled";
    if ((st.fcHolds.get(fcKey(a.binding))?.credited ?? 0) >= REENROLL_HOLD) return "held";
    if (st.authorized.get(space)?.has(id)) return "authorized";
    const signer = st.approvers.get(id);
    const via = signer === undefined ? null : this.source(signer, space, seen);
    return via && `approved by ${label(st.accepted.get(signer!)!.binding)} (${via})`;
  }

  /** Hours left on `b`'s first-contact hold here, or null if it has none. */
  firstContactRemaining(b: Binding): number | null {
    const h = this.state.fcHolds.get(fcKey(b));
    if (!h) return null;
    const running = this.state.revoked.has(bindingId(b)) ? 0 : Math.max(0, this.localNow() - h.checkpoint);
    return Math.max(0, REENROLL_HOLD - h.credited - running);
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
          if (this.policy === "inviters") {
            // The target inherits its signer's standing, and starts its own
            // first-contact hold in case the signer is removed first.
            st.approvers.set(tid, bindingId(ap.signer));
            this.startFirstContactHold(ap.target);
          }
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
      if (cand) for (const b of cand) {
        st.accepted.set(bindingId(b), { binding: b, evidence: "first use" });
        if (this.policy === "inviters") {
          this.startFirstContactHold(b);
          st.lineage.add(bindingId(b));
        }
      }
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
        `${account} reset their devices. This device will share with their new device from ${fmtHour(this.localNow() + REENROLL_HOLD)}.`,
        { account, until: this.localNow() + REENROLL_HOLD, about: cand[0] });
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
    const so = st.startOver;
    if (so && !so.list) so.list = new Map([...view.present.values()].filter((b) => !sameBinding(b, this.own)).map((b) => [bindingId(b), b]));
    for (const b of view.present.values()) {
      const id = bindingId(b);
      if (sameBinding(b, this.own) || st.approvedByMe.has(id)) continue;
      if (this.isAccepted(b)) {
        const by = view.approvals.find((a) => sameBinding(a.target, b))?.signer;
        this.notice(`added:${id}`, "own-added", `New device ${label(b)}${by ? `, added from ${label(by)}` : ""}. Not you? Remove it.`, { about: b, by });
      } else if (!(so && !so.done && so.list!.has(id))) {
        // On a start-over list until the user has removed it; after that, or
        // for anything not on the list, an unaccepted binding alarms.
        this.alarmOnce(`unapproved:${id}`, "unapproved-own", `A device you don't recognise (${label(b)}) is on your account.`);
      }
    }
    for (const [id, b] of st.revoked) {
      if (b.account === account && !sameBinding(b, this.own)) this.notice(`removed:${id}`, "own-removed", `Device ${label(b)} was removed from your account.`, { about: b });
    }
  }

  /** Whether a grant to this own binding is start-over history rather than a
   * detection (audit.md#direct-sync): the binding is on the removal list, and
   * either the user hasn't finished removing or it is verified absent. */
  startOverHistory(b: Binding): boolean {
    const so = this.state.startOver;
    if (!so?.list?.has(bindingId(b))) return false;
    return !so.done || !this.state.views.get(b.account)?.present.has(b.device.deviceId);
  }

  reconcileHolds(): void {
    const st = this.state;
    for (const [account, h] of [...st.holds]) {
      if (this.live(account).length) st.holds.delete(account);
      else if (h.candidate.some((id) => st.revoked.has(id))) st.holds.delete(account);
    }
  }

  /** Credit elapsed local time; a clock that moved back credits nothing.
   * A revoked binding's first-contact hold keeps its credit but earns no
   * more. Under the inviters policy, installations tick before applying an
   * observation, so a removal costs no credit earned before it was learned. */
  tick(): void {
    const now = this.localNow();
    for (const h of this.state.holds.values()) {
      h.credited += Math.max(0, now - h.checkpoint);
      h.checkpoint = now;
    }
    for (const [id, h] of this.state.fcHolds) {
      if (!this.state.revoked.has(id)) h.credited += Math.max(0, now - h.checkpoint);
      h.checkpoint = now;
    }
    for (const p of this.state.pending.values()) {
      p.credited += Math.max(0, now - p.checkpoint);
      p.checkpoint = now;
    }
  }

  // ---- grant standing (inviters policy) ------------------------------------

  private startFirstContactHold(b: Binding): void {
    const k = fcKey(b);
    if (b.account !== this.own.account && !this.state.fcHolds.has(k)) this.state.fcHolds.set(k, { credited: 0, checkpoint: this.localNow() });
  }

  /** Whether `b` is in this installation's first-contact lineage: a root,
   * or accepted by approval, directly or through a chain, from a root
   * (revoked or not), so a replacement phone stays in it. */
  inLineage(b: Binding): boolean {
    const st = this.state;
    const seen = new Set<string>();
    for (let id: string | undefined = bindingId(b); id && !seen.has(id); id = st.approvers.get(id)) {
      if (st.lineage.has(id)) return true;
      seen.add(id);
    }
    return false;
  }

  /** A published record of this installation's own account authorizes `b`
   * in `space`. */
  authorize(space: string, b: Binding): void {
    const st = this.state;
    if (!st.authorized.has(space)) st.authorized.set(space, new Set());
    st.authorized.get(space)!.add(bindingId(b));
  }

  /** This installation's account published an invite record admitting
   * `account` to `space`. */
  admit(account: Did, space: string): void {
    const st = this.state;
    if (!st.admitted.has(account)) st.admitted.set(account, new Set());
    st.admitted.get(account)!.add(space);
  }

  /** Abandon a pending invite: it stops being pending, persistently. */
  abandonPending(rkey: string): void {
    this.state.pending.delete(rkey);
    this.state.abandoned.add(rkey);
  }

  /** Remember a pending invite this installation's device `issuer` made. */
  addPending(rkey: string, space: string, account: Did, issuer: string): void {
    if (!this.state.pending.has(rkey) && !this.state.abandoned.has(rkey))
      this.state.pending.set(rkey, { space, account, issuer, credited: 0, checkpoint: this.localNow(), done: false });
  }

  /** Take the authorization in an invite or capture record from this
   * installation's own account. If it never pinned the account, it pins the
   * authorized bindings, like a pin copied by pairing, as roots of its
   * first-contact lineage (presence is checked by the next observation). If
   * it already pins the account, it takes the authorization only for
   * bindings in its own first-contact lineage, so a record never ends a
   * reset's hold running here. Returns whether it pinned anything. */
  adoptInvite(rec: Invite): boolean {
    if (!rec.authorizes.length) return false;
    const st = this.state;
    const fresh = !this.knew(rec.account);
    for (const b of rec.authorizes) {
      if (b.account !== rec.account) continue;
      if (fresh) {
        st.accepted.set(bindingId(b), { binding: b, evidence: `invited by ${label(rec.issuer)}` });
        this.startFirstContactHold(b);
        st.lineage.add(bindingId(b));
      } else if (!this.inLineage(b)) continue;
      this.authorize(rec.space, b);
    }
    return fresh && this.knew(rec.account);
  }

  // ---- transfer ------------------------------------------------------------

  /** Import another own installation's state (pairing, backup). */
  importFrom(other: TrustState): void {
    const st = this.state;
    const knew = new Set([...st.accepted.values()].map((a) => a.binding.account));
    if (this.policy === "inviters") this.tick();
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
    if (this.policy === "inviters") {
      // First-contact holds transfer as credited time, never more than
      // either installation credited.
      for (const [id, h] of other.fcHolds) {
        const mine = st.fcHolds.get(id);
        st.fcHolds.set(id, { credited: Math.max(h.credited, mine?.credited ?? 0), checkpoint: now });
      }
      // Lineage roots carry only to an installation with no pin for the account.
      for (const id of other.lineage) {
        const b = other.accepted.get(id)?.binding;
        if (b && !knew.has(b.account)) st.lineage.add(id);
      }
      // Approval evidence first, then an authorization only for a binding in
      // this installation's first-contact lineage.
      for (const [t, s] of other.approvers) if (!st.approvers.has(t)) st.approvers.set(t, s);
      for (const [space, ids] of other.authorized)
        for (const id of ids) {
          const b = other.accepted.get(id)?.binding;
          if (b && this.inLineage(b)) this.authorize(space, b);
        }
      for (const [d, spaces] of other.admitted) for (const s of spaces) this.admit(d, s);
      // Pending invites never transfer; abandonments do.
      for (const k of other.abandoned) this.abandonPending(k);
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

  notice(key: string, kind: string, text: string, details: Omit<Notice, "at" | "kind" | "text"> = {}): void {
    if (this.state.noticed.has(key)) return;
    this.state.noticed.add(key);
    this.state.notices.push({ at: this.localNow(), kind, text, ...details });
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
