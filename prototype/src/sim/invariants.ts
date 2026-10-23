// Invariants from model/test_walks.py, checked per installation against its
// own verified observations rather than the true world. Evaluated around
// every scenario step; violations are reported, not thrown, so the UI can
// show them.

import type { Installation } from "../protocol/installation";
import { type AccountView, REENROLL_HOLD } from "../protocol/trust";
import { type Binding, bindingId, label } from "../protocol/types";
import type { World } from "../world/world";
import { DisclosureCheck } from "./disclosure";

const EPS = 1e-9;

type Snap = {
  accepted: Set<string>;
  revoked: Set<string>;
  revs: Map<string, number>;
  holds: Map<string, { key: string; credited: number }>;
  imports: number;
};

function snap(i: Installation): Snap {
  const st = i.trust.state;
  return {
    accepted: new Set(st.accepted.keys()),
    revoked: new Set(st.revoked.keys()),
    revs: new Map([...st.views].map(([d, v]) => [d, v.rev])),
    holds: new Map([...st.holds].map(([d, h]) => [d, { key: `${d}:${h.candidate.join(",")}`, credited: h.credited }])),
    imports: i.imports,
  };
}

export class InvariantMonitor {
  private prev = new Map<string, Snap>();
  /** World time each exact candidate was first seen by any installation. */
  private firstSeen = new Map<string, number>();
  readonly violations: { at: number; text: string }[] = [];
  private readonly disclosure: DisclosureCheck;

  constructor(private readonly world: World) {
    this.disclosure = new DisclosureCheck(world);
  }

  before(): void {
    this.disclosure.begin();
    for (const i of this.world.installations.values()) this.prev.set(i.id, snap(i));
  }

  after(): string[] {
    const out: string[] = [];
    for (const i of this.world.installations.values()) {
      for (const [d, h] of i.trust.state.holds) {
        const k = `${d}:${h.candidate.join(",")}`;
        if (!this.firstSeen.has(k)) this.firstSeen.set(k, this.world.t);
      }
      for (const v of this.check(i)) out.push(`${i.id}: ${v}`);
    }
    for (const v of this.disclosure.check()) out.push(`goal: ${v}`);
    for (const text of out) this.violations.push({ at: this.world.t, text });
    return out;
  }

  private check(i: Installation): string[] {
    const st = i.trust.state;
    const before = this.prev.get(i.id);
    const out: string[] = [];
    if (before) {
      for (const id of before.accepted) if (!st.accepted.has(id)) out.push(`acceptance lost: ${id.slice(0, 8)}`);
      for (const id of before.revoked) if (!st.revoked.has(id)) out.push(`revocation lost: ${id.slice(0, 8)}`);

      // New usable acceptances of accounts this installation already knew.
      if (i.imports === before.imports) {
        const knew = new Set([...before.accepted].map((id) => st.accepted.get(id)!.binding.account));
        // Devices this installation approved itself were authenticated by
        // pairing; it need not see its own approval come back first.
        const base = new Set([...before.accepted, ...st.approvedByMe]);
        for (const [account, h] of before.holds) {
          const ids = h.key.slice(account.length + 1).split(",");
          if (this.world.t - (this.firstSeen.get(h.key) ?? Infinity) >= REENROLL_HOLD - EPS) ids.forEach((x) => base.add(x));
        }
        const reach = this.closure(i, base, before.revoked);
        for (const [id, a] of st.accepted) {
          if (before.accepted.has(id) || st.revoked.has(id) || !knew.has(a.binding.account)) continue;
          if (!reach.has(id)) out.push(`accepted ${label(a.binding)} without an approval path or elapsed hold`);
        }
      }
    }

    for (const [d, h] of st.holds) {
      const k = `${d}:${h.candidate.join(",")}`;
      const real = this.world.t - (this.firstSeen.get(k) ?? this.world.t);
      if (h.credited > real + EPS) out.push(`hold for ${d} credited ${h.credited.toFixed(1)}h, more than ${real.toFixed(1)}h real`);
      if (h.candidate.some((x) => st.revoked.has(x))) out.push(`hold for ${d} pending with a revoked candidate`);
      if (i.trust.live(d).length) out.push(`hold for ${d} pending while the account has a live binding`);
      const old = before?.holds.get(d);
      if (old && old.key === k && h.credited < old.credited - EPS) out.push(`hold credit for ${d} fell`);
    }

    if (st.revoked.has(bindingId(i.binding)) && !st.alarms.some((a) => a.kind === "own-removed"))
      out.push("own binding revoked without takeover alarm");

    // After a detected fork the account's history is suspect, and clients
    // rightly refuse it rather than act on it.
    const forked = new Set(st.alarms.filter((a) => a.kind === "fork").map((a) => a.subject));

    if (before) {
      // Rollback refusal: a verified view of a repo never moves backward.
      for (const [d, v] of st.views)
        if (v.rev < (before.revs.get(d) ?? 0)) out.push(`view of ${d} rolled back from ${before.revs.get(d)} to ${v.rev}`);
      // Revocation is justified by a view at least as new as the binding's
      // acceptance that shows its record absent.
      if (i.imports === before.imports)
        for (const [id, b] of st.revoked) {
          if (before.revoked.has(id) || forked.has(b.account)) continue;
          const v = st.views.get(b.account);
          const p = v?.present.get(b.device.deviceId);
          if (!v || v.rev < (st.accepted.get(id)?.rev ?? 0) || (p && bindingId(p) === id))
            out.push(`revoked ${label(b)} without a view newer than its record showing it absent`);
        }
    }
    if (i.online) {
      for (const [account, view] of st.views) {
        if (account === i.did || forked.has(account)) continue;
        const expect = singleRoot(view, st.revoked);
        const want = expect ? expect.map(bindingId).sort() : null;
        const live = i.trust.live(account).length > 0;
        const knows = i.trust.knew(account);

        // First use follows the single-root rule (restated independently).
        const knewBefore = !!before && [...before.accepted].some((id) => st.accepted.get(id)?.binding.account === account);
        if (before && !knewBefore && knows && i.imports === before.imports) {
          const got = [...st.accepted].filter(([id, a]) => a.binding.account === account && !before.accepted.has(id) && !st.revoked.has(id))
            .map(([id]) => id).sort();
          if (!want) out.push(`first use of ${account} accepted ${got.length} binding(s); the rule declines`);
          else if (got.join() !== want.join()) out.push(`first use of ${account} accepted ${got.length}, the rule accepts ${want.length}`);
        }

        // Closure: approvals by accepted signers are applied while the
        // account has a live accepted binding.
        if (live)
          for (const ap of view.approvals)
            if (st.accepted.has(bindingId(ap.signer)) && !st.accepted.has(bindingId(ap.target)))
              out.push(`${label(ap.target)} approved by accepted ${label(ap.signer)} but not accepted`);

        // Re-enrollment: a known account with no live binding whose present
        // records satisfy the rule has exactly that candidate on hold.
        if (knows && !live && want) {
          const h = st.holds.get(account);
          if (!h || h.candidate.join() !== want.join()) out.push(`re-enrollment of ${account} is not holding the rule's candidate`);
        }
      }

      for (const [id, a] of st.accepted) {
        if (forked.has(a.binding.account)) continue;
        const view = st.views.get(a.binding.account);
        const p = view?.present.get(a.binding.device.deviceId);
        if (view && view.rev >= (a.rev ?? 0) && !st.revoked.has(id) && (!p || bindingId(p) !== id))
          out.push(`${label(a.binding)} absent but not revoked`);
      }
    }
    return out;
  }

  /** Approval closure over this installation's verified approvals, following
   * only accounts with a binding that was live when the step began (an
   * acceptance and a later revocation can happen within one step). */
  private closure(i: Installation, start: Set<string>, revokedBefore: Set<string>): Set<string> {
    const st = i.trust.state;
    const seen = new Set(start);
    const liveAccount = (account: string) =>
      [...seen].some((id) => {
        const b: Binding | undefined = st.accepted.get(id)?.binding ?? st.candidatesSeen.get(id);
        return !!b && b.account === account && !revokedBefore.has(id);
      });
    for (;;) {
      let added = false;
      for (const [account, view] of st.views) {
        if (!liveAccount(account)) continue;
        for (const ap of view.approvals) {
          const t = bindingId(ap.target);
          if (seen.has(bindingId(ap.signer)) && !seen.has(t)) {
            seen.add(t);
            added = true;
          }
        }
      }
      if (!added) return seen;
    }
  }
}

/** The first-use rule, restated from model/test_walks.py: the present,
 * unrevoked records a client accepts on first contact, or null. */
function singleRoot(view: AccountView, revoked: Map<string, Binding>): Binding[] | null {
  const present = [...view.present.values()].filter((b) => !revoked.has(bindingId(b)));
  if (!present.length) return null;
  const aps = view.approvals;
  const incoming = new Set(aps.map((a) => bindingId(a.target)));
  const roots = present.filter((b) => !incoming.has(bindingId(b)));
  if (roots.length > 1) return null;
  const presentIds = new Set(present.map(bindingId));
  const starts = new Set(roots.length ? roots.map(bindingId)
    : aps.flatMap((a) => [bindingId(a.signer), bindingId(a.target)]).filter((id) => !presentIds.has(id)));
  if (!starts.size) return null;
  const reached = new Set(starts);
  for (let added = true; added; ) {
    added = false;
    for (const a of aps)
      if (reached.has(bindingId(a.signer)) && !reached.has(bindingId(a.target))) {
        reached.add(bindingId(a.target));
        added = true;
      }
  }
  return present.every((b) => reached.has(bindingId(b))) ? present : null;
}
