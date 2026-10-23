// Invariants from model/test_walks.py, checked per installation against its
// own verified observations rather than the true world. Evaluated around
// every scenario step; violations are reported, not thrown, so the UI can
// show them.

import type { Installation } from "../protocol/installation";
import { REENROLL_HOLD } from "../protocol/trust";
import { type Binding, bindingId, label } from "../protocol/types";
import type { World } from "../world/world";

const EPS = 1e-9;

type Snap = {
  accepted: Set<string>;
  revoked: Set<string>;
  holds: Map<string, { key: string; credited: number }>;
  imports: number;
};

function snap(i: Installation): Snap {
  const st = i.trust.state;
  return {
    accepted: new Set(st.accepted.keys()),
    revoked: new Set(st.revoked.keys()),
    holds: new Map([...st.holds].map(([d, h]) => [d, { key: `${d}:${h.candidate.join(",")}`, credited: h.credited }])),
    imports: i.imports,
  };
}

export class InvariantMonitor {
  private prev = new Map<string, Snap>();
  /** World time each exact candidate was first seen by any installation. */
  private firstSeen = new Map<string, number>();
  readonly violations: { at: number; text: string }[] = [];

  constructor(private readonly world: World) {}

  before(): void {
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
        const base = new Set(before.accepted);
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

    if (i.online) {
      for (const [id, a] of st.accepted) {
        const view = st.views.get(a.binding.account);
        const p = view?.present.get(a.binding.device.deviceId);
        if (view && !st.revoked.has(id) && (!p || bindingId(p) !== id)) out.push(`${label(a.binding)} absent but not revoked`);
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
