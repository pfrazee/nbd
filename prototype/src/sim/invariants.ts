// Invariants from model/test_walks.py, checked per installation against its
// own verified observations rather than the true world. Evaluated around
// every scenario step; violations are reported, not thrown, so the UI can
// show them.
//
// Under the inviters policy it also checks grant standing
// (proposal-inviters.md): every accepted binding starts its own first-contact
// hold, credited no faster than real time and frozen once revoked; a vouch
// comes only from an invite or capture record its account made on first
// meeting the account, reaching only installations that had not pinned it
// before; an admitted space only from an invite record that admitted the
// account; a capture only from the device that made the pending invite;
// every binding a published record authorizes was first met through it or
// vouched for its maker when it was made; each authorization an installation
// holds traces to a published own record for that space naming the binding,
// which it holds as vouched; and new standing is explained by such an
// authorization, an approval from a binding with standing there, or an
// elapsed hold.

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
  // Inviters policy only.
  knew: Set<string>;
  vouched: Set<string>; // binding IDs
  admitted: Set<string>; // `${account}|${space}`
  authorized: Set<string>; // `${space}|${binding ID}`
  fc: Map<string, number>; // binding ID -> first-contact credit
  standing: Set<string>; // `${space}|${binding ID}`
};

function snap(i: Installation, spaces: string[]): Snap {
  const st = i.trust.state;
  const standing = new Set<string>();
  for (const s of spaces)
    for (const [id, a] of st.accepted) if (i.trust.standing(a.binding, s)) standing.add(`${s}|${id}`);
  return {
    knew: new Set([...st.accepted.values()].map((a) => a.binding.account)),
    vouched: new Set(st.vouched.keys()),
    admitted: new Set([...st.admitted].flatMap(([d, ss]) => [...ss].map((s) => `${d}|${s}`))),
    authorized: new Set([...st.authorized].flatMap(([s, ids]) => [...ids].map((id) => `${s}|${id}`))),
    fc: new Map([...st.fcHolds].map(([id, h]) => [id, h.credited])),
    standing,
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
  /** installation ID -> account -> event sequence when it first knew the account. */
  private knownSince = new Map<string, Map<string, number>>();
  /** Invite facts already checked. */
  private factsSeen = 0;

  constructor(private readonly world: World) {
    this.disclosure = new DisclosureCheck(world);
  }

  before(): void {
    this.disclosure.begin();
    const spaces = this.spaces();
    for (const i of this.world.installations.values()) this.prev.set(i.id, snap(i, spaces));
    if (this.world.policy === "inviters") this.noteKnown();
  }

  private noteKnown(): void {
    let seq: number | null = null;
    for (const i of this.world.installations.values()) {
      const m = this.knownSince.get(i.id) ?? new Map<string, number>();
      for (const a of i.trust.state.accepted.values()) if (!m.has(a.binding.account)) m.set(a.binding.account, (seq ??= this.world.tick()));
      this.knownSince.set(i.id, m);
    }
  }

  /** Spaces whose standing is tracked: all of them, under the inviters policy. */
  private spaces(): string[] {
    return this.world.policy === "inviters" ? [...this.world.host.spaces.keys()] : [];
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
    // Only the device that made a pending invite captures it.
    const facts = this.world.provenance.invites;
    for (const f of facts.slice(this.factsSeen)) {
      if (!f.captures) continue;
      const p = facts.find((x) => x.rkey === f.captures);
      if (!p || p.device !== f.device) out.push(`${f.inviter}/${f.device.slice(0, 6)} captured a pending invite ${p ? `made by ${p.device.slice(0, 6)}` : "it never published"}`);
    }
    // A record authorizes only devices first met through it, or vouched for
    // its maker when it was made: first met through an earlier published
    // record of the account that its maker knew of.
    for (const f of facts.slice(this.factsSeen)) {
      const maker = [...this.world.installations.values()].find((i) => i.binding.device.deviceId === f.device);
      const knew = (maker && this.knownSince.get(maker.id)?.get(f.account)) ?? Infinity;
      for (const d of f.authorizes) {
        if (f.devices.includes(d)) continue;
        if (!facts.some((g) => g.inviter === f.inviter && g.account === f.account && g.firstMet && g.devices.includes(d) && g.publishedSeq < f.seq && knew > g.seq))
          out.push(`${f.inviter}/${f.device.slice(0, 6)}'s invite to ${f.space} authorizes ${d.slice(0, 6)}, which was not vouched for it`);
      }
    }
    this.factsSeen = facts.length;
    if (this.world.policy === "inviters") this.noteKnown();
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

    if (this.world.policy === "inviters") out.push(...this.checkStanding(i, before));

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
        // A pin taken from an own invite record is copied, like pairing; the
        // standing checks cover it.
        const adopted = [...st.accepted.values()].some((a) => a.binding.account === account && a.evidence.startsWith("invited by"));
        if (before && !knewBefore && knows && !adopted && i.imports === before.imports) {
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

  private checkStanding(i: Installation, before: Snap | undefined): string[] {
    const w = this.world;
    const st = i.trust.state;
    const out: string[] = [];
    for (const [id, a] of st.accepted) {
      if (a.binding.account === i.did || a.evidence === "re-enrolled") continue;
      const h = st.fcHolds.get(id);
      if (!h) {
        out.push(`accepted ${label(a.binding)} without starting its first-contact hold`);
        continue;
      }
      const appeared = w.provenance.publishedAt.get(a.binding.device.deviceId);
      if (appeared !== undefined && h.credited > w.t - appeared + EPS)
        out.push(`first-contact hold for ${label(a.binding)} credited ${h.credited.toFixed(1)}h, more than the ${(w.t - appeared).toFixed(1)}h since it appeared`);
      const old = before?.fc.get(id);
      if (old !== undefined && h.credited < old - EPS) out.push(`first-contact credit for ${label(a.binding)} fell`);
      if (old !== undefined && before!.revoked.has(id) && h.credited > old + EPS) out.push(`first-contact hold for revoked ${label(a.binding)} kept crediting`);
    }
    // A vouch comes only from an invite or capture record, by this account,
    // made when the inviting installation first met the account and naming
    // the device, and reaches only installations that first knew the account
    // no earlier than that record was made.
    const since = this.knownSince.get(i.id);
    for (const id of st.vouched.keys()) {
      if (before?.vouched.has(id)) continue;
      const b = st.accepted.get(id)?.binding;
      if (!b) {
        out.push(`vouched for ${id.slice(0, 8)} without accepting it`);
        continue;
      }
      const knew = since?.get(b.account) ?? Infinity;
      if (!w.provenance.invites.some((v) => v.firstMet && v.inviter === i.did && v.account === b.account && v.devices.includes(b.device.deviceId) && knew > v.seq))
        out.push(`vouched for ${label(b)} with no invite that first met ${b.account} before this installation knew it`);
    }
    // An admitted space comes only from a published record that admitted the account.
    for (const [account, spaces] of st.admitted)
      for (const space of spaces) {
        if (before?.admitted.has(`${account}|${space}`)) continue;
        if (!w.provenance.invites.some((v) => v.admits && v.inviter === i.did && v.account === account && v.space === space))
          out.push(`counts ${account} as admitted to ${space} with no invite record that admitted it`);
      }
    // An authorization traces to a published own record for that space
    // naming the binding, which this installation holds as vouched.
    for (const [space, ids] of st.authorized)
      for (const id of ids) {
        if (before?.authorized.has(`${space}|${id}`)) continue;
        const b = st.accepted.get(id)?.binding;
        if (!b || !st.vouched.has(id)) out.push(`authorized ${b ? label(b) : id.slice(0, 8)} in ${space} without holding it as vouched`);
        else if (!w.provenance.invites.some((v) => v.inviter === i.did && v.space === space && v.authorizes.includes(b.device.deviceId)))
          out.push(`authorized ${label(b)} in ${space} with no record of its account authorizing it there`);
      }
    // New standing has a basis in this installation's own state.
    for (const space of this.spaces())
      for (const [id, a] of st.accepted) {
        if (before?.standing.has(`${space}|${id}`) || !i.trust.standing(a.binding, space)) continue;
        if (!this.justified(i, id, space, new Set()))
          out.push(`standing for ${label(a.binding)} in ${space} without an authorizing record there, an approval with standing, or an elapsed hold`);
      }
    return out;
  }

  /** Standing, restated: own, re-enrolled, an elapsed first-contact hold,
   * an authorization in this space (checked above), or an approval in this
   * installation's verified view by an accepted signer with standing here. */
  private justified(i: Installation, id: string, space: string, seen: Set<string>): boolean {
    if (seen.has(id)) return false;
    seen.add(id);
    const st = i.trust.state;
    const a = st.accepted.get(id);
    if (!a) return false;
    if (a.binding.account === i.did || a.evidence === "re-enrolled") return true;
    if ((st.fcHolds.get(id)?.credited ?? 0) >= REENROLL_HOLD - EPS) return true;
    if (st.authorized.get(space)?.has(id)) return true;
    const aps = st.views.get(a.binding.account)?.approvals ?? [];
    return aps.some((ap) => bindingId(ap.target) === id && this.justified(i, bindingId(ap.signer), space, new Set(seen)));
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
