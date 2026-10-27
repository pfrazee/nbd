// Goal-level check (goals in the top-level README.md): every grant from an honest
// installation to a device an attacker controls must be explained by a path
// the goals permit. It judges against the world's ground truth (who controls
// each device, when it appeared, which keys were copied), not the clients'
// own reasoning, so a client bug that discloses early shows up here even if
// the client believes it acted correctly.
//
// Permitted paths, for issuer I, attacker device X of account A:
// - First contact: I first knew A no earlier than X appeared (non-goal 1).
//   Under the inviters policy (device-enrollment.md#grant-standing) only one first contact
//   excuses a grant: an invite or capture record of I's account for this
//   space authorizes X or an approval ancestor D of X, and D or an approval
//   ancestor of D appeared before I first knew A, so I met it as a first
//   contact rather than a reset. Every other first contact must wait out a
//   hold.
// - Elapsed hold: X appeared at least REENROLL_HOLD ago (goal 3).
// - Compromised signer: a compromised key approved X while A still had a
//   device the attacker does not control, so it was not a full reset. A
//   compromised or removed device's approval passes every check (goal 2 and
//   the revoked-signer gap); own-account notices surface it.
// - Chain: a live attacker device that I already accepted approved X.
//
// Separately, for any recipient: an honest issuer never grants to a device
// its own view shows removed (goal 4).

import type { Installation } from "../protocol/installation";
import { ref } from "../protocol/encoding";
import { recordsIn } from "../protocol/repo";
import { REENROLL_HOLD } from "../protocol/trust";
import { type Binding, COL, type SpaceKeyGrant, asCbor, bindingId, hasStanding } from "../protocol/types";
import type { World } from "../world/world";

const EPS = 1e-9;

export class DisclosureCheck {
  private judged = new Set<string>();
  /** installation ID -> account -> event sequence when it first knew the account. */
  private firstKnown = new Map<string, Map<string, number>>();

  constructor(private readonly world: World) {}

  /** Call before every step: grants that already exist belong to earlier
   * steps and are judged only against the state they were made in. */
  begin(): void {
    for (const [key] of this.grants()) this.judged.add(key);
    this.observe();
  }

  private *grants(): Generator<[string, SpaceKeyGrant]> {
    for (const pds of this.world.pdses.values())
      for (const repo of pds.repos.values()) {
        if (!repo.name.includes("|")) continue;
        for (const [, v] of recordsIn(repo.latest(), COL.grant)) {
          const g = (v as { value: SpaceKeyGrant }).value;
          yield [ref(asCbor(g)), g];
        }
      }
  }

  /** Record which accounts each installation knows, so knowledge that
   * predates a step is never mistaken for first contact. */
  private observe(): void {
    const w = this.world;
    const now = w.tick();
    for (const i of w.installations.values()) {
      const m = this.firstKnown.get(i.id) ?? new Map<string, number>();
      for (const a of i.trust.state.accepted.values()) if (!m.has(a.binding.account)) m.set(a.binding.account, now);
      this.firstKnown.set(i.id, m);
    }
  }

  /** Call after every step: judge new grants, then record new contacts. */
  check(): string[] {
    const out: string[] = [];
    for (const [key, g] of this.grants()) {
      if (this.judged.has(key)) continue;
      this.judged.add(key);
      const why = this.judge(g);
      if (why) out.push(why);
    }
    this.observe();
    return out;
  }

  private judge(g: SpaceKeyGrant): string | null {
    const w = this.world;
    const p = w.provenance;
    const x = g.recipient.deviceId;
    const issuer = [...w.installations.values()].find((i) => i.binding.device.deviceId === g.issuer.deviceId);
    if (!issuer || p.attacker.has(g.issuer.deviceId)) return null; // attackers may share among themselves
    const view = issuer.trust.state.views.get(g.recipient.account);
    const accepted = [...issuer.trust.state.accepted.values()].find((a) => a.binding.account === g.recipient.account && a.binding.device.deviceId === x);
    if (view && accepted && view.rev >= (accepted.rev ?? 0) && view.present.get(x) === undefined)
      return `${issuer.id} granted to ${g.recipient.account.slice(8)}/${x.slice(0, 6)}, which its own view shows removed`;
    if (!p.attacker.has(x)) return null; // the rest concerns attacker devices
    const account = g.recipient.account;
    const appeared = p.publishedAt.get(x) ?? w.t;
    const appearedSeq = p.publishedSeq.get(x) ?? 0;
    const knew = this.firstKnown.get(issuer.id)?.get(account) ?? Infinity;
    const who = `${issuer.id} granted to attacker device ${account.slice(8)}/${x.slice(0, 6)}`;

    if (hasStanding(w.policy)) {
      if (this.authorized(issuer, g.space, account, x, knew)) return null; // the inviter's first contact
    } else if (knew > appearedSeq) return null; // first contact
    if (w.t - appeared >= REENROLL_HOLD - EPS) return null; // a hold could have elapsed
    const approvals = p.approvals.filter((a) => a.target === x);
    if (approvals.some((a) => a.compromised && a.standing)) return null; // compromised signer, not a reset
    if (approvals.some((a) => p.attacker.has(a.signer) && this.liveAt(issuer, account, a.signer))) return null; // chain
    if (hasStanding(w.policy)) return `${who} in ${g.space} ${(w.t - appeared).toFixed(1)}h after it appeared, with no record authorizing it there`;
    return `${who} ${(w.t - appeared).toFixed(1)}h after it appeared, though it already knew ${account.slice(8)}`;
  }

  /** A record of I's account for `space` authorizes X or an approval
   * ancestor D of X, and D or an approval ancestor of D appeared before I
   * first knew the account: it is in I's first-contact lineage, not a reset. */
  private authorized(i: Installation, space: string, account: string, x: string, knew: number): boolean {
    const facts = this.world.provenance.invites.filter((v) => v.inviter === i.did && v.account === account && v.space === space);
    const seq = this.world.provenance.publishedSeq;
    return [...approvalAncestors(this.world, x)].some((d) => facts.some((v) => v.authorizes.includes(d))
      && [...approvalAncestors(this.world, d)].some((m) => (seq.get(m) ?? Infinity) < knew));
  }

  private liveAt(i: Installation, account: string, deviceId: string): boolean {
    const b: Binding | undefined = [...i.trust.state.accepted.values()].map((a) => a.binding)
      .find((x) => x.account === account && x.device.deviceId === deviceId);
    return !!b && i.trust.isAccepted(b) && !i.trust.state.revoked.has(bindingId(b));
  }
}

/** Device X and every device whose approval chain reaches it, by ground truth. */
export function approvalAncestors(world: World, x: string): Set<string> {
  const out = new Set([x]);
  for (let added = true; added; ) {
    added = false;
    for (const a of world.provenance.approvals)
      if (out.has(a.target) && !out.has(a.signer)) {
        out.add(a.signer);
        added = true;
      }
  }
  return out;
}
