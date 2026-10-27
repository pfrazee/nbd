// Goal-level detection check for the Relay-Witnessed Repos proposal
// (proposal-reliable-detection.md, Goal). It judges against the world's
// ground truth, not the clients' reasoning:
//
//   Every device an honest installation accepted for account A that none of
//   A's installations generated, transferred, or approved (an attacker or
//   malicious-PDS device) either appears in, or leaves a gap in, the history
//   A's installation read, and each of A's installations alarmed or warned
//   within 24 hours of the acceptance, or, if it was not running then, when
//   it next ran.
//
// For acceptance by installation I at world time t on the witnessed commit
// with relay sequence s, and each honest installation O of A whose state
// began no later than t (a restored installation inherits its backup's
// start, and counts what its lost predecessor did; a device linked later is
// new, its approver having read that history), the obligation is met by the deadline (t + 24h if O was
// running then, otherwise O's next run) when O
//   (a) alarmed about the device, or presented it (an own-added notice, a
//       fresh-enrollment history notice, a start-over list), or
//   (b) recorded a gap warning whose interval covers s, or
//   (c) showed the liveness warning while its own history was processed
//       only to before s.
// The goal is conditional on an honest reference relay and witness, so
// obligations whose owner's witness or relay a scenario made dishonest are
// skipped. Under a non-witness policy only (a) can apply: that is how the
// comparison scenarios show the baseline missing a case.
//
// It also checks, under the witness policy, that the commit an acceptance
// relied on was reconstructed by the accepting installation's own witness
// with the device in it.

import type { Installation } from "../protocol/installation";
import { LIVENESS_LIMIT } from "../protocol/witness";
import type { World } from "../world/world";

const EPS = 1e-9;

export type Obligation = { key: string; text: string };

export class DetectionCheck {
  private reported = new Set<string>();

  constructor(private readonly world: World) {}

  /** New violations since the last call. */
  check(): string[] {
    const out: string[] = [];
    for (const v of detectionViolations(this.world)) {
      if (this.reported.has(v.key)) continue;
      this.reported.add(v.key);
      out.push(v.text);
    }
    return out;
  }
}

/** Every unmet obligation whose deadline has passed. */
export function detectionViolations(w: World): Obligation[] {
  const p = w.provenance;
  const out: Obligation[] = [];
  const witnessed = w.policy === "witness";
  for (const r of p.accepts) {
    if (!p.attacker.has(r.target) || p.attacker.has(r.device)) continue;
    const short = `${r.account.slice(8)}/${r.target.slice(0, 6)}`;
    if (witnessed) {
      if (r.seq === null) continue; // transferred or adopted: the original acceptance carries it
      const wit = [...w.witnesses.values()].find((x) => x.id === r.witness);
      const entry = wit?.accounts.get(r.account)?.history.find((h) => h.seq === r.seq);
      if (wit && entry && (entry.kind !== "state" || ![...entry.snap.records.keys()].some((k) => k.endsWith(`/${r.target}`))))
        out.push({ key: `basis:${r.inst}:${r.target}`, text: `${r.inst} accepted ${short} on witnessed commit ${r.seq}, which doesn't contain it` });
    }
    const deadline = r.world + LIVENESS_LIMIT;
    for (const o of w.installations.values()) {
      if (o.did !== r.account || p.attacker.has(o.binding.device.deviceId) || o.originOrder > r.order) continue;
      if (witnessed && dishonest(w, o)) continue;
      const due = dueBy(o, deadline, w.t);
      if (due === null || w.t < due - EPS) continue;
      // A restored installation's lost predecessor may already have met it.
      let done = false;
      for (let x: Installation | null = o; x && !done; x = x.predecessor) done = met(x, r.target, r.seq, r.world, due, w.t);
      if (done) continue;
      out.push({
        key: `${r.inst}:${r.target}:${o.id}`,
        text: `${o.id} neither alarmed nor warned within 24h of ${r.inst} accepting ${short}${r.seq !== null ? ` (relay seq ${r.seq})` : ""} at ${r.world.toFixed(1)}h`,
      });
    }
  }
  return out;
}

/** Whether the trust assumptions are broken for `o`: its witness omits
 * commits of its account, or the relay hides its account from that witness. */
function dishonest(w: World, o: Installation): boolean {
  const wit = w.witnesses.get(o.app);
  return !!wit && ((wit.omits.get(o.did)?.size ?? 0) > 0 || !!w.relay?.hideFrom.get(o.did)?.has(wit.id));
}

/** The deadline for `o`: `deadline` if it was running then, otherwise the
 * start of its next run; null if it has not run since. */
function dueBy(o: Installation, deadline: number, now: number): number | null {
  for (let i = 0; i < o.runs.length; i++) {
    const r = o.runs[i];
    const to = i === o.runs.length - 1 && o.running ? now : r.to;
    if (r.from <= deadline + EPS && deadline <= to + EPS) return deadline;
    if (r.from > deadline) return r.from;
  }
  return null;
}

function met(o: Installation, device: string, seq: number | null, accepted: number, due: number, now: number): boolean {
  const st = o.trust.state;
  if (st.alarms.some((a) => a.device === device && (a.world ?? Infinity) <= due + EPS)) return true;
  if (st.notices.some((n) => n.about?.device.deviceId === device && (n.kind === "own-added" || n.kind === "history-binding") && (n.world ?? Infinity) <= due + EPS)) return true;
  if ([...(st.startOver?.list?.values() ?? [])].some((b) => b.device.deviceId === device)) return true;
  if (seq === null) return false;
  if (o.mon.gaps.some((g) => g.fromSeq <= seq && seq <= g.toSeq && g.world <= due + EPS)) return true;
  // Liveness: in a segment where its own history stopped before `seq`, the
  // warning shows once coverage age passes the limit.
  for (let i = 0; i < o.segments.length; i++) {
    const s = o.segments[i];
    if (s.cursor >= seq) continue;
    const last = i + 1 === o.segments.length;
    const end = last ? now : o.segments[i + 1].world;
    const warnAt = s.world + Math.max(0, LIVENESS_LIMIT - s.base);
    // Shown for a positive time after the acceptance, by the deadline.
    if (end > accepted + EPS && (last || warnAt < end - EPS) && warnAt <= due + EPS) return true;
  }
  return false;
}
