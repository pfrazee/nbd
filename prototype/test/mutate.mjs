// Mutation check for the prototype: break one trust rule at a time and see
// whether the random walks (and, with --all, every test) notice.
// Run from prototype/: node test/mutate.mjs [--all] [name filter]
// MISSED means nothing notices that rule being broken.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const TRUST = "src/protocol/trust.ts";
const CLIENT = "src/protocol/installation.ts";
const GRANTS = "src/protocol/grants.ts";
const RELAY = "src/world/relay.ts";
// name: [from, to] in trust.ts, or [file, from, to].
const MUTATIONS = {
  "approvals during re-enrollment": ["if (this.live(account).length === 0) return; // re-enrollment: only the hold accepts", "// guard removed"],
  "no hold": ["if (held.credited >= REENROLL_HOLD) {", "if (true) {"],
  "hold not bound to candidate": ["if (!held || held.candidate.join() !== key.join()) {", "if (!held) {"],
  "first use for known accounts": ["    if (!this.knew(account)) {\n      if (cand)", "    if (true) {\n      if (cand)"],
  "roots ignored when present": ["    if (!starts.length) {\n      const nodes", "    {\n      const nodes"],
  "approvals need an unrevoked signer": ["if (st.accepted.has(bindingId(ap.signer)) && !st.accepted.has(tid)) {", "if (st.accepted.has(bindingId(ap.signer)) && !st.revoked.has(bindingId(ap.signer)) && !st.accepted.has(tid)) {"],
  "deleted path targets stay usable": ["if (!this.presentBinding(account, ap.target)) st.revoked.set(tid, ap.target);", ""],
  "revoked records join first use": ["const present = [...view.present.values()].filter((b) => !this.state.revoked.has(bindingId(b)));", "const present = [...view.present.values()];"],
  "rollback accepted": ["if (rev < prev.rev) return false; // rollback: refuse", "// rollback allowed"],
  "revocation on stale snapshots": ["if (viewRev < (st.accepted.get(id)?.rev ?? 0)) continue; // snapshot predates the binding", ""],
  "backward clocks credit time": ["h.credited += Math.max(0, now - h.checkpoint);", "h.credited += Math.abs(now - h.checkpoint);"],
  "imports merge any candidate": ["else if (mine.candidate.join() === h.candidate.join()) mine.credited", "else mine.credited"],
  "holds kept with a live binding": ["if (this.live(account).length) st.holds.delete(account);", "if (false) st.holds.delete(account);"],
  "lazy pinning by default": [CLIENT, 'pinning: "eager" | "lazy" = "eager";', 'pinning: "eager" | "lazy" = "lazy";'],
  "archived keys issue grants": [CLIENT, "if (sp.key && !sp.archived) {", "if (sp.key) {"],
  "publication ignores lost authority": [CLIENT, 'if (d.result !== "OK") {\n      move(iss, "stopped"', 'if (false) {\n      move(iss, "stopped"'],
  "host alarm freezes membership": [CLIENT, "if (tampered) this.trust.raise(", "if (tampered) return void this.trust.raise("],
  "start-over quiets every grant": ["    if (!so?.list?.has(bindingId(b))) return false;", "    if (so) return true;"],
  "start-over list never closes": ["} else if (!(so && !so.done && so.list!.has(id))) {", "} else if (!(so && so.list!.has(id))) {"],
  // The inviters policy (device-enrollment.md#grant-standing).
  "inviters: grants ignore standing": [GRANTS, "if (!basis) return fail(", "if (false) return fail("],
  "inviters: a new invite authorizes only what it first met": [CLIENT, "const authorizes = live.filter((b) => this.trust.inLineage(b));", "const authorizes = met;"],
  "inviters: a later pin extends older admissions": ["if (st.authorized.get(space)?.has(id)) return \"authorized\";", "if (this.inLineage(a.binding) && st.admitted.get(a.binding.account)?.has(space)) return \"authorized\";"],
  "inviters: re-enrolled devices join the lineage": ["for (const b of cand) st.accepted.set(bindingId(b), { binding: b, evidence: \"re-enrolled\" });", "for (const b of cand) { st.accepted.set(bindingId(b), { binding: b, evidence: \"re-enrolled\" }); st.lineage.add(bindingId(b)); }"],
  "inviters: first use doesn't join the lineage": ["          this.startFirstContactHold(b);\n          st.lineage.add(bindingId(b));\n", "          this.startFirstContactHold(b);\n"],
  "inviters: import ends a hold": ["if (b && !knew.has(b.account)) st.lineage.add(id);", "if (b) st.lineage.add(id);"],
  "inviters: invite records override pins": ["      } else if (!this.inLineage(b)) continue;\n", "      }\n"],
  "inviters: hold keyed to account instead of binding": ["const fcKey = (b: Binding): string => bindingId(b);", "const fcKey = (b: Binding): string => b.account;"],
  "inviters: approved devices start no hold": ["            this.startFirstContactHold(ap.target);\n", ""],
  "inviters: removal erases credit": ["if (!this.state.revoked.has(id)) h.credited += Math.max(0, now - h.checkpoint);", "if (!this.state.revoked.has(id)) h.credited += Math.max(0, now - h.checkpoint); else h.credited = 0;"],
  "inviters: revoked bindings keep crediting": ["if (!this.state.revoked.has(id)) h.credited += Math.max(0, now - h.checkpoint);", "h.credited += Math.max(0, now - h.checkpoint);"],
  "inviters: removals observed before crediting": [CLIENT, "      this.trust.tick();\n      this.flushInvites();", "      this.flushInvites();"],
  "inviters: invite published for an existing member": [CLIENT, "    if (this.net.host.membership(space, account)?.eligible) return false;\n", ""],
  "inviters: a retry re-derives the record": [CLIENT, "const { record, rkey } = e;", "const { record, rkey } = e === current ? e : this.prepareInvite(e.space, e.account);"],
  "inviters: pending invites never expire": [CLIENT, "      if (p.credited >= PENDING_INVITE_TTL) continue; // expired: an ordinary first contact\n", ""],
  "inviters: a re-invite prepares a second record": [CLIENT, "    if (unsent) {", "    if (false) {"],
  "inviters: abandon keeps the pending state": [CLIENT, "          this.trust.abandonPending(rkey);\n", ""],
  "inviters: import restores pending": ["      // Pending invites never transfer; abandonments do.\n", "      for (const [k, p] of other.pending) st.pending.set(k, { ...p, checkpoint: now });\n"],
  "inviters: capture skips the published check": [CLIENT, "        if (!this.ownSpaceRecords(e.space, COL.invite).some(([k]) => k === record.captures)) {", "        if (false) {"],
  "inviters: adoption ignores approval chains": ["      } else if (!this.inLineage(b)) continue;", "      } else if (!st.lineage.has(bindingId(b))) continue;"],
  "inviters: lineage ignores approval chains": ["id && !seen.has(id); id = st.approvers.get(id)) {", "id && !seen.has(id); id = undefined) {"],
  // The witness policy (proposal-reliable-detection.md), one per rule.
  "witness: accept on a PDS-served commit": [CLIENT, "    if (vouch.status === \"unknown\" && rev > (this.trust.state.views.get(did)?.rev ?? 0)) {\n      this.mon.incomplete.add(did);", "    if (vouch.status === \"unknown\" && rev > (this.trust.state.views.get(did)?.rev ?? 0)) {\n      this.trust.observe(did, snap);"],
  "witness: any witness trusted": [CLIENT, "const w = this.net.witness?.(this.id) ?? null;", "const w = [this.net.witness?.(this.id) ?? null, ...(this.net.otherWitnesses?.(this.id) ?? [])].filter((x) => x !== null).sort((a, b) => (b!.latest(this.id, did)?.snap.commit.rev ?? 0) - (a!.latest(this.id, did)?.snap.commit.rev ?? 0))[0] ?? null;"],
  "witness: latest-only watching": [CLIENT, "return es; // own: every entry", "return [...es.filter((e) => e.kind === \"gap\"), ...es.filter((e) => e.kind === \"state\").slice(-1)];"],
  "witness: snapshot skipping": [CLIENT, "return es; // pinned: every entry", "return es.filter((e) => e.kind === \"state\").slice(-1);"],
  "witness: gap erased on resync": [RELAY, "private readonly eraseGapsOnResync = false;", "private readonly eraseGapsOnResync = true;"],
  "witness: deadline reset at check completion": [CLIENT, "this.mon.coverage = { base: frontierAge, mono: sent };", "this.mon.coverage = { base: 0, mono: this.net.now() };"],
  "witness: restore from now": [CLIENT, "for (const [d, c] of s.witness.cursors) this.mon.cursors.set(d, c);", "for (const [d, c] of s.witness.cursors) this.mon.cursors.set(d, d === this.did ? Number.MAX_SAFE_INTEGER : c);"],
  "witness: ack suppresses liveness": [CLIENT, "if (age <= LIVENESS_LIMIT) return null;", "if (age <= LIVENESS_LIMIT || this.mon.gaps.some((g) => g.acked)) return null;"],
  "witness: ack suppresses later gaps": [CLIENT, "if (!this.mon.gaps.some((x) => x.key === key)) this.mon.gaps.push", "if (!this.mon.gaps.some((x) => x.key === key || x.acked)) this.mon.gaps.push"],
  "witness: a gap holds the frontier": [CLIENT, "< this.coverageAge()) this.mon.coverage", "< this.coverageAge() && !this.mon.gaps.some((g) => !g.acked)) this.mon.coverage"],
  "witness: fresh enrollment presents only current bindings": [CLIENT, "      this.trust.notice(`history:${id}`, \"history-binding\",", "      if (false) this.trust.notice(`history:${id}`, \"history-binding\","],
  "witness: restart ignores downtime": [CLIENT, "{ base: cp.age + d, mono: this.net.now() }", "{ base: cp.age, mono: this.net.now() }"],
  "witness: backward clock trusted across restart": [CLIENT, "cp && d >= 0 && Number.isFinite(cp.age)", "cp && Number.isFinite(cp.age)"],
  "witness: stream gaps ignored": [RELAY, "if (this.relay.outdated(this.cursor)) {", "if (false) {"],
  "witness: result not checked against the commit root": [RELAY, "if (next && snapshotData(next) === e.commit.data && invert(", "if (next && invert("],
  // Witness progress by relay event time, and cursors as repo revisions.
  "witness: frontier from delivery time, not relay time": [RELAY, "this.frontier = Math.max(this.frontier, this.relay.networkTime(this.id, by), newest);", "this.frontier = Math.max(this.frontier, by, newest);"],
  "witness: a pending fetch doesn't hold the frontier": [RELAY, "return p ? Math.min(this.frontier, p.e.time) : this.frontier;", "return this.frontier;"],
  "witness: clock skew fault ignored": [RELAY, "if (this.clockFault(did)) return Infinity;", ""],
  "witness: witness-local cursors": [RELAY, "return h.kind === \"state\" ? h.rev : h.toRev; // a repo revision", "return h.local;"],
  // PDS-served commits the relay never published, and revision checks.
  "witness rev: alarm on any unreported lower revision": [RELAY, "if (es.some((h) => h.kind === \"gap\" && h !== a.open && h.fromRev <= rev && rev <= h.toRev)) return { status: \"gap\" };", "if (es.some((h) => h.kind === \"state\" && h.rev > rev)) return { status: \"unpublished\", below: 0, above: rev + 1 };"],
  "witness rev: no alarm between consecutive reconstructions": [RELAY, "return { status: \"unpublished\", below: lo.rev, belowData: lo.snap.commit.data, above: hi.rev };", "return { status: \"unknown\" };"],
  "witness rev: a #sync counts as consecutive": [RELAY, "hi.kind === \"state\" && hi.via === \"commit\" && lo.rev", "hi.kind === \"state\" && lo.rev"],
  "witness rev: no-change commit not exempt": [CLIENT, "if (vouch.status === \"unpublished\" && snap.commit.data !== vouch.belowData) {", "if (vouch.status === \"unpublished\") {"],
  "witness rev: a served gap is INCOMPLETE": [CLIENT, "if (vouch.status === \"unknown\" && rev > (this.trust.state.views.get(did)?.rev ?? 0)) {", "if ((vouch.status === \"unknown\" || vouch.status === \"gap\") && rev > (this.trust.state.views.get(did)?.rev ?? 0)) {"],
  "witness rev: dropped commit reconstructed by fetch": [RELAY, "      if (a.state) {\n        // The commit must follow", "      if (a.state && e.prevData === snapshotData(a.state.records)) {\n        // The commit must follow"],
  "witness rev: future revision accepted into history": [RELAY, "if (beyondAllowance(e.commit.rev, e.time)) return this.future(a, e);", ""],
  "witness rev: future revision raises the latest revision": [RELAY, "    a.state = null;\n    if (a.open) return;", "    a.state = null;\n    a.lastRev = Math.max(a.lastRev, e.commit.rev);\n    if (a.open) return;"],
  "witness rev: future revision alarms": [RELAY, "    this.push(a, gap);\n    a.open = gap;", "    this.push(a, gap);\n    a.open = gap;\n    a.integrity.push({ id: gap.id, seq: e.seq, rev: e.commit.rev, after: a.lastRev, reason: gap.reason });"],
  "witness rev: non-increasing revision not checked": [RELAY, "if (e.commit.rev <= a.lastRev) return this.backward(a, e);", ""],
  // Astra's second review, and the model's follow-up: stream-gap intervals
  // and cursors, reference-relay timestamps, and time in transit.
  "witness: stream gap ends at the resync revision": [RELAY, "const toRev = Math.max(revAt(resumedAt + REV_ALLOWANCE), resync);", "const toRev = resync;"],
  "witness: cursor moves to a stream gap's end": [RELAY, "return h.resync; // past a stream gap", "return h.toRev; // past a stream gap"],
  "witness: stream gap served only after the cursor": [RELAY, "return this.position(h) > start || (h.kind === \"gap\" && h.stream && h.toRev >= start);", "return this.position(h) > start;"],
  "witness: resync below the revision held raises no alarm": [RELAY, "          if (latest && latest.commit.rev < a.lastRev)\n            a.integrity.push(", "          if (false)\n            a.integrity.push("],
  "witness: relay refreshes time on replay": [RELAY, "return this.timeOnDelivery;", "return true;"],
  "witness: coverage aged from response processing": [CLIENT, "if (frontierAge + Math.max(0, this.net.now() - sent) < this.coverageAge()) this.mon.coverage = { base: frontierAge, mono: sent };", "if (frontierAge < this.coverageAge()) this.mon.coverage = { base: frontierAge, mono: this.net.now() };"],
  "witness: multi-page answer aged from the last page's request": [CLIENT, "first = req.first;\n        age = req.age!;", "first = req.sent;\n        age = req.age!;"],
  "witness: paged answer takes the last page's frontier age": [CLIENT, "if (req.age === null) req.age = r.frontierAge;", "req.age = r.frontierAge;"],
  "witness: a late answer moves coverage back": [CLIENT, "if (frontierAge + Math.max(0, this.net.now() - sent) < this.coverageAge()) this.mon.coverage", "if (true) this.mon.coverage"],
  "witness: an answer from before a restart accepted": [CLIENT, "if (r.req !== undefined && r.req !== req.id) continue; // not this request's answer: discarded", ""],
  "witness rev: integrity alarms only from history after the cursor": [CLIENT, "for (const x of r.integrity)", "for (const x of r.integrity.filter((y) => y.rev > (this.mon.cursors.get(did) ?? 0)))"],
};

const all = process.argv.includes("--all");
const only = process.argv.slice(2).find((a) => !a.startsWith("--"));
const originals = new Map([TRUST, CLIENT, GRANTS, RELAY].map((f) => [f, readFileSync(f, "utf8")]));
let missed = 0;
try {
  for (const [name, spec] of Object.entries(MUTATIONS)) {
    if (only && !name.includes(only)) continue;
    const [file, from, to] = spec.length === 3 ? spec : [TRUST, ...spec];
    const original = originals.get(file);
    if (!original.includes(from)) throw new Error(`mutation "${name}" no longer applies`);
    for (const [f, text] of originals) writeFileSync(f, text);
    writeFileSync(file, original.replace(from, to));
    let caught = false;
    try {
      execFileSync("npx", ["vitest", "run", ...(all ? [] : ["test/fuzz.test.ts"])], { stdio: "pipe" });
    } catch {
      caught = true;
    }
    if (!caught) missed++;
    console.log(`${caught ? "CAUGHT" : "MISSED"} ${name}`);
  }
} finally {
  for (const [f, text] of originals) writeFileSync(f, text);
}
process.exit(missed ? 1 : 0);
