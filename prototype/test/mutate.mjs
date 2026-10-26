// Mutation check for the prototype: break one trust rule at a time and see
// whether the random walks (and, with --all, every test) notice.
// Run from prototype/: node test/mutate.mjs [--all] [name filter]
// MISSED means nothing notices that rule being broken.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const TRUST = "src/protocol/trust.ts";
const CLIENT = "src/protocol/installation.ts";
const GRANTS = "src/protocol/grants.ts";
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
  "inviters: a new invite drops earlier vouches": [CLIENT, "const authorizes = [...met, ...live.filter((b) => !met.includes(b) && this.trust.descendsFromVouched(b))];", "const authorizes = [...met];"],
  "inviters: a later vouch extends older admissions": ["if (st.authorized.get(space)?.has(id)) return \"authorized\";", "if (st.vouched.has(id) && st.admitted.get(a.binding.account)?.has(space)) return \"authorized\";"],
  "inviters: known account vouched": [CLIENT, "const met = knew ? [] : live.filter(", "const met = live.filter("],
  "inviters: import ends a hold": ["if (b && !knew.has(b.account)) this.vouch(space, b);", "if (b) this.vouch(space, b);"],
  "inviters: invite records override pins": ["      } else if (!this.descendsFromVouched(b)) continue;\n", "      }\n"],
  "inviters: hold keyed to account instead of binding": ["const fcKey = (b: Binding): string => bindingId(b);", "const fcKey = (b: Binding): string => b.account;"],
  "inviters: approved devices start no hold": ["            this.startFirstContactHold(ap.target);\n", ""],
  "inviters: removal erases credit": ["if (!this.state.revoked.has(id)) h.credited += Math.max(0, now - h.checkpoint);", "if (!this.state.revoked.has(id)) h.credited += Math.max(0, now - h.checkpoint); else h.credited = 0;"],
  "inviters: revoked bindings keep crediting": ["if (!this.state.revoked.has(id)) h.credited += Math.max(0, now - h.checkpoint);", "h.credited += Math.max(0, now - h.checkpoint);"],
  "inviters: removals observed before crediting": [CLIENT, "      this.trust.tick();\n      this.flushInvites();", "      this.flushInvites();"],
  "inviters: invite published for an existing member": [CLIENT, "    if (this.net.host.membership(space, account)?.eligible) return false;\n", ""],
  "inviters: a retry re-derives the record": [CLIENT, "const { record, rkey, vouch } = e;", "const { record, rkey, vouch } = e === current ? e : this.prepareInvite(e.space, e.account);"],
  "inviters: pending invites never expire": [CLIENT, "      if (p.credited >= PENDING_INVITE_TTL) continue; // expired: an ordinary first contact\n", ""],
  "inviters: a re-invite prepares a second record": [CLIENT, "    if (unsent) {", "    if (false) {"],
  "inviters: abandon keeps the pending state": [CLIENT, "          this.trust.abandonPending(rkey);\n", ""],
  "inviters: import restores pending": ["      // Pending invites never transfer; abandonments do.\n", "      for (const [k, p] of other.pending) st.pending.set(k, { ...p, checkpoint: now });\n"],
  "inviters: capture skips the published check": [CLIENT, "        if (!this.ownSpaceRecords(e.space, COL.invite).some(([k]) => k === record.captures)) {", "        if (false) {"],
  "inviters: adoption requires a direct vouch": ["      } else if (!this.descendsFromVouched(b)) continue;", "      } else if (!st.vouched.has(bindingId(b))) continue;"],
  "inviters: vouch on publication": [CLIENT, "    for (const b of met) this.trust.vouch(space, b); // the vouch is saved with the prepared record\n", ""],
  "inviters: authorizes ignores descendants": ["id && !seen.has(id); id = st.approvers.get(id)) {", "id && !seen.has(id); id = undefined) {"],
};

const all = process.argv.includes("--all");
const only = process.argv.slice(2).find((a) => !a.startsWith("--"));
const originals = new Map([TRUST, CLIENT, GRANTS].map((f) => [f, readFileSync(f, "utf8")]));
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
