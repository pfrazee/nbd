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
  // The inviters policy (proposal-inviters.md).
  "inviters: grants ignore standing": [GRANTS, "if (!basis) return fail(", "if (false) return fail("],
  "inviters: vouch scoped account-wide": ["if (st.vouches.get(space)?.has(id)) return \"vouched\";", "if ([...st.vouches.values()].some((v) => v.has(id))) return \"vouched\";"],
  "inviters: known account vouched": [CLIENT, "const met = knew ? [] : live.filter(", "const met = live.filter("],
  "inviters: import ends a hold": ["if (b && !knew.has(b.account)) this.vouch(space, b);", "if (b) this.vouch(space, b);"],
  "inviters: invite records override pins": ["if (!rec.vouched || this.knew(rec.account)) return false;", "if (!rec.vouched) return false;"],
  "inviters: hold keyed to account instead of binding": ["const fcKey = (b: Binding): string => bindingId(b);", "const fcKey = (b: Binding): string => b.account;"],
  "inviters: approved devices start no hold": ["            this.startFirstContactHold(ap.target);\n", ""],
  "inviters: removal erases credit": ["if (!this.state.revoked.has(id)) h.credited += Math.max(0, now - h.checkpoint);", "if (!this.state.revoked.has(id)) h.credited += Math.max(0, now - h.checkpoint); else h.credited = 0;"],
  "inviters: revoked bindings keep crediting": ["if (!this.state.revoked.has(id)) h.credited += Math.max(0, now - h.checkpoint);", "h.credited += Math.max(0, now - h.checkpoint);"],
  "inviters: removals observed before crediting": [CLIENT, "      this.trust.tick();\n      this.adoptOwnInvites();", "      this.adoptOwnInvites();"],
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
