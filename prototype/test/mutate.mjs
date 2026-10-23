// Mutation check for the prototype: break one trust rule at a time and see
// whether the random walks (and, with --all, every test) notice.
// Run from prototype/: node test/mutate.mjs [--all]
// MISSED means nothing notices that rule being broken.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const FILE = "src/protocol/trust.ts";
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
};

const all = process.argv.includes("--all");
const original = readFileSync(FILE, "utf8");
let missed = 0;
try {
  for (const [name, [from, to]] of Object.entries(MUTATIONS)) {
    if (!original.includes(from)) throw new Error(`mutation "${name}" no longer applies`);
    writeFileSync(FILE, original.replace(from, to));
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
  writeFileSync(FILE, original);
}
process.exit(missed ? 1 : 0);
