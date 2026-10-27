// Shared-view traces for the Python model (model/test_traces.py). With
// NBD_WRITE_TRACES=1 this writes fresh fixtures; otherwise it checks that
// each committed fixture still regenerates identically from its seed, so
// the fixtures cannot drift from the prototype. `traces/` follows the
// baseline; `traces-inviters/` the inviters policy (README.md#inviters-traces);
// `traces-witness/` the witness policy (README.md#witness-traces).

import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { type Trace, walk } from "../src/sim/fuzz";
import type { Policy } from "../src/protocol/types";

const COUNT = Number(process.env.NBD_TRACES ?? 40);
const STEPS = 30;

function generate(seed: string, policy: Policy): Trace {
  const r = walk(seed, STEPS, true, policy);
  if (r.failure || !r.trace) throw new Error(`${seed}: ${r.failure}`);
  return { ...r.trace, actions: r.actions };
}

describe.each([
  ["traces", "trace", "baseline"],
  ["traces-inviters", "inviters", "inviters"],
  ["traces-witness", "witness", "witness"],
] as const)("shared-view traces in %s/", (dir, prefix, policy) => {
  const DIR = join(__dirname, "..", dir);

  if (process.env.NBD_WRITE_TRACES) {
    it("writes fixtures", () => {
      if (!existsSync(DIR)) mkdirSync(DIR);
      for (let i = 0; i < COUNT; i++) {
        const seed = `${prefix}-${i}`;
        writeFileSync(join(DIR, `${seed}.json`), JSON.stringify(generate(seed, policy)) + "\n");
      }
    }, 600_000);
  }

  it("committed fixtures regenerate identically", () => {
    const files = existsSync(DIR) ? readdirSync(DIR).filter((f) => f.endsWith(".json")) : [];
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const saved = JSON.parse(readFileSync(join(DIR, f), "utf8")) as Trace;
      expect(JSON.parse(JSON.stringify(generate(saved.seed, saved.policy ?? "baseline"))), f).toEqual(saved);
    }
  }, 600_000);
});
