// Shared-view traces for the Python model (model/test_traces.py). With
// PEEP_WRITE_TRACES=1 this writes fresh fixtures; otherwise it checks that
// each committed fixture still regenerates identically from its seed, so
// the fixtures cannot drift from the prototype.

import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { type Trace, walk } from "../src/sim/fuzz";

const DIR = join(__dirname, "..", "traces");
const COUNT = Number(process.env.PEEP_TRACES ?? 40);
const STEPS = 30;

function generate(seed: string): Trace {
  const r = walk(seed, STEPS, true);
  if (r.failure || !r.trace) throw new Error(`${seed}: ${r.failure}`);
  return { ...r.trace, actions: r.actions };
}

describe("shared-view traces", () => {
  if (process.env.PEEP_WRITE_TRACES) {
    it("writes fixtures", () => {
      if (!existsSync(DIR)) mkdirSync(DIR);
      for (let i = 0; i < COUNT; i++) {
        const seed = `trace-${i}`;
        writeFileSync(join(DIR, `${seed}.json`), JSON.stringify(generate(seed)) + "\n");
      }
    }, 600_000);
  }

  it("committed fixtures regenerate identically", () => {
    const files = existsSync(DIR) ? readdirSync(DIR).filter((f) => f.endsWith(".json")) : [];
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const saved = JSON.parse(readFileSync(join(DIR, f), "utf8")) as Trace;
      expect(JSON.parse(JSON.stringify(generate(saved.seed))), f).toEqual(saved);
    }
  }, 600_000);
});
