import { walk } from "../src/sim/fuzz";

const WALKS = Number(process.env.PEEP_WALKS ?? 20);
const STEPS = Number(process.env.PEEP_STEPS ?? 30);

describe.each([
  ["shared view", true],
  ["lag, forged views, offline, backups", false],
] as const)("random walks: %s", (_label, shared) => {
  it(`keeps every invariant over ${WALKS} walks of ${STEPS} steps`, () => {
    for (let s = 0; s < WALKS; s++) {
      const r = walk(`walk-${shared ? "s" : "a"}-${s}`, STEPS, shared);
      if (r.failure) {
        const trace = r.actions.map((a) => `  ${JSON.stringify(a)}`).join("\n");
        expect.fail(`seed walk-${shared ? "s" : "a"}-${s}: ${r.failure}\n${trace}`);
      }
    }
  }, 600_000);
});
