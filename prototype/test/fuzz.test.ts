import { walk } from "../src/sim/fuzz";

const WALKS = Number(process.env.NBD_WALKS ?? 20);
const STEPS = Number(process.env.NBD_STEPS ?? 30);

describe.each([
  ["shared view", true, "baseline", "s"],
  ["lag, forged views, offline, backups", false, "baseline", "a"],
  ["inviters, shared view", true, "inviters", "is"],
  ["inviters, lag, forged views, offline, backups", false, "inviters", "ia"],
  ["witness, shared view", true, "witness", "ws"],
  ["witness, malicious PDSes, witness outages, lag, offline, backups", false, "witness", "wa"],
] as const)("random walks: %s", (_label, shared, policy, tag) => {
  it(`keeps every invariant over ${WALKS} walks of ${STEPS} steps`, () => {
    for (let s = 0; s < WALKS; s++) {
      const r = walk(`walk-${tag}-${s}`, STEPS, shared, policy);
      if (r.failure) {
        const trace = r.actions.map((a) => `  ${JSON.stringify(a)}`).join("\n");
        expect.fail(`seed walk-${tag}-${s}: ${r.failure}\n${trace}`);
      }
    }
  }, 600_000);
});
