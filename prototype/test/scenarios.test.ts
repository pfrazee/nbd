import { Run } from "../src/sim/scenario";
import { scenarios } from "../src/sim/scenarios";

describe.each(scenarios.map((s) => [s.title, s] as const))("%s", (_title, scenario) => {
  it("meets every expectation with no invariant violations", () => {
    const failures: string[] = [];
    for (const r of new Run(scenario).runAll()) {
      for (const c of r.checks) if (!c.ok) failures.push(`${r.step.title}: ${c.label}`);
      for (const v of r.violations) failures.push(`${r.step.title}: invariant: ${v}`);
    }
    expect(failures).toEqual([]);
  });
});
