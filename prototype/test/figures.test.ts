// Every UX figure's panels must match protocol state: a figure that shows a
// notice, hold, or lock state the protocol no longer produces fails here.

import { figures } from "../src/ux/figures";
import { worldAt } from "../src/ux/figure";

describe.each(figures.map((f) => [f.id, f] as const))("%s", (_id, figure) => {
  it("every panel's expectations hold", () => {
    const cache = new Map();
    const failures: string[] = [];
    figure.panels.forEach((p, n) => {
      const [w, c] = worldAt(figure, p.at, cache);
      for (const ch of p.expect?.(w, c) ?? []) if (!ch.ok) failures.push(`panel ${n + 1} (${p.label}): ${ch.label}`);
    });
    expect(failures).toEqual([]);
  });
});
