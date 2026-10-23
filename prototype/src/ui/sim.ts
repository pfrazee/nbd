// UI store: one simulation (a scenario Run, possibly continued by hand) that
// React components subscribe to. Every mutation goes through act(), which
// wraps it with the invariant monitor and bumps the version.

import { useSyncExternalStore } from "react";
import { Run, type Scenario, type StepResult } from "../sim/scenario";
import { scenarios } from "../sim/scenarios";
import type { World } from "../world/world";

const sandbox: Scenario = {
  id: "sandbox",
  title: "Sandbox",
  summary: "An empty world. Add accounts and devices, then try things.",
  steps: [],
};

export class Sim {
  run: Run;
  version = 0;
  actionLog: { at: number; text: string; violations: string[] }[] = [];
  private listeners = new Set<() => void>();

  constructor(scenario: Scenario = sandbox) {
    this.run = new Run(scenario);
  }

  get world(): World {
    return this.run.world;
  }

  get scenarios(): Scenario[] {
    return [sandbox, ...scenarios];
  }

  load(id: string, steps = 0): void {
    const s = this.scenarios.find((x) => x.id === id) ?? sandbox;
    this.run = new Run(s);
    this.actionLog = [];
    for (let i = 0; i < steps && !this.run.done; i++) this.run.step();
    this.syncUrl();
    this.bump();
  }

  next(): StepResult | null {
    if (this.run.done) return null;
    const r = this.run.step();
    this.syncUrl();
    this.bump();
    return r;
  }

  /** Apply a hand-made action, checking invariants around it. */
  act(text: string, fn: (w: World) => void): void {
    this.run.monitor.before();
    try {
      fn(this.world);
    } catch (e) {
      this.world.note(`failed: ${text}: ${(e as Error).message}`);
    }
    const violations = this.run.monitor.after();
    this.actionLog.push({ at: this.world.t, text, violations });
    this.bump();
  }

  subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };

  private bump(): void {
    this.version++;
    for (const l of this.listeners) l();
  }

  private syncUrl(): void {
    if (typeof window === "undefined") return;
    const u = new URL(window.location.href);
    u.searchParams.set("scenario", this.run.scenario.id);
    u.searchParams.set("step", String(this.run.next));
    window.history.replaceState(null, "", u);
  }
}

export const sim = new Sim();

if (typeof window !== "undefined") {
  const p = new URLSearchParams(window.location.search);
  const id = p.get("scenario");
  if (id) sim.load(id, Number(p.get("step") ?? 0));
}

/** Re-render on every simulation change. */
export function useSim(): Sim {
  useSyncExternalStore(sim.subscribe, () => sim.version);
  return sim;
}
