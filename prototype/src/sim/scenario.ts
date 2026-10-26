// Scenarios: narrated steps that drive a World, with expectations checked
// after each step. The same definitions run headless in Vitest and play
// step by step in the UI's story mode.

import type { Installation } from "../protocol/installation";
import type { Policy } from "../protocol/types";
import { type StolenKeys, World } from "../world/world";
import { InvariantMonitor } from "./invariants";

export type Ctx = {
  inst: Record<string, Installation>;
  space: Record<string, string>;
  did: Record<string, string>;
  stolen: Record<string, StolenKeys>;
};
export type Check = { label: string; ok: boolean; detail?: string };
export type Step = {
  title: string;
  narration: string;
  run: (w: World, c: Ctx) => void;
  expect?: (w: World, c: Ctx) => Check[];
};
/** `policy`: the grant rule the scenario's world follows (default baseline). */
export type Scenario = { id: string; title: string; summary: string; steps: Step[]; policy?: Policy };

export function check(label: string, ok: boolean, detail?: string): Check {
  return { label, ok, detail };
}

export type StepResult = { step: Step; checks: Check[]; violations: string[] };

/** A running scenario: one World, one context, and the invariant monitor. */
export class Run {
  readonly world: World;
  readonly ctx: Ctx = { inst: {}, space: {}, did: {}, stolen: {} };
  readonly monitor: InvariantMonitor;
  readonly results: StepResult[] = [];
  next = 0;

  constructor(readonly scenario: Scenario, seed = scenario.id, policy = scenario.policy) {
    this.world = new World(seed, { policy });
    this.monitor = new InvariantMonitor(this.world);
  }

  get done(): boolean {
    return this.next >= this.scenario.steps.length;
  }

  step(): StepResult {
    const step = this.scenario.steps[this.next++];
    this.monitor.before();
    step.run(this.world, this.ctx);
    const violations = this.monitor.after();
    const checks = step.expect?.(this.world, this.ctx) ?? [];
    const r = { step, checks, violations };
    this.results.push(r);
    return r;
  }

  runAll(): StepResult[] {
    while (!this.done) this.step();
    return this.results;
  }
}
