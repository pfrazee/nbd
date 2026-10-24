// A figure is a storyboard for one UX flow: a script of world actions and
// panels that each show one device at one point in that script. A panel is
// rendered from a fresh world replayed to its point, so later steps never
// change earlier panels. The same scripts run headless in test/figures.test.ts.

import type { ReactNode } from "react";
import type { Installation } from "../protocol/installation";
import type { Check } from "../sim/scenario";
import { World } from "../world/world";
import type { Mode } from "./copy";

export type FigureCtx = { i: Record<string, Installation>; space: Record<string, string> };
export type Action = (w: World, c: FigureCtx) => void;

export type Panel = {
  label: string; // "Laptop shows a code"
  device: string; // "Alice's laptop"
  at: number; // script steps run before this panel
  view: (w: World, c: FigureCtx) => ReactNode;
  caption: string; // **bold** runs are emphasized
  expect?: (w: World, c: FigureCtx) => Check[];
};

export type Figure = {
  id: string; // image file name, e.g. "relaxed-tofu-adding-a-device"
  mode: Mode;
  number: number | string;
  title: string;
  description: string;
  setup: Action;
  steps: Action[];
  panels: Panel[];
};

/** A fresh world replayed to step `at`, memoized per figure. */
export function worldAt(f: Figure, at: number, cache = new Map<string, [World, FigureCtx]>()): [World, FigureCtx] {
  const key = `${f.id}:${at}`;
  let hit = cache.get(key);
  if (!hit) {
    const w = new World(f.id);
    const c: FigureCtx = { i: {}, space: {} };
    f.setup(w, c);
    for (const step of f.steps.slice(0, at)) step(w, c);
    w.settle();
    hit = [w, c];
    cache.set(key, hit);
  }
  return hit;
}
