import type { Figure } from "../figure";
import { relaxedFigures } from "./relaxed";
import { tofuFigures } from "./tofu";

export const figures: Figure[] = [...relaxedFigures, ...tofuFigures];
