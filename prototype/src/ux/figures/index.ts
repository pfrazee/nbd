import type { Figure } from "../figure";
import { relaxedFigures } from "./relaxed";
import { paranoidFigures } from "./paranoid";

export const figures: Figure[] = [...relaxedFigures, ...paranoidFigures];
