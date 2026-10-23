// Grant publication (audit.md#publication): each issuance keeps its exact
// signed grant and evidence bytes and moves through prepared,
// outcome-unknown, acknowledged, or stopped. Retries resend the same bytes
// at the same identity; an interrupted write is reconciled by reading the
// repo back, never assumed to have failed.

import type { Binding, Evidence, SpaceKeyGrant } from "./types";

export type IssuanceState = "prepared" | "outcome-unknown" | "acknowledged" | "stopped";

export type Issuance = {
  recipient: Binding;
  grant: SpaceKeyGrant;
  evidence: Evidence;
  grantKey: string; // record key of the grant
  evidenceKey: string; // record key of the evidence
  evidenceUp: boolean; // evidence bytes confirmed in the repo
  /** Host revisions the evidence records; a change stops the issuance. */
  basis: { config: number; issuer: number; recipient: number };
  state: IssuanceState;
  history: string[];
};

export function move(i: Issuance, state: IssuanceState, why: string): void {
  i.state = state;
  i.history.push(`${state}: ${why}`);
}
