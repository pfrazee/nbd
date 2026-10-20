# PEEP: Grant Publication and Auditing

The signed [grant](core.md#grant-format) is the audit record. Publishing it in the issuer's own space repo lets an affected account discover substitution through another PDS: if Bob grants to keys forged by Alice's PDS, Alice can obtain Bob's grant and compare its exact selection with her authorization history.

## Evidence

A manifest is `{ version: 1, space, blocks: CID[] }`, with `blocks` a set of exact protocol values. Each referring field determines its block's required type. Issuers MUST include:

- Both parties' exact signed declarations/keys, starting snapshots, and the space-local approval/ancestry used for issuance.
- Configuration, both membership decisions, accepted epoch/request/outcome, rotation context, and required trigger/revocation/cycle evidence.
- Referenced activation manifests and their required blocks, validated as an acyclic graph.

The grant header's declaration, host-state, and epoch references MUST be in its manifest; the package includes the manifest itself. Activation manifests contain proposer authorization and predecessor/context evidence, omitting their own request and the not-yet-accepted epoch. A manifest MUST NOT reference its enclosing grant/request. An earlier authenticated epoch used as a starting point need not recursively import all earlier activation requests.

The starting epoch's committed [history wrap](core.md#backward-history-wrapping) makes the grant an audit record for access to its connected history as well. Publish epoch metadata used for issuance under the same evidence rules; additional predecessor metadata may be fetched lazily from authenticated host history for reading. Missing traversal data is a history-coverage gap, not permission to omit evidence required to validate the starting grant. Recipients MUST record each derived key's starting grant and traversed epoch references. No additional per-recipient grant record is needed for each hop, and earlier grants/evidence remain retained with their original trust decisions.

Stop at retained bindings/starting snapshots. Earlier OOB/approval provenance stays private; every space-specific published block MUST belong to this space. Public revocations have no space. Readers use their own trust/history and may need additional evidence; the bundle does not promise universal verification from scratch.

Issuers MUST publish actual bytes as immutable [evidence records](core.md#records) in the issuer's space repo, readable without the granted key or substituted private key. Batching/shared same-space records are allowed; issuers MUST preserve exact bytes and all referenced blocks. Links back to a withholding source PDS are insufficient. The manifest reference binds this package through the HPKE header and grant signature. Absence of private provenance is not missing required public evidence.

## Publication

Each issuance has immutable grant/evidence bytes and record identity, a durable state (`prepared`, `outcome-unknown`, `acknowledged`, or `stopped`), and retained publication/uncertainty facts. Issuers MUST follow P1–P8. `Ready` means evidence publication is complete and [grant authorization](core.md#grant-authorization) has just returned `OK` using the exact evidence and trust decision recorded for this issuance. Every attempt releasing grant bytes requires `Ready`, including retries and direct forwarding.

| Step | State/event | Required action and next state |
| --- | --- | --- |
| P1 | New issuance | Durably save exact signed grant, evidence, identity, and authorization decision before upload; enter `prepared`. |
| P2 | `prepared`, evidence upload/retry | Upload actual evidence bytes first; resume partial uploads without changing bytes. Remain `prepared` until grant submission. |
| P3 | `prepared`, `Ready` | Persist `outcome-unknown` before uploading the grant at its exact identity. |
| P4 | `outcome-unknown`, result/reconciliation | An authenticated acknowledgment of the exact write or an authenticated read of identical bytes establishes `acknowledged`. Different bytes are an integrity error: enter `stopped`. Absence, timeout, or failed reads leave `outcome-unknown` and exposure uncertain. |
| P5 | `outcome-unknown`, retry | Require `Ready`, then resend only the same grant bytes/identity; remain `outcome-unknown` until P4. Duplicate publication is one grant. |
| P6 | `acknowledged`, direct forwarding | Require `Ready`, then forward the same published record; remain `acknowledged`. Without acknowledgment direct forwarding is forbidden. |
| P7 | Any active state, lost authority/conflict/missing required evidence/changed evidence or trust decision/cancellation | Durably enter `stopped`; release no further grant bytes for this issuance. A new issuance requires new preparation and authorization, not reinterpretation of the old record. |
| P8 | `stopped`, late publication result | Retain new acknowledgment or uncertainty evidence without resuming delivery or erasing earlier outcomes. |

An authenticated integrity error at a prepared record's existing identity also uses P7. On restart, issuers MUST restore these states and MUST NOT assume an interrupted write failed. A previously acknowledged issuance that later stops retains its acknowledgment and exposure facts. Publication acknowledgment proves neither durable availability nor recipient decryption; failure, cancellation, deletion, or absence MUST NOT be treated as proof that released keys were unexposed. Previously published records and uncertain outcomes MUST remain retained after stopping.

## Retention and access

Publishers MUST retain published immutable records and exact supporting evidence indefinitely. Each account MUST keep all its declarations—including superseded snapshots, forks, and resolutions—in its space repo; issuers MUST keep the grants and evidence they used. Publishers MUST preserve these through migration, replacement, conflict resolution, rotation, revocation, and membership changes, and MUST NOT prune referenced evidence.

Permissioned evidence follows normal Spaces access rules. Former members may keep/audit synced copies but have no guaranteed further access, even to grants addressed to them. Retention does not extend authorization or guarantee hosting, availability, completeness, or freshness.

## Archived grants

Historical reading MUST use [grant acceptance](core.md#grant-acceptance) in archive mode. Later membership/selection removal or account-wide revocation alone does not invalidate a historical grant. The recipient MUST still authenticate its exact bindings, signatures, required evidence, and epoch commitment, and satisfy the current identity-verification policy before first key acceptance.

For A4, assess the referenced membership/selection/context and retained authorization history without requiring either party to remain enrolled. A historical authorization check contradicted by authenticated evidence returns `BLOCKED`; missing required public evidence or authentication basis returns `INCOMPLETE`. When all mandatory checks pass and only issuance timing relative to withdrawal is unknown, historical authorization is `uncertain` and reading MAY proceed. Timestamps, old selections, and decryption do not establish that issuance preceded withdrawal or that the issuer knew globally current state.

Clients MUST report three separate assessments: cryptographic/binding/evidence validity (`valid`, `invalid`, `incomplete`), historical authorization (`supported`, `uncertain`, `contradicted`), and audit coverage/gaps. A retained local issuance decision with its then-known state can support that decision; no trusted timestamp service is required. Historical reading MUST NOT reset pins/withdrawals, restore current authority, or authorize new issuance, retries, or direct delivery.

## Direct sync

Auditors MUST discover repos through authenticated host writer discovery, available membership information, and retained participant/issuer history, including known former participants while access permits. Auditors MUST resolve each account's current repo host and sync directly with Spaces credentials/DPoP. Auditors MUST use permissioned-repo integrity/commit rules, not public MST proofs; public device/revocation records use public-repo sync. See the [Spaces sync boundary](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data#the-sync-boundary-writer-set).

Auditors MUST atomically persist each authenticated repo checkpoint, retained record IDs/CIDs, audit cursor, pending evidence requests, and gaps with processed evidence. Notifications schedule catch-up; periodic discovery/sweeps recover missed notifications. Discontinuity, migration, or invalid checkpoints require reconciliation without erasing history or marking skipped intervals complete. Deleted immutable records are gaps, not withdrawals. Renew credentials normally; failed renewal proves neither an empty repo nor a clean audit. Auditors MUST stop retrieval when denied and preserve permitted local copies.

Clients MUST audit grants to the local account without waiting for content keys. Auditors MUST check issuer signatures/bindings, exact selections, contexts, and retained own authorization history. Distinguish unauthorized bindings, authenticated forks, formerly authorized selections, malformed evidence, and insufficient history. Auditors MUST preserve evidence and alert on known unauthorized selections or authenticated declaration conflicts; missing remembered approval is inconclusive when history is missing. Observations without a signed grant do not establish issuance. A signature attributes a statement to a key, not PDS misconduct or recipient decryption.

Applications MUST let users inspect observed grants to any member, including unexpected admissions. Show the exact recipient binding, issuer, membership decision and policy used, epoch, and connected historical access, including evidence/history gaps. Correlate grants with authenticated membership changes. Grants to an unexpected host-authorized member remain protocol-valid when all required checks pass; audit evidence does not establish users' consent to that admission.

Detection requires an honest issuer's evidence, eventual access, and enough local history. Withholding, collusion, isolation, or lost read access can prevent it; matching observed grants do not prove all grants were seen. Auditors MUST report gaps and continue background catch-up without blocking unrelated operation. [Grant checks](core.md#grant-authorization) and [writer rules](core.md#writers) still apply. Detection has no deadline and cannot undo disclosure.

Audit records expose device/account relationships, trust mode, epochs, and transferable device signatures to authorized readers. Publishers MUST NOT include private OOB details, other-space history, credentials/tokens, DPoP keys, or plaintext.
