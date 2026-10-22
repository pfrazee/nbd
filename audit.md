# PEEP: Grant Publication and Auditing

The signed [grant](core.md#grant-format) is the audit record. Publishing it in the issuer's own space repo lets an affected account discover substitution through another PDS: if Bob grants to keys forged by Alice's PDS, Alice can obtain Bob's grant and compare its exact selection with her authorization history.

## Evidence

A manifest is `{ version: 1, space, blocks: CID[] }`, with `blocks` a set of exact protocol values. Each referring field determines its block's required type. Issuers MUST include:

- Both parties' exact signed declarations/keys, starting snapshots, and the space-local approval/ancestry used for issuance.
- Configuration, both membership decisions, accepted epoch/request/outcome, rotation context, and required trigger/revocation evidence.
- Referenced activation manifests and their required blocks, validated as an acyclic graph.

The grant header's declaration, host-state, and epoch references MUST be in its manifest; the package includes the manifest itself. Activation manifests contain proposer authorization and predecessor/context evidence, omitting their own request and the not-yet-accepted epoch. A manifest MUST NOT reference its enclosing grant/request. An earlier authenticated epoch used as a starting point need not recursively import all earlier activation requests.

The starting epoch's committed [history wraps](core.md#backward-history-wrapping), including bridges, make the grant an audit record for access to all history reachable from that key. Publish epoch metadata used for issuance under the same evidence rules; additional historical target metadata may be fetched lazily from authenticated host history for reading. Missing traversal data is a history-coverage gap, not permission to omit evidence required to validate the starting grant. Recipients MUST record each derived key's starting grant and traversed source/target epoch references. A later bridge extends access from its new epoch; it MUST NOT be attributed to earlier grants whose keys cannot reach it. No additional per-recipient grant record is needed for each hop, and earlier grants/evidence remain retained with their original trust decisions.

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

Except for disposable [key requests](core.md#key-requests), publishers MUST retain published immutable records and exact supporting evidence indefinitely. Each account MUST keep all its declarations—including superseded snapshots, forks, and resolutions—in its space repo; issuers MUST keep the grants and evidence they used. Publishers MUST preserve these through migration, replacement, conflict resolution, rotation, revocation, and membership changes, and MUST NOT prune referenced evidence.

Permissioned evidence follows normal Spaces access rules. Former members may keep/audit synced copies but have no guaranteed further access, even to grants addressed to them. Retention does not extend authorization or guarantee hosting, availability, completeness, or freshness.

## Archived grants

Historical reading MUST use [grant acceptance](core.md#grant-acceptance) in archive mode. Later membership/selection removal or account-wide revocation alone does not invalidate a historical grant. The recipient MUST still authenticate its exact bindings, signatures, required evidence, and epoch commitment, and satisfy the space's [verification policy](core.md#device-verification-policy) before first key acceptance.

For A4 in either mode, the referenced membership decisions MUST authorize the exact issuer and recipient accounts, and the referenced configuration, selections, and epoch context MUST permit the grant on its recorded basis. A known failure of those authorization checks returns `BLOCKED`; invalid or missing required evidence returns `INVALID` or `INCOMPLETE`. A newer eligible decision MUST NOT repair an ineligible decision recorded in the grant.

Assess historical authorization separately using retained history, without requiring either party to remain enrolled. Clients MAY read an archive with uncertain historical authorization once all mandatory checks pass; lack of proof about issuance time or the issuer's then-known state is not missing required public evidence. Timestamps, old selections, and decryption do not establish that issuance preceded withdrawal or that the issuer knew globally current state.

Clients MUST report three separate assessments: cryptographic/binding/evidence validity (`valid`, `invalid`, `incomplete`), historical authorization (`supported`, `uncertain`, `contradicted`), and audit coverage/gaps. A retained local issuance decision with its then-known state can support that decision; no trusted timestamp service is required. Historical reading MUST NOT reset pins/withdrawals, restore current authority, or authorize new issuance, retries, or direct delivery.

## Direct sync

Auditors MUST discover repos through authenticated host writer discovery, available membership information, and retained participant/issuer history, including known former participants while access permits. Auditors MUST resolve each account's current repo host and sync directly with Spaces credentials/DPoP. Auditors MUST use permissioned-repo integrity/commit rules, not public MST proofs; public device/revocation records use public-repo sync. See the [Spaces sync boundary](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data#the-sync-boundary-writer-set).

Auditors MUST atomically persist each authenticated repo checkpoint, retained record IDs/CIDs, audit cursor, pending evidence requests, and gaps with processed evidence. Notifications schedule catch-up; periodic discovery/sweeps recover missed notifications. Discontinuity, migration, or invalid checkpoints require reconciliation without erasing history or marking skipped intervals complete. Deleted immutable audit records are gaps, not withdrawals; deleting a disposable key request is not an audit gap. Renew credentials normally; failed renewal proves neither an empty repo nor a clean audit. Auditors MUST stop retrieval when denied and preserve permitted local copies.

Clients MUST audit grants to the local account without waiting for content keys, promptly when they learn of them, using notifications and periodic sweeps of known issuers' repos. In TOFU-permitted spaces this audit and [change notices](core.md#trusted-host-state) are the defense against key substitution, so clients MUST visibly alarm on a grant to a binding of the local account that no locally accepted own binding selected, and on declarations or device records in the local account's repos for bindings it has not accepted. A PDS can hide records from its own account's reads, so grants in other issuers' repos remain the stronger signal. Auditors MUST check issuer signatures/bindings, exact selections, contexts, and retained own authorization history. Distinguish unauthorized bindings, authenticated forks, formerly authorized selections, malformed evidence, and insufficient history. Auditors MUST preserve evidence and alert on known unauthorized selections or authenticated declaration conflicts; missing remembered approval is inconclusive when history is missing. Observations without a signed grant do not establish issuance. A signature attributes a statement to a key, not PDS misconduct or recipient decryption.

An approval by a compromised own installation passes every signature and approval check, so the account holder is the only party who can recognize it. Each installation MUST therefore visibly notify the user of every new or removed binding of the local account that it did not itself approve, including bindings approved by another own installation, learned from any of: a declaration in the account's space repos, a device record or revocation in its public repo, a grant to an own-account binding in another issuer's repo, or a [trust sync](device-enrollment.md#own-device-trust-sync) snapshot. Notices identify the binding, the approving installation when known, and the affected spaces; one notice covers a binding across all spaces. Notices for additions MUST offer removal, which revokes the binding from the notified installation under [revocation rules](device-enrollment.md#device-revocations) and triggers [rotation](core.md#triggers). These notices are not integrity alarms and add no approval gate. They protect only users with at least one honest installation online to receive them.

Applications MUST let users inspect observed grants to any member, including unexpected admissions. Show the exact recipient binding, issuer, membership decision and policy used, epoch, and connected historical access, including evidence/history gaps. Correlate grants with authenticated membership changes. Grants to an unexpected host-authorized member remain protocol-valid when all required checks pass; audit evidence does not establish users' consent to that admission.

Detection requires an honest issuer's evidence, eventual access, and enough local history. Withholding, collusion, isolation, or lost read access can prevent it; matching observed grants do not prove all grants were seen. Auditors MUST report gaps and continue background catch-up without blocking unrelated operation. [Grant checks](core.md#grant-authorization) and [writer rules](core.md#writers) still apply. Detection has no guaranteed deadline and cannot undo disclosure.

Audit records expose device/account relationships, trust mode, epochs, and transferable device signatures to authorized readers. Publishers MUST NOT include private OOB details, other-space history, credentials/tokens, DPoP keys, or plaintext.
