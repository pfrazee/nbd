# PEEP: Grant Publication and Auditing

The signed [grant](core.md#grant-format) is the audit record. Publishing it in the issuer's own space repo lets an affected account discover substitution through another PDS: if Bob grants to keys forged by Alice's PDS, Alice can obtain Bob's grant and compare its exact selection with her authorization history.

## Evidence

A manifest is `{ version: 1, space, blocks: CID[] }`, with `blocks` a set of exact protocol values. Each referring field determines its block's required type. Include:

- Both parties' exact signed declarations/keys, starting snapshots, and the space-local approval/ancestry used for issuance.
- Configuration, both membership decisions, accepted epoch/request/outcome, rotation context, and required trigger/revocation/cycle evidence.
- Referenced activation manifests and their required blocks, validated as an acyclic graph.

The grant header's declaration, host-state, and epoch references must be in its manifest; the package includes the manifest itself. Activation manifests contain proposer authorization and predecessor/context evidence, omitting their own request and the not-yet-accepted epoch. A manifest must not reference its enclosing grant/request. An earlier authenticated epoch used as a starting point need not recursively import all earlier activation requests.

The starting epoch's committed [history wrap](core.md#backward-history-wrapping) makes the grant an audit record for access to its connected history as well. Publish epoch metadata used for issuance under the same evidence rules; additional predecessor metadata may be fetched lazily from authenticated host history for reading. Missing traversal data is a history-coverage gap, not permission to omit evidence required to validate the starting grant. Record each derived key's starting grant and traversed epoch references. No additional per-recipient grant record is needed for each hop, and earlier grants/evidence remain retained with their original trust decisions.

Stop at retained bindings/starting snapshots. Earlier OOB/approval provenance stays private; every space-specific published block must belong to this space. Public revocations have no space. Readers use their own trust/history and may need additional evidence; the bundle does not promise universal verification from scratch.

Publish actual bytes as immutable [evidence records](core.md#records) in the issuer's space repo, readable without the granted key or substituted private key. Batching/shared same-space records are allowed; preserve exact bytes and all referenced blocks. Links back to a withholding source PDS are insufficient. The manifest reference binds this package through the HPKE header and grant signature. Absence of private provenance is not missing required public evidence.

## Publication

1. Durably save the exact signed grant, evidence, and record identity before upload. Track `prepared`, `outcome-unknown`, `acknowledged`, or `stopped`.
2. Upload evidence first, then the grant. Before releasing grant bytes on any attempt, recheck [current authorization](core.md#grant-authorization), including rotation context. Resume interrupted evidence uploads without changing bytes.
3. Reconcile uncertain writes by authenticated read of that identity: identical bytes acknowledge publication; different bytes are an integrity error; absence leaves exposure uncertain. Retry only the same bytes/identity after authorization passes. Duplicate publication is one grant.
4. Direct delivery may forward that same record only after acknowledgment, with another authorization check.

Stop on lost authority, conflicts, or missing required evidence. If current checks require different published evidence or a changed trust decision, stop that delivery attempt and prepare a new issuance; never reinterpret or rewrite the old record. Prior acknowledgment does not bypass rechecks. Acknowledgment proves neither durable availability nor recipient decryption; failure/cancellation/deletion does not prove absence of exposure. Preserve previously published records and uncertain outcomes after stopping.

## Retention and access

Retain published immutable records and exact supporting evidence indefinitely. Each account keeps all its declarations—including superseded snapshots, forks, and resolutions—in its space repo; issuers keep the grants and evidence they used. Preserve these through migration, replacement, conflict resolution, rotation, revocation, and membership changes. Do not prune referenced evidence.

Permissioned evidence follows normal Spaces access rules. Former members may keep/audit synced copies but have no guaranteed further access, even to grants addressed to them. Retention does not extend authorization or guarantee hosting, availability, completeness, or freshness.

## Archived grants

Later membership/selection removal or account-wide revocation does not itself invalidate historical reading. Check exact bindings, issuer signature, declarations/approvals, authenticated host/epoch evidence, and key commitment without requiring either party to remain currently enrolled. First key acceptance still requires [device verification](core.md#device-verification-policy). Historical validity cannot bypass required evidence or identity verification.

Report three separate results: cryptographic/binding/evidence validity (`valid`, `invalid`, `incomplete`), historical authorization (`supported`, `uncertain`, `contradicted`), and audit coverage/gaps. A local issuance decision with its then-known state can support that decision, but timestamps, old selections, and decryption do not prove issuance preceded withdrawal or that authorization was globally current. Uncertain historical authorization alone need not prevent decryption once required checks pass. No trusted timestamp service is required.

An archive grants no current authority, resets no pins/withdrawals, and cannot justify new issuance, retries, or direct delivery. Those operations use current authorization.

## Direct sync

Discover repos through authenticated host writer discovery, available membership information, and retained participant/issuer history, including known former participants while access permits. Resolve each account's current repo host and sync directly with Spaces credentials/DPoP. Use permissioned-repo integrity/commit rules, not public MST proofs; public device/revocation records use public-repo sync. See the [Spaces sync boundary](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data#the-sync-boundary-writer-set).

Atomically persist each authenticated repo checkpoint, retained record IDs/CIDs, audit cursor, pending evidence requests, and gaps with processed evidence. Notifications schedule catch-up; periodic discovery/sweeps recover missed notifications. Discontinuity, migration, or invalid checkpoints require reconciliation without erasing history or marking skipped intervals complete. Deleted immutable records are gaps, not withdrawals. Renew credentials normally; failed renewal proves neither an empty repo nor a clean audit. Stop retrieval when denied and preserve permitted local copies.

Audit grants to the local account without waiting for content keys. Check issuer signatures/bindings, exact selections, contexts, and retained own authorization history. Distinguish unauthorized bindings, authenticated forks, formerly authorized selections, malformed evidence, and insufficient history. Preserve evidence and alert on known unauthorized selections or authenticated declaration conflicts; missing remembered approval is inconclusive when history is missing. Observations without a signed grant do not establish issuance. A signature attributes a statement to a key, not PDS misconduct or recipient decryption.

Let users inspect observed grants to any member, including unexpected admissions. Show the exact recipient binding, issuer, membership decision and policy used, epoch, and connected historical access, including evidence/history gaps. Correlate grants with authenticated membership changes. Grants to an unexpected host-authorized member remain protocol-valid when all required checks pass; audit evidence does not establish users' consent to that admission.

Detection requires an honest issuer's evidence, eventual access, and enough local history. Withholding, collusion, isolation, or lost read access can prevent it; matching observed grants do not prove all grants were seen. Report gaps and continue background catch-up without blocking unrelated operation. [Grant checks](core.md#grant-authorization) and [writer rules](core.md#writers) still apply. Detection has no deadline and cannot undo disclosure.

Audit records expose device/account relationships, trust mode, epochs, and transferable device signatures to authorized readers. Publish no private OOB details, other-space history, credentials/tokens, DPoP keys, or plaintext.
