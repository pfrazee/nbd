# PEEP: Protocol Details

Status: Discussion draft · October 20, 2026

This document specifies the baseline encodings and client procedures for [Core](core.md) and [Device Enrollment](device-enrollment.md). Names under `com.example.peep` and the host operations below are proposed extensions; production Lexicons and transport conformance remain [TODO-03](TODOs.md#todo-03). Cryptographic interoperability and security validation remain [TODO-10](TODOs.md#todo-10).

## Encoding and identifiers

`CBOR(x)` means normalized ATProto CBOR, including byte strings and CID links. Decode with finite limits and reject duplicate/unknown fields, non-normalized encodings, trailing bytes, wrong types, unknown versions, invalid key/signature encodings, and integers outside 0 through 2^53−1. All fields shown are required; `null` is permitted only where shown. Never hash JSON or a displayed CID string. Sets are arrays sorted by unsigned lexicographic order of their elements' normalized CBOR bytes, with duplicates rejected; other arrays retain their specified order.

`Ref(x)` is a CIDv1 with codec `dag-cbor` (`0x71`) and SHA-256 multihash of `CBOR(x)`. Resolve a reference to exactly those bytes and check its hash before interpreting it. This commits to content, not authority, freshness, or availability. `Digest` is a 32-byte SHA-256 result. `RandomId` is 16 independently random bytes encoded as 32 lowercase hexadecimal characters. Allocate new device IDs for fresh installations or replacement keys; imported copies of the same private keys retain their binding. All identities use exact DIDs, never mutable handles. Space identifiers use the exact canonical URI obtained from the authenticated host; do not normalize identifiers differently for signing and verification.

```typescript
type Device = { deviceId: string; authPubkey: bytes; encryptPubkey: bytes };
type Binding = { account: string; device: Device };
```

Both public keys are 32 bytes under [Core's profile](core.md#mandatory-grant-profile). New device IDs use `RandomId`. A binding ID is lowercase hexadecimal `SHA-256(CBOR(["peep/device-binding", 1, binding]))`; it includes both keys and the account. Key fingerprints remain the separate algorithm-specific fingerprints defined in Core.

## Records and declarations

Publish a device's `Binding` in its account's public repo as `{ $type: "com.example.peep.device", value: binding }`, with record key equal to `deviceId`. The repo account must match the binding account. This is discovery, not approval. Retain exact bindings in signed declarations rather than following mutable key-record URLs.

All other records below are immutable protocol values wrapped as `{ $type: collection, value }`. Their record key is lowercase hexadecimal SHA-256 of `CBOR(value)`; references identify the inner value. Writing different bytes at an existing identity is an error. Collections are `com.example.peep.declaration`, `.revocation`, `.grant`, `.evidence`, and `.compromise`. Declarations belong in the declaring account's space repo; grants and their evidence belong in the issuer's space repo. Revocations belong in the signer's public repo and may be copied unchanged into space repos. Compromise reports belong in the reporting account's space repo. Retain superseded records and evidence indefinitely under the agreed access rules.

```typescript
type Declaration = {
  version: 1;
  space: string;
  account: string;
  devices: Device[];       // Set, at most one binding per deviceId; empty is valid.
  previous: CID[];         // Set of predecessor declarations, all in this account/space.
  signer: Binding;         // Same account; need not appear in devices.
  proof: bytes;
};
```

The signature is `Ed25519.Sign(signerKey, CBOR(["peep/declaration", 1, declarationWithoutProof]))`. All selected devices inherit `account`. A normal update has one predecessor; an initial declaration has none; a resolution covers all known competing tips. A mutable “current declaration” pointer, if an application provides one, is only a discovery hint. Resolve heads through signed ancestry and retained state, using the [bootstrap and conflict rules](device-enrollment.md#bootstrap-and-incremental-validation).

Before signing, present the account, space, and selection changes to the user. Authenticate added devices' complete bindings through local pairing or independent verification; possession of a key or a list supplied by a PDS is insufficient confirmation of user intent. Persist the signed snapshot and the user's authorization locally before publication. A removal by omission is explicit in this confirmation, including removal of the last selected device.

Validate approval paths outward from a locally accepted, unwithdrawn same-account binding. Verify each declaration signature and exact selected bindings before accepting additions; preserve whether the root is TOFU or independently verified. Keep the exact approval records privately even after reusing the resulting binding elsewhere. Do not infer trust from self-signatures, unanchored cycles, another issuer's status, or a path containing an unaccepted withdrawn approver. Previously accepted bindings retain their trust under the approver-withdrawal rule. New declarations by withdrawn signers do not acquire authority through that preservation.

## Independent verification

The verification payload is `CBOR(["peep/verify-device", 1, binding])`. A QR encodes `peep:verify:` followed by unpadded base64url of that payload. Decode it strictly, require canonical re-encoding, and compare every binding component. The safety code is the full lowercase hexadecimal SHA-256 of the payload, displayed as sixteen groups of four characters; compare every group. Spaces, handles, display names, and timestamps are excluded from this representation.

Display the account DID and device being verified alongside the code. Require confirmation that the QR came directly from the intended person's device or that the entire safety code matched through an independently authenticated channel. Successful comparison records direct verification of that exact binding; valid approvals derived from it record approval provenance separately. Any mismatch records a dispute and blocks dependent grants and key acceptances pending explicit resolution. Do not replace pins, clear withdrawals, relabel earlier grants, or fall back to TOFU. An application may add a friendlier display but must not shorten the authenticated comparison silently.

## Revocation records

```typescript
type Revocation = {
  version: 1;
  scope: "account";
  signer: Binding;
  target: Binding;
  proof: bytes;
};
```

Sign `CBOR(["peep/device-revocation", 1, revocationWithoutProof])`. Signer and target must name the same account; self-revocation is valid. Validate signer authority using the receiver's own accepted bindings and the [revocation-cycle exception](device-enrollment.md#device-revocation-cycles). Retain valid statements, their exact targets, and locally recorded acceptance/withdrawal ordering even if records disappear. Reject cross-account signatures and scope/key substitutions. A revoked exact binding cannot be revived; replacement requires fresh keys and normal approval or recovery.

On public-key discovery and periodic catch-up, enumerate that account's revocation records as well as its device publications. Use public repo synchronization for those records, separately from permissioned space synchronization. Peers may relay the original signed value by CID; neither the relay nor public-repo authentication substitutes for device-signature/trust validation. No observation of “no new revocations” is a freshness certificate.

Retain cryptographically valid cycle candidates even when their signer is withdrawn; keep them inactive unless ordinary authority or a complete qualifying cycle permits acceptance. Evaluate each candidate cycle against locally preserved ordering before applying the batch, and never reverse an already accepted withdrawal. Missing ordering is unknown, not evidence of prior acceptance. Bounded graph validation may defer an unresolved candidate; it must not silently accept a partial cycle or grant new authority to outgoing edges outside it.

## Trusted host state

The Spaces adapter authenticates the host through the space authority's DID and the deployed Spaces protocol. It obtains membership decisions from that host's management implementation. Writer discovery and read credentials are not membership decisions or device approvals. The [Spaces proposal](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data) separates these functions; its `listRepos` enumerates writers, and management policies determine participation.

PEEP requires these host-authenticated values, retained by content reference:

| Value | Required fields |
| --- | --- |
| Configuration | `version: 1`, `kind: "configuration"`, `space`, positive monotonic `revision`, `grantProfile: "peep-hpke-v1"`, `deviceVerification: "tofu-permitted" \| "verified-only"`, positive `maxEncryptedBlobBytes` (default 16,777,216). |
| Membership decision | `version: 1`, `kind: "membership"`, `space`, `account`, positive per-account monotonic `revision`, `eligible: boolean`. Eligibility is the host's explicit PEEP participation decision under its management rules. |
| Epoch metadata | `version: 1`, `space`, positive `epoch`, `keyId: RandomId`, `commitment: Digest`, `previous: CID \| null`, `context: CID`. |
| Activation outcome | `version: 1`, `space`, `requestId: RandomId`, `request: CID`, `status: "accepted" \| "stale" \| "rejected"`, `active: CID \| null`. An accepted outcome identifies the exact epoch accepted for that request. |

Provide authenticated reads of current configuration, per-account membership, active epoch, exact historical values by CID, and durable activation outcomes, including the accepted request/outcome for each epoch. Updates use existing management authority. Preserve monotonic revisions and exact historical bytes through restart/migration; unknown historical state is unavailable, never reconstructed as current state. Configuration defaults apply only to authenticated creation, not missing configuration. Clients preserve highest known revisions, accepted epoch references, and known withdrawals across restore. Equal revision with different bytes is an error; lower revisions cannot replace known current state. A later authenticated membership decision may re-admit an account; this cannot reset its device trust/history.

Host values do not require a new transferable signature system: authenticate them by direct host retrieval or a retained local observation from that authenticated retrieval. Published copies let readers recover exact bytes but do not independently authenticate the host. Readers lacking their own authentication must resolve the reference against the host; failure leaves required evidence unavailable. Keep the authentication basis in private state. A host read does not give a trusted issuance timestamp or prove that no subsequent change exists. Do not publish credentials, DPoP keys, OAuth tokens, or private trust records as evidence.

The adapter must expose change notification plus resumable reconciliation for membership/configuration/epochs. Notifications are hints to fetch authenticated state. Cached validated state remains usable under the baseline freshness policy; known changes take effect before the next grant release. A deployment lacking these operations does not implement this PEEP baseline. Their endpoint/Lexicon mapping and retention support require [integration validation](TODOs.md#todo-03); this specification does not claim existing Spaces deployments already provide them.

## Rotation context

Every epoch references a context `{ version: 1, space, events: CID[] }`, with events a set. Creation has an empty set unless there are already known applicable restrictions. A successor includes its predecessor's entire event set plus newly addressed events. Inheriting an event preserves its requirement; it does not claim that all possible events have been learned. Keep event/context bytes with host epoch history and in grants' evidence. No global enrollment log is introduced.

Each event is one of these exact maps; all include `version: 1` and `space`:

| `kind` | Additional fields | Effect |
| --- | --- | --- |
| `membership` | `decision: CID` | A host-authenticated ineligible membership decision. Grants involving that account require a later authenticated eligible decision. |
| `selection` | `before: CID`, `after: CID` | Same-account signed declarations with validated replacement ancestry. The omitted exact bindings are removed. Grants involving that account require `after` or a valid descendant/resolution, not an older selection. |
| `revocation` | `revocation: CID` | An account-wide signed revocation, validated under local trust. Permanently excludes that exact binding as recipient or issuer and applies the normal approval-authority rules. |
| `compromise` | `report: CID` | A device-signed report identifying the compromised epoch/key; requires a fresh replacement for that key. It creates no account/device ban by itself. |

The selection evidence includes the ancestry needed to show replacement and identify removals; an addition-only update is not a removal event. A later valid selection may re-add a per-space removed device unless account-wide revocation prohibits it. A membership removal and later re-admission similarly preserve rotation history without a permanent account ban. New historical-key grants still follow current eligibility.

A compromise report has `{ version: 1, space, epoch: CID, reporter: Binding, declaration: CID, proof: bytes }`, signed over `CBOR(["peep/key-compromise", 1, reportWithoutProof])`. Accept reports from an eligible, enrolled key holder using the normal binding/authority checks and retained supporting evidence; a client may also act on its own knowledge of compromise. The referenced epoch fixes the exact key commitment. Publishing a report asserts suspected disclosure; it need not reveal the secret or prove the leak. A report about an older key does not require endless rotation of unaffected successor keys.

Before generating a replacement, process the trigger evidence and derive its restrictions. Generate a fresh independent key afterward; never reuse a candidate already generated/distributed under an earlier authorization context. The activation request signs the exact context and key commitment and asserts this ordering. This is a requirement on trusted clients, not cryptographic proof of randomness, timing, or non-disclosure.

For every new grant, retry, and direct delivery, load the epoch's context and identify its relevant events. Validate and enforce the restrictions for both recipient and issuer under local trust, in addition to current authorization. Missing bytes needed to identify an event's scope block validation; missing required authority/ancestry evidence blocks affected grants. An event label, host ordering, or another issuer's trust status cannot replace those checks. Restrictions inherited by successors must be enforced too; valid later reauthorization must satisfy the event's membership/declaration floor. Known revocations and conflicts always apply, even if absent from the context.

Track each pending event with the epoch/key considered at risk when it was learned. It is addressed only by an accepted fresh replacement for that key whose context contains the exact event (or its inherited reference) and whose restrictions are enforced. If a competing epoch omitted an outstanding event, prepare a fresh proposal against it with that event included. Re-observing an already addressed event does not itself trigger another rotation. Compromise or an unauthorized grant of the replacement key is a new event naming that replacement. Context does not establish that no one leaked the key, that hidden events were included, or that every writer switched.

## Activation and publication state

An activation request is `{ version: 1, requestId: RandomId, proposal: EpochMetadata, proposer: Binding, declaration: CID, evidence: CID, proof: bytes }`. Sign `CBOR(["peep/activate-epoch", 1, requestWithoutProof])`. Its evidence manifest supplies proposer authorization and context/event bytes. The host authenticates the requesting account, verifies the request's signature and presented declaration binding, checks account eligibility under its management rules, and orders the proposal; this does not transfer independently verified device trust to other clients. Host acceptance does not authorize accepting a grant: clients apply the [device verification policy](core.md#device-verification-policy) to the device supplying the key, whether the generator or another eligible issuer. A TOFU binding cannot authorize key acceptance in a verified-only space. The request asserts that the client is eligible/enrolled, durably holds the fresh key, and processed the context before generation.

`proposal.previous` is the exact expected active epoch reference, or `null` at creation. The proposed number is predecessor number plus one, or 1 at creation; reject overflow, repeated key IDs, incorrect context inheritance, and malformed commitments. The host atomically compares the predecessor, persists the accepted outcome and metadata, and advances the active pointer. No recipient coverage, self-grant, or acknowledgment is required. Other proposals against that predecessor become stale and are never queued for later activation. Generator authority is evaluated for that activation using its retained evidence; later withdrawal does not invalidate an archived epoch's commitment. New grants still require current issuer/recipient authorization.

Persist key bytes, proposal, context, request bytes/ID, and local status before sending. Request IDs are scoped to space and proposer account; reusing an ID with different bytes is an error. The host durably retains terminal outcomes. Exact retries return the original outcome, even after later rotations; query current active metadata separately and never roll back newer known state. If no terminal outcome is found after an uncertain response, resend the exact request. A stale/rejected proposal is never used for content or grants; regenerate with a new ID/key against the then-active epoch if a trigger remains. Distribute grants only after authenticated acceptance. Cancellation cannot establish that an uncertain request was never accepted.

Track pending grants as `prepared`, `outcome-unknown`, `acknowledged`, or `stopped`. Persist their full immutable bytes/evidence and record identity before upload. Store evidence records first and the grant record last; before any operation releasing grant bytes, recheck authorization and rotation context. An interrupted evidence upload can resume without changing the grant. Reconcile uncertain grant writes by authenticated read of that exact identity: matching bytes acknowledge publication, different bytes are an integrity error, and an absent record leaves exposure uncertain. Resend identical bytes only after current authorization passes. Stop on lost authority, missing required evidence, or conflicts; do not delete previously published evidence. Forward directly only after acknowledgment, with another authorization check.

A recheck must not silently reinterpret the signed header or manifest. If authorization now requires different published evidence or a different recorded trust decision, stop the old delivery attempt and prepare a new issuance under current checks. Retain the old record/outcome, including uncertainty about prior exposure; it is not rewritten or erased.

On learning a newer active epoch, invalidate queued old-epoch publication work, obtain the new key, and re-encrypt unpublished records/blobs with fresh nonces. Recheck the known active epoch immediately before each publication operation. An old-key upload already in flight may have been exposed; cancellation does not undo that exposure. Retain that fact, do not link its object from newly encrypted content as though it excluded former holders, and upload a new encrypted object as needed. Local drafts and archived reads remain available while waiting for a key. Learning a trigger alone does not create a separate write pause.

## Evidence manifests

An evidence manifest is `{ version: 1, space, blocks: CID[] }`, where `blocks` is a set of exact protocol values. The referring field determines each block's required type; a CID cannot substitute another type. Include the starting snapshots and incremental declaration/approval ancestry used locally, relevant revocation/cycle evidence, configuration and issuer/recipient membership decisions, the accepted epoch with its accepted request/outcome and rotation context, and required event evidence. Include referenced activation manifests and their required blocks too; validate this as an acyclic graph. Activation manifests omit the not-yet-accepted epoch and their own request, including instead the proposal's predecessor/context and proposer authorization. No manifest references its enclosing grant/request, avoiding a hash cycle.

The grant header names one recipient declaration, one issuer declaration, one configuration, one membership decision for each party, one accepted epoch, and the manifest. All must be present in its manifest or, for the manifest itself, the package. Exact keys are embedded in those declarations/signers; verify grant identities/fingerprints against them. The recipient must independently apply the space's device verification policy to the exact issuer binding before accepting the key; the signed `recipientTrust` field records only the issuer's check of the recipient. Match the epoch's space, number, and key ID to the grant and verify the decrypted key's commitment. Include additional space-local records needed by the issuer's validation, stopping at retained starting snapshots/bindings. Public revocations have no space; every space-specific record in a package must name this space. Do not recursively include private provenance or evidence from another space. An earlier accepted epoch used as an authenticated starting point need not recursively import all previous activation requests; retain the current request and its required authorization/context evidence.

Publish every referenced value needed within that scope as an evidence record in the issuer's space repo, using its content-derived identity. Existing same-space records may be shared among grants but cannot be pruned while referenced. Packages are logical sets of these immutable records; a network response may batch them, but must preserve their exact bytes. Hash-only links to a source PDS are insufficient retention. Evidence is readable through normal Spaces access without a content key. The signed header's manifest reference binds the package through both HPKE context and the grant signature. Audit/status statements never substitute for missing required evidence.

Report validation on separate axes: cryptographic/binding/evidence checks (`valid`, `invalid`, `incomplete`), historical authorization (`supported`, `uncertain`, `contradicted`), and audit coverage (recorded gaps). A retained local issuance decision with its then-known state can support that issuer's decision; it cannot prove globally current authorization. A reader lacking such ordering reports uncertainty instead of trusting a claimed timestamp. Archived decryption may proceed only after required cryptographic/binding/evidence checks pass, while preserving authorization warnings; it confers no current authority. Live release always requires current local authorization, and first key acceptance requires the issuer binding to meet the device verification policy. See [Core's historical rule](core.md#archived-grant-validation).

## Local state and recovery

Durably retain exact binding pins, direct/approval-derived TOFU or verified status, disputes, private approval/OOB evidence, local acceptance and learned-withdrawal ordering, revocation candidates/accepted statements, declaration starting points/tips/conflicts, authenticated host observations, epoch/key state and local verification decisions at key acceptance, pending operations, authored selections, and audit checkpoints/gaps. Private storage must be authenticated and confidential. Record local events in an append-only journal with a unique installation/history identity and monotonic sequence; importing another installation's history preserves its identity/order and records the import as a local event. Wall-clock timestamps never establish acceptance before withdrawal. Do not invent an ordering between unrelated histories.

Use the application's protected backup/paired-device transfer container for keys and this state together; no new interoperable backup protocol is required by this baseline. The container must bind its format/version, owner account, source installation/history, and full payload, and authenticate it before importing any state. Encrypt with independently protected high-entropy key material; a PDS login/reset must not reveal or reset that protection. Pair transfers through authenticated trusted devices. Each implementation documents its key wrapping/KDF, integrity, rollback detection limits, and atomic restore; platform and backup validation remain [TODO-08](TODOs.md#todo-08) and [TODO-12](TODOs.md#todo-12).

Validate key/public-binding consistency, references, provenance, owner, and journal integrity before an atomic import. Union known revocations and preserve unresolved disputes/conflicts; merge declaration tips by authenticated ancestry and host state by monotonic revisions. Conflicting exact pins require explicit resolution. Preserve valid verification provenance without silently promoting TOFU. An older backup cannot roll back state already known on the destination. If all newer state was lost, the backup cannot detect that loss by itself: report its coverage/freshness limits, reconcile available sources, and do not manufacture prior acceptance for withdrawal exceptions. Incomparable histories cannot establish a cycle's required ordering.

Reinstall/full device loss uses restored protected state, an accepted surviving device's approval, or a helper issuer's independent verification of fresh keys. A key-only backup restores only keys; mark trust/declaration/audit history missing and require explicit recovery. Recover available declaration history and resolve known tips/conflicts before new issuance; missing comparison evidence remains blocking. Explicit recovery does not authorize a new root over known history. Notify peers through the replacement declaration and signed withdrawals where an authorized signer survives; PDS recovery alone cannot issue those withdrawals. Each peer applies its own trust decision. Lost copies of all epoch keys and decryptable backups mean lost plaintext; host administration cannot recreate it.

## Synchronization and bounded validation

Discover space repos from authenticated host writer discovery, available membership information, and retained participant/issuer history. Resolve each account's current repo host and sync it directly with normal Spaces credentials/DPoP. Membership eligibility must be checked separately. Use the deployed permissioned-repo integrity/commit rules, not public-repository MST proofs; public repo sync remains the path for device/revocation publications. The [Spaces draft](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data#the-sync-boundary-writer-set) provides writer discovery and direct repo sync; the PEEP adapter must verify its concrete mapping before deployment.

Persist each repo's authenticated checkpoint, retained record identities/CIDs, audit cursor, pending evidence requests, and coverage gaps atomically with processed evidence. Notifications schedule catch-up; periodic discovery and sweeps repair missed notifications. On discontinuity, migration, or invalid checkpoints, reconcile available records without erasing retained history or marking skipped intervals complete. Treat deleted immutable audit/declaration records as gaps, not withdrawals. Renew credentials through the ordinary Spaces flow; failed renewal does not mean an empty repo or a clean audit. Stop remote retrieval when access is denied and preserve permitted local copies. Do not extend former members' access.

For each grant to the local account, check the issuer signature/binding, exact selection, context, and retained local authorization history. Distinguish an unauthorized binding, an authenticated fork, a formerly authorized but withdrawn selection, malformed evidence, and insufficient history. Preserve the evidence and alert on known unauthorized selection; lack of remembered approval alone with missing history is inconclusive. A valid signature attributes a statement to that key; it does not prove PDS misconduct, recipient decryption, or absence of other grants. Audit records expose account/device relationships, trust mode, and key epochs to authorized readers and carry transferable device signatures; omit private OOB details, other-space history, credentials, and plaintext.

Validate declaration graphs incrementally using visited-reference sets, cached signature results, and per-operation byte/node/depth/work budgets. Reject actual graph cycles and cross-account/space ancestry; sharing an ancestor is valid. Authenticate edges before using them to establish replacement or a conflict. Bootstrap may stop at the authenticated starting snapshot; later comparisons cannot skip a required edge. Keep graph progress resumable, and report resource exhaustion or unavailable history as incomplete validation. Never truncate a selection/context, choose a branch, discard revocations, or weaken verification to fit a limit. Limit each decoded block before allocation; applications publish their supported finite limits. Large histories may require additional work or a more capable client, not silent acceptance.

Background audit gaps do not block unrelated ordinary operation. Missing evidence required for a particular grant, unresolved local conflicts/withdrawals, and the active-epoch writer rule still apply. Neither a completed sync of available records nor a backup restore proves a complete or fresh history.
