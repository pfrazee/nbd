# PEEP: Remaining Work

Baseline design decisions are resolved. Implementation, interoperability, and independent security validation remain outstanding. IDs are retained for existing references.

## Implementation and validation

<a id="todo-03"></a>
### 03: Spaces integration

Allocate production namespaces and implement concrete Lexicon/XRPC mappings for the [host contract](core.md#trusted-host-state). Validate authorization, historical storage, migration/key changes, atomic durable activation, history-wrap retention, and host abuse controls against the selected Spaces revision; expose required reads without granting administrative powers.

<a id="todo-08"></a>
### 08: Recovery and backup

Implement and validate the application's [protected backup/pairing container](device-enrollment.md#backup-and-transfer), including ownership, encryption/KDF, atomic import, corruption, rollback limits, and recoverability.

<a id="todo-09"></a>
### 09: Publication and sync

Integrate [grant publication and auditing](audit.md), generator-first scheduling, and key-request hints usable without content keys with the chosen host/PDS transports.

<a id="todo-10"></a>
### 10: Interoperability and security

Publish byte-exact positive/negative vectors, cross-check independent implementations, and obtain independent protocol/cryptographic review. Track coverage in [validation cases](#validation-cases).

<a id="todo-12"></a>
### 12: Platforms

Validate Ed25519/X25519 operations, installation identity, storage, pairing, restore, and independent-app behavior against [platform constraints](device-enrollment.md#platform-notes), including browser origin/profile isolation and state loss.

## Specified baselines

| ID | Specification |
| --- | --- |
| <a id="todo-01"></a>01 | [Signed selection and approval](device-enrollment.md#declarations). |
| <a id="todo-02"></a>02 | [Local trust and verification](device-enrollment.md#local-trust). |
| <a id="todo-04"></a>04 | [Declaration history](device-enrollment.md#declaration-ancestry). |
| <a id="todo-05"></a>05 | [Grant format](core.md#grant-format) and [evidence](audit.md#evidence). |
| <a id="todo-06"></a>06 | [Freshness and revocation](device-enrollment.md#freshness); stronger profiles deferred below. |
| <a id="todo-07"></a>07 | [Rotation](core.md#rotation). |

## Deferred extensions

- **02:** Cross-user verification attestations and separate trust sync.
- **06:** Expiring approval needs reliable clocks and renewal by approvers that stop renewing withdrawn selections. Per-grant approval needs an online trusted approver, issuer nonce, exact selection/epoch, deadline, and replay protection. A fresh response alone proves neither current authority nor consent; any delay bound must state its assumptions.
- **08:** Dedicated recovery-key authority and cross-application backup portability.

<a id="todo-11"></a>
### 11: Independent content authentication

Define a separate profile binding devices to content/location/revision, handling replay and the effect of transferable signatures on deniable rebroadcast. Enrollment signatures do not upgrade [Format 1 authorship](core.md#encrypted-records).

<a id="todo-13"></a>
### 13: Authenticated streaming

Large media, seeking, or early playback needs a separate versioned format authenticating chunk order/count, total length, object identity, and final manifest. Test truncation and cross-object substitution; [Format 1](core.md#encrypted-blobs) requires bounded whole-file authentication.

## Validation cases

Each row requires implementation evidence; prose/link checks do not satisfy it.

| Area | Required cases |
| --- | --- |
| Encoding and cryptography | Fingerprints, verification payload/code, all signing domains, CID/CBOR normalization, grant headers/manifests, HPKE suites/lengths, commitments, record/blob/history AAD, history-wrap lengths and nonce separation; malformed/duplicate/unknown fields, signatures/points/all-zero KEM inputs, altered contexts, account/space/location substitution, no suite fallback, finite limits, full authentication before plaintext. |
| Host authority | Authenticate current/historical membership/configuration/epochs through migration; credentials/writer lists are not membership or device evidence. No creator signature or issuer appointment. Any eligible enrolled holder may grant current/historical keys, including pre-join epochs; reject known removed issuers/recipients. |
| Verification | Initial PDS substitution versus independently verified rejection; changed pins, downgrades, exact DID/device/both-key QR/full-code comparison through an independent channel. Self-signatures/PDS delivery insufficient; mismatches block until resolution. Reuse across spaces/lifecycle without repeat OOB or bypassing space authorization. |
| Approvals | Same-account additions rooted in TOFU/verified bindings, offline approver reuse, retained private provenance; reject cross-account/space substitution, missing/unanchored/cyclic approval, unjustified promotion, and another issuer's status/grant as verification. Withdrawn approvers cannot establish new bindings through backdated or unaccepted intermediate approvals. |
| Upgrades and policy | Exact-binding upgrade affects future local decisions only; preserve prior grant status and derived provenance, never revive revocations. Verified-only applies to granting and accepting current/historical keys, retries, and direct delivery; issuer and recipient each verify the other locally. One eligible issuer suffices when both checks pass. Reject a TOFU issuer even if the recipient is verified, and a TOFU recipient even if the issuer is verified; valid signatures, host activation, reported recipient trust, and successful decryption cannot bypass these checks. Missing configuration never permits fallback; tightening cannot repair disclosure or invalidate valid archives. First key acceptance from an archive still verifies the issuer; policy tightening preserves prior valid acceptances and historical grant validity. |
| Bootstrap and ancestry | Genuine first observation at an authenticated complete snapshot with unfetched predecessors and existing account pins/withdrawals. Retain starting refs; later updates need comparison paths. Out-of-order delivery, changed/cross-account/space edges, cycles, ancestor replay, new-root reset, and newly discovered pre-bootstrap history. Missing paths prove neither supersession nor conflict and block affected grants. |
| Selections and conflicts | Complete replacement, empty versus missing/deleted snapshot, removal by omission without revoking account-wide trust, no selection of revoked bindings. Authenticated forks pause grants to/from only the affected account/space. No merge/branch choice; accepted unwithdrawn signer can resolve while not selected. Cover every known tip, concurrent resolutions, later forks, invalid evidence, and missing ancestry. |
| Batched enrollment | One confirmation covers exact bindings, chosen spaces, and changes; each signed snapshot uses its own space/history. Reuse verification without automatic account-wide selection. Partial failure, offline spaces, retries, concurrent updates/conflicts, removal during a batch, and restart preserve other selections and the authorized scope; report incomplete publication. |
| Withdrawals | Same-account peer/self, compromised accepted signer withdrawing peers, invalid/cross-account/unknown/withdrawn signers, modified target/scope. Preserve across deletion, replay, restore, future spaces. Previously accepted bindings survive approver withdrawal subject to their own withdrawal. Relays use local trust; withheld updates never imply bounded freshness. |
| Revocation cycles | Mutual/longer/overlapping/late-closing cycles in varied delivery orders. All bindings accepted locally before any cycle withdrawal learned; preserve every withdrawal. Reject missing/incomparable history, timestamps/other-issuer substitutes, invalid/unknown/cross-account edges, later replacements, open chains and outgoing edges outside cycles. Bounded/resumed validation; recovery after all devices withdrawn. |
| Rotation events | Membership removal, selection omission/empty selection, account revocation, mixed updates, current-key compromise. Additions alone or access only to old keys do not require rotation of unaffected keys. Process exact evidence before fresh generation, no reused candidate, reject context/commitment substitution. Inherit restrictions, block missing required evidence, accept valid later membership/selection but never undo exact-binding revocation. Competing epoch omitting trigger requires fresh proposal; replacement-key disclosure is a new event. Ordering/labels do not prove exclusion. |
| Activation | Competing creation/rotation/recovery: one atomic winner, stale requests never auto-activate, exact proposal/commitment, unique IDs, numbering/overflow, durable key before request. Lost replies, restarts, altered-ID reuse, retries after later rotations return original result without rollback. Losing proposals authorize neither writes nor grants. Accept keys only from issuers meeting the device verification policy, including when the issuer generated the epoch. |
| Availability | Zero/partial grants, no self-grant or recipient acknowledgments, unavailable recipients/missing enrollment evidence, later grants under current authorization. Missing active key pauses writers; content is lost only if no key copy, backup, or usable history-wrapping path survives. Host acceptance proves neither key durability nor universal delivery. |
| Availability recovery | Proposer crash, offline/withholding behavior, or sole-key loss after acceptance and before grants. Another eligible enrolled device without the active key can activate a fresh successor without a security trigger, proof of zero grants, recipient acknowledgment, or protocol-wide timeout. Cover zero/partial/unknown grant coverage, local retries/backoff, concurrent recoveries, and races with security rotation. Preserve inherited restrictions and newly known events without a new event type; missing required evidence and symmetric verified-only checks still block affected operations. Content publication waits for the accepted successor key while recovery remains permitted. Late old-key grants allow historical reading without rollback; lost-key content stays unavailable. Exercise host throttling/removal against repeated malicious activation without claiming unconditional progress. |
| Distribution scheduling | Generator-first authorization failures and crashes; helpers use randomized backoff or recipient requests, including device additions. Concurrent helpers, partial repo views, retries, and duplicates retain normal publication checks. Existing grants with unverified issuers, missing evidence, or bad ciphertext cannot permanently suppress alternatives. Requests usable without content keys remain non-authoritative, bounded hints; no exclusive issuer or complete-coverage claim. |
| Backward history | A current grant unlocks a complete chain without separate historical device grants; pre-join access and lazy cached traversal. Bind space, epoch, key ID, predecessor CID, commitment, and context; reject altered ciphertext/tag/nonce, wrong keys/lengths/fields, cross-space or non-predecessor links, and commitment mismatches. Non-null creation wraps are invalid. Account for current-key compromise exposing connected history while old keys cannot move forward. |
| History gaps and fallback | Recovery without the predecessor key activates with null history. Creation ends traversal normally; later missing, invalid, unavailable, or budget-limited paths report gaps while the valid starting key remains usable. Malformed starting metadata still fails the starting grant. Direct historical grants obey current authorization and symmetric verification, then traverse their own chains. No post-activation edits or supplemental wraps under old keys; backfilling cannot expose new secrets to removed holders. A surviving later wrap can recover a key lost from plaintext storage; no fallback to older write epochs. |
| History audit | Starting grant verification covers its supplied connected history without trusting earlier generators or creating transferable verification. After policy tightening, prior acceptance of a TOFU starting key cannot bypass verification for first acceptance of a derived key; preserve earlier valid acceptances. Retain derived-key provenance, exact metadata used for issuance, and later traversal evidence; preserve original audit records/trust decisions. Lazy history fetch cannot excuse missing starting-grant evidence. Include vectors and independent review for the new wrap encoding. |
| Abuse controls | Account budgets survive new device IDs; bounded queues/report processing, duplicate reports, and coalesced events preserve unresolved restrictions and immediate withdrawal enforcement. Idempotent outcomes survive throttling. Forged claims or repeated reports confer no extra authority. Permit urgent rotation and administration without a protocol-wide cooldown; repeated malicious activation and quota exhaustion have explicit availability limits. |
| Writers | Continue latest-known active epoch during pending triggers, including compromise, while withdrawals block grants. New active epoch requires switch/pause, no fallback/rollback. Fresh-nonce re-encryption of queued records/blobs; interrupted uploads/cancellation cannot undo exposure. Preserve offline reads/drafts; no global switching deadline. |
| Evidence and archives | Exact issuer/recipient declarations/keys, host decisions, accepted epoch/context, actual retained bytes when source PDS withholds; no private OOB/cross-space provenance leakage or inherited verification. Historical reading after removals/revocations still checks signatures/bindings/evidence/commitment. Missing required evidence blocks; historical uncertainty alone need not block valid decryption but timestamps do not prove ordering. Archives never restore authority or access. |
| Publication retries | Durable bytes/identity before release, evidence-first upload, crashes before/after publication/ack, identical retries give one record. Changed bytes are new issuance. Recheck both parties/policy/context/withdrawals/conflicts/evidence on retries/direct delivery, even after acknowledgment. Missing acknowledgment leaves exposure uncertain and forbids direct forwarding; stopped retries preserve published audit records. |
| Auditing | TOFU substitution detected through honest issuer repo and retained own history despite source withholding. Forged audit signatures, stale formerly authorized versus never-authorized keys, legitimate revisions, suppression/collusion, unknown history, observations versus grants. Signature attributes statement, not PDS misconduct or decryption. Review metadata and transferable-signature privacy. |
| Retention and sync | Indefinite grants, exact evidence, declarations including superseded snapshots/branches/resolutions; preserve through migration/rotation/revocation/membership/restore. Host discovery plus retained participants, former repos while authorized, audit before key delivery, interrupted checkpoints/gaps, expiry/deletion/unavailable history. Offline catch-up, retained local auditing after removal without promised further access; no all-grants-seen claim. Background gaps neither bypass grant checks nor block unrelated work. |
| Recovery/transfer | Surviving approval or independent helper verification of fresh keys, one eligible holder can restore retained epochs without transferring trust to others. Reject PDS-only replacement, fresh-TOFU fallback, revived withdrawals or re-invitation history reset. Authenticated/confidential keys plus pins/provenance/order/withdrawals/conflicts; older imports preserve newer known state. Missing/incomparable history cannot invent prior acceptance; key-only restore cannot recreate trust; all copies and wrapping paths lost means plaintext lost. |
