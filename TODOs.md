# PEEP: Remaining Work

Baseline policies, encodings, and client procedures are specified in [Core](core.md), [Device Enrollment](device-enrollment.md), and [Protocol Details](protocol.md). Remaining work is implementation/integration and independent validation. “Specified” does not mean implemented or security-reviewed. IDs remain stable for existing links.

Deferred extensions: cross-user verification attestations and separate trust sync (02), stricter freshness profiles (06), dedicated recovery-key authority (08), independent content authentication (11), and streaming (13).

<a id="todo-01"></a>
## TODO-01: Selection authentication — specified

[Records and declarations](protocol.md#records-and-declarations) fixes embedded keys, canonical signing/domain separation, confirmation of user intent, approval paths, and private provenance. The signed declaration is the approval; no separate service or record is required. Validate implementations under 10.

<a id="todo-02"></a>
## TODO-02: Local verification and trust — specified

[Verification](protocol.md#independent-verification) fixes the account/device/both-key QR and complete safety-code comparison, confirmation, mismatch handling, and TOFU upgrades. [Local state](protocol.md#local-state-and-recovery) specifies private pins/provenance, acceptance ordering, backup contents, merges, and explicit history-loss recovery. Trust remains local and reusable across spaces; the space's device verification policy follows [host state](protocol.md#trusted-host-state).

Validate the comparison UX, private storage, and backup/transfer implementations under 08, 10, and 12. Applications use their protected backup container; separate trust sync and cross-user attestations remain deferred.

<a id="todo-03"></a>
## TODO-03: Spaces transport and host integration — validate

The [host contract](protocol.md#trusted-host-state) defines authenticated configuration, explicit account eligibility, immutable historical reads, monotonic revisions, and durable activation outcomes. Device authority and public [revocation records](protocol.md#revocation-records) remain separate from host administration.

Implement and verify the concrete Lexicon/XRPC mapping against the selected Spaces revision and allocate production namespaces. Verify membership authorization rather than inferring it from writer discovery or credentials; expose required decisions to eligible clients without administrative powers. Confirm historical-state retention, immutable evidence storage, authenticated retrieval through host migration/key changes, and activation's atomic/durable behavior. These are proposed PEEP capabilities, not claims about existing Spaces APIs. Unsupported deployments must report that limitation.

<a id="todo-04"></a>
## TODO-04: Declarations and incremental history — specified

[Declarations](protocol.md#records-and-declarations) select direct key bytes, immutable references, signed predecessor sets, and complete snapshots. [Incremental validation](protocol.md#synchronization-and-bounded-validation) and [restore](protocol.md#local-state-and-recovery) define bounded traversal, starting points, comparison paths, conflicts, and missing-state behavior. Genuine first-observation bootstrap need not replay all history. Validate under 10 and benchmark limits without silently truncating security state.

<a id="todo-05"></a>
## TODO-05: Grants and evidence — specified

[Core's header](core.md#grant-creation) binds declarations, host decisions, epoch/context, evidence, and reported recipient trust. [Manifests](protocol.md#evidence-manifests) define exact-byte packaging, private-provenance boundaries, and separate cryptographic/authorization/coverage results. Archived reading remains distinct from current issuance. Validate byte-level binding, privacy, retention, and historical checks under 10.

<a id="todo-06"></a>
## TODO-06: Freshness and revocation — baseline specified

[Revocation publication/relay](protocol.md#revocation-records), [cached host state](protocol.md#trusted-host-state), and [restore](protocol.md#local-state-and-recovery) preserve learned withdrawals. Approvals do not automatically expire or require fresh per-grant approval. Withholding may leave clients stale indefinitely; no bounded revocation/detection time is promised.

Stricter profiles remain deferred. Expiration needs reliable clocks and renewal by approvers that stop renewing withdrawn selections. Per-grant approval needs an online trusted approver, issuer nonce, exact selection/epoch, deadlines, and replay protection. A fresh nonce response alone proves neither current authority nor consent; any claimed bound must state its assumptions.

<a id="todo-07"></a>
## TODO-07: Rotation — specified

[Rotation context](protocol.md#rotation-context) binds triggering evidence to the new key commitment and requires later grants to enforce inherited restrictions. [Activation/publication](protocol.md#activation-and-publication-state) specifies fresh generation after processing events, atomic expected-predecessor acceptance, numbering, durable idempotency, zero-grant activation, catch-up, queued content, and uncertain uploads. Writers retain the agreed rule: no separate rotation-pending pause, but switch or pause after learning a newer active epoch.

Key distribution uses the same [device verification policy](core.md#device-verification-policy) in both directions: verify the recipient before granting and the issuer before accepting. Verified-only never permits a TOFU binding for either operation. No separate key-provenance mechanism is required. Validate rotation and this symmetric policy under 10.

<a id="todo-08"></a>
## TODO-08: Recovery and backup — implement and validate

[Recovery](protocol.md#local-state-and-recovery) specifies surviving-device approval, independently verified replacement through a helper, withdrawal/notification, history preservation, key-only restore limits, and loss of all key copies. Host administration/PDS login do not recover cryptographic authority. Dedicated recovery-key authority is deferred.

Validate each application's protected backup/pairing container, documenting encryption/key wrapping or KDF, authenticated ownership, atomic import, corruption/rollback handling, and recoverability. Include trust/audit state with keys; do not claim freshness or detection of lost newer state without a surviving reference. Cross-application backup portability is outside this baseline.

<a id="todo-09"></a>
## TODO-09: Publication and audit sync — specified; integrate

[Publication](protocol.md#activation-and-publication-state) defines durable immutable preparation, evidence-first upload, retries, acknowledgment reconciliation, and stopped issuance. [Synchronization](protocol.md#synchronization-and-bounded-validation) defines discovery, direct repo sync, checkpoints/gaps, credential renewal, retained former-participant history, comparison, alerts, and privacy.

Implement against the chosen Spaces transports and validate under 10. Normal access rules govern retrieval; indefinite retention does not extend former members' access. Coverage depends on evidence availability and retained authorization history. No global witness/log or clean-history certificate is required.

<a id="todo-10"></a>
## TODO-10: Interoperability and adversarial validation — outstanding

Publish byte-exact positive/negative vectors, cross-check independent implementations, and obtain independent cryptographic/protocol review. Documentation checks are not substitutes. Each row needs implementation evidence before calling the protocol validated.

| Area | Required cases |
| --- | --- |
| Encoding and cryptography | Fingerprints, verification payload/code, all signing domains, CID/CBOR normalization, grant headers/manifests, HPKE suites/lengths, commitments, record/blob AAD; malformed/duplicate/unknown fields, signatures/points/all-zero KEM inputs, altered contexts, account/space/location substitution, no suite fallback, finite limits, full authentication before plaintext. |
| Host authority | Authenticate current/historical membership/configuration/epochs through migration; credentials/writer lists are not membership or device evidence. No creator signature or issuer appointment. Any eligible enrolled holder may grant current/historical keys, including pre-join epochs; reject known removed issuers/recipients. |
| Verification | Initial PDS substitution versus independently verified rejection; changed pins, downgrades, exact DID/device/both-key QR/full-code comparison through an independent channel. Self-signatures/PDS delivery insufficient; mismatches block until resolution. Reuse across spaces/lifecycle without repeat OOB or bypassing space authorization. |
| Approvals | Same-account additions rooted in TOFU/verified bindings, offline approver reuse, retained private provenance; reject cross-account/space substitution, missing/unanchored/cyclic approval, unjustified promotion, and another issuer's status/grant as verification. Withdrawn approvers cannot establish new bindings through backdated or unaccepted intermediate approvals. |
| Upgrades and policy | Exact-binding upgrade affects future local decisions only; preserve prior grant status and derived provenance, never revive revocations. Verified-only applies to granting and accepting current/historical keys, retries, and direct delivery; issuer and recipient each verify the other locally. One eligible issuer suffices when both checks pass. Reject a TOFU issuer even if the recipient is verified, and a TOFU recipient even if the issuer is verified; valid signatures, host activation, reported recipient trust, and successful decryption cannot bypass these checks. Missing configuration never permits fallback; tightening cannot repair disclosure or invalidate valid archives. First key acceptance from an archive still verifies the issuer; policy tightening preserves prior valid acceptances and historical grant validity. |
| Bootstrap and ancestry | Genuine first observation at an authenticated complete snapshot with unfetched predecessors and existing account pins/withdrawals. Retain starting refs; later updates need comparison paths. Out-of-order delivery, changed/cross-account/space edges, cycles, ancestor replay, new-root reset, and newly discovered pre-bootstrap history. Missing paths prove neither supersession nor conflict and block affected grants. |
| Selections and conflicts | Complete replacement, empty versus missing/deleted snapshot, removal by omission without revoking account-wide trust, no selection of revoked bindings. Authenticated forks pause grants to/from only the affected account/space. No merge/branch choice; accepted unwithdrawn signer can resolve while not selected. Cover every known tip, concurrent resolutions, later forks, invalid evidence, and missing ancestry. |
| Withdrawals | Same-account peer/self, compromised accepted signer withdrawing peers, invalid/cross-account/unknown/withdrawn signers, modified target/scope. Preserve across deletion, replay, restore, future spaces. Previously accepted bindings survive approver withdrawal subject to their own withdrawal. Relays use local trust; withheld updates never imply bounded freshness. |
| Revocation cycles | Mutual/longer/overlapping/late-closing cycles in varied delivery orders. All bindings accepted locally before any cycle withdrawal learned; preserve every withdrawal. Reject missing/incomparable history, timestamps/other-issuer substitutes, invalid/unknown/cross-account edges, later replacements, open chains and outgoing edges outside cycles. Bounded/resumed validation; recovery after all devices withdrawn. |
| Rotation events | Membership removal, selection omission/empty selection, account revocation, mixed updates, current-key compromise. Additions alone or access only to old keys do not rotate unaffected keys. Process exact evidence before fresh generation, no reused candidate, reject context/commitment substitution. Inherit restrictions, block missing required evidence, accept valid later membership/selection but never undo exact-binding revocation. Competing epoch omitting trigger requires fresh proposal; replacement-key disclosure is a new event. Ordering/labels do not prove exclusion. |
| Activation | Competing creation/rotation: one atomic winner, stale requests never auto-activate, exact proposal/commitment, unique IDs, numbering/overflow, durable key before request. Lost replies, restarts, altered-ID reuse, retries after later rotations return original result without rollback. Losing proposals authorize neither writes nor grants. Accept keys only from issuers meeting the device verification policy, including when the issuer generated the epoch. |
| Availability | Zero/partial grants, no self-grant or recipient acknowledgments, unavailable recipients/missing enrollment evidence, later grants under current authorization. Missing active key pauses writers; loss of sole copy/backup loses content. Host acceptance proves neither key durability nor universal delivery. |
| Writers | Continue latest-known active epoch during pending triggers, including compromise, while withdrawals block grants. New active epoch requires switch/pause, no fallback/rollback. Fresh-nonce re-encryption of queued records/blobs; interrupted uploads/cancellation cannot undo exposure. Preserve offline reads/drafts; no global switching deadline. |
| Evidence and archives | Exact issuer/recipient declarations/keys, host decisions, accepted epoch/context, actual retained bytes when source PDS withholds; no private OOB/cross-space provenance leakage or inherited verification. Historical reading after removals/revocations still checks signatures/bindings/evidence/commitment. Missing required evidence blocks; historical uncertainty alone need not block valid decryption but timestamps do not prove ordering. Archives never restore authority or access. |
| Publication retries | Durable bytes/identity before release, evidence-first upload, crashes before/after publication/ack, identical retries give one record. Changed bytes are new issuance. Recheck both parties/policy/context/withdrawals/conflicts/evidence on retries/direct delivery, even after acknowledgment. Missing acknowledgment leaves exposure uncertain and forbids direct forwarding; stopped retries preserve published audit records. |
| Auditing | TOFU substitution detected through honest issuer repo and retained own history despite source withholding. Forged audit signatures, stale formerly authorized versus never-authorized keys, legitimate revisions, suppression/collusion, unknown history, observations versus grants. Signature attributes statement, not PDS misconduct or decryption. Review metadata and transferable-signature privacy. |
| Retention and sync | Indefinite grants, exact evidence, declarations including superseded snapshots/branches/resolutions; preserve through migration/rotation/revocation/membership/restore. Host discovery plus retained participants, former repos while authorized, audit before key delivery, interrupted checkpoints/gaps, expiry/deletion/unavailable history. Offline catch-up, retained local auditing after removal without promised further access; no all-grants-seen claim. Background gaps neither bypass grant checks nor block unrelated work. |
| Recovery/transfer | Surviving approval or independent helper verification of fresh keys, one eligible holder can restore retained epochs without transferring trust to others. Reject PDS-only replacement, fresh-TOFU fallback, revived withdrawals or re-invitation history reset. Authenticated/confidential keys plus pins/provenance/order/withdrawals/conflicts; older imports preserve newer known state. Missing/incomparable history cannot invent prior acceptance; key-only restore cannot recreate trust; all copies lost means plaintext lost. |

<a id="todo-11"></a>
## TODO-11: Independent content authentication — deferred

Define a separate profile for device-authenticated content/location/revision binding and replay handling, accounting for transferable signatures and deniable rebroadcast. Enrollment signatures do not upgrade [Format 1's authorship guarantee](core.md#encrypted-records).

<a id="todo-12"></a>
## TODO-12: Platform integration — validate

Validate Ed25519/X25519 operations, installation identity, protected storage, pairing, backup/restore, and independent-app behavior on each target platform. Check hardware facilities and Android KeyChain algorithm compatibility rather than assuming support. Validate browser origin/profile isolation and state loss. See [storage constraints](device-enrollment.md#storage--its-implications).

<a id="todo-13"></a>
## TODO-13: Authenticated streaming — deferred

Large media, seeking, or early playback needs a separate versioned format authenticating chunk order/count, total length, object identity, and final manifest, with truncation and cross-object substitution tests. [Format 1](core.md#encrypted-blobs) remains bounded and requires whole-file authentication.
