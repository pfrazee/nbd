# PEEP: Open Questions and Validation Work

The specs select optional independent verification local to each issuer, supported TOFU, and signed grants as mandatory audit records published with their evidence in issuers' own repos. The items below track remaining decisions and validation; alternatives within them are not selected requirements. Cross-user verification attestations in TODO-02, and TODO-11 and TODO-13, are deferred extensions.

Suggested decision order: trust/bootstrap (02), authority (03), approval (01), declarations/evidence (04–05), remaining audit details (09), freshness/rotation/recovery (06–08), then validation (10, 12). IDs remain stable for links.

<a id="todo-01"></a>
## TODO-01: Authenticate the user's selection

Choose the approval and continuity mechanism for both TOFU and independently verified bindings. For the device-signature candidate, define placement, canonical signing input, domain separation, rejection rules, and how the client confirms keys and user intent. A shared space-key MAC cannot identify the consenting account. Verified bindings must prevent substitution before release; TOFU cannot make that first-contact guarantee. Freshness remains separate under [TODO-06](#todo-06).

[Spec: substitution prevention](device-enrollment.md#preventing-pds-substitution).

<a id="todo-02"></a>
## TODO-02: First trust and local verification

Settled: verification is local to each issuer. Its verification decision does not establish verified trust for other users, and a device needs only one valid grant from an authorized issuer for each epoch's key.

Define exactly which account/device/key binding is pinned, independent verification methods, reuse across spaces, and authentication of space configuration. Specify pin storage, verification status, transition from TOFU to verified trust, and explicit handling of changed bindings or lost state. Define authenticated transfer/restore of local trust state between the issuer's own trusted installations. Decide how a space can require verified issuance by all issuers.

Deferred: cross-user verification attestations and their trust/delegation rules. This does not settle whether an accepted device can authorize additional devices for its own account; see [TODO-01](#todo-01) and [TODO-03](#todo-03).

[Spec: first trusted binding](device-enrollment.md#establishing-the-first-trusted-binding).

<a id="todo-03"></a>
## TODO-03: Membership and authority boundaries

Define how issuers authenticate Spaces membership/configuration decisions and receive changes. Choose approval and issuance roles, delegation evidence, account-scoped versus space-wide powers, eligibility to grant historical keys, and who can withdraw each role. Specify the effect of account removal. Do not assume that receiving a grant confers other powers.

[Spec: authorization](core.md#configuration-and-authorization).

<a id="todo-04"></a>
## TODO-04: Declaration format and updates

Define the lexicon, location, canonical encoding, and direct-key or immutable-reference representation. Choose full selections versus updates; specify replacement, withdrawal, empty selections, deletion, concurrent edits, rollback protection, and conflict handling. Avoid merging selections in ways that restore removed devices. Distinguish legitimate revisions from conflicting claims without assuming a global chain.

[Spec: declarations](device-enrollment.md#in-space-declarations).

<a id="todo-05"></a>
## TODO-05: Grant evidence and wire format

Finalize the provisional `enrollmentReference.declaration` binding, approval, membership, and issuer-authority evidence, and reporting of the issuer's local trust decision. Any reported verification status is an issuer statement, not a transferable verification attestation. Specify what accompanies a grant, what is retained/retrieved, rejection behavior, and validation of archived grants. The signed grant is the audit record: finalize how its published record carries exact declaration/key/approval bytes, cryptographically bound to the grant, under [TODO-09](#todo-09). Verification and audit evidence must be readable without the granted key or a substituted recipient private key.

Define historical-authority checks without assuming a trusted issuance timestamp or registry commit receipt.

[Spec: grant creation](core.md#grant-creation) and [delivery](core.md#grant-delivery).

<a id="todo-06"></a>
## TODO-06: Grant freshness and revocation

Choose a default and any supported alternatives:

| Candidate | Tradeoff |
| --- | --- |
| Reusable approval | Asynchronous grants; replay is unbounded while updates are withheld. |
| Expiring approval | Limits old-approval replay if expiration is enforced and trusted approvers stop renewing withdrawn selections; requires renewal and reliable clocks. |
| Fresh per-grant approval | Requires an online trusted approver; bind an issuer nonce, exact selection, and target epoch, with a response deadline and replay protection. |

Apply freshness to membership, recipients, and approving/issuing authority in both trust modes. Define behavior for unavailable evidence, stale approvers, clock uncertainty, cached state, and restore. Any revocation bound must state its assumptions; independent verification, grant audit records, or a fresh response alone do not establish globally current authorization.

[Spec: grant freshness](device-enrollment.md#grant-freshness).

<a id="todo-07"></a>
## TODO-07: Rotation and writer behavior

Define rotation authority, epoch metadata authentication/distribution, numbering, concurrent rotations, recipient selection, required grant coverage, and completion. Handle enrollment changes during distribution. Choose writer behavior for offline publication, stale state, reconnect/restore, queued drafts, and interrupted uploads, with explicit exclusion timing and availability tradeoffs.

[Spec: revocation and rotation](core.md#revocation-and-rotation).

<a id="todo-08"></a>
## TODO-08: Recovery and authority replacement

Choose recovery through surviving devices, previously authenticated recovery material, or independent re-verification. Define compromised-key replacement, withdrawals, notification, and evidence for other issuers, including recovery from an attacked TOFU bootstrap. Separately specify content backups and administrator succession. Cover reinstall, loss of every account device, loss of the sole key holder, and loss of all administrative authority without silently resetting trust; preserve audit/authorization history or report its loss.

[Spec: recovery and succession](core.md#recovery-and-succession).

<a id="todo-09"></a>
## TODO-09: Grant auditing through issuer repos

Settled: the signed grant itself is the audit record. Publish it with exact supporting evidence in the issuer's own permissioned repo; direct delivery forwards the same record only after publication is acknowledged. Retain grants and evidence indefinitely under normal Spaces access rules. Former members may keep synced evidence; further audit access is not guaranteed. See [Core's retention and access rules](core.md#grant-delivery). Packaging remains [TODO-05](#todo-05).

Remaining decisions:

- Define retries, duplicate handling, and recovery from crashes or uncertain write outcomes. An acknowledgment does not prove durable availability; a missing acknowledgment does not prove the grant was never exposed.
- Define issuer discovery, direct-sync coverage, and catch-up under normal Spaces access rules, including access before receiving keys and behavior when a PDS withholds evidence or credentials expire.
- Specify preservation of clients' authorization history, comparison, alerts, missing-history handling, and what establishes unauthorized selection, stale authorization, or attributable misconduct. Account for legitimate revisions/concurrent edits, issuer-signature trust, and metadata/transferable-signature privacy.

No separate witness or global log is required. Detection remains conditional on an honest issuer and eventual access to retained evidence and authorization history; neither a detection deadline nor universal proof of a clean history is promised.

[Spec: inconsistent views](device-enrollment.md#detecting-inconsistent-views).

<a id="todo-10"></a>
## TODO-10: Interoperability and adversarial validation

Publish byte-exact vectors and validate independent implementations of fingerprints, CBOR contexts, signatures, HPKE grants, and content envelopes. Exercise malformed encodings, modified contexts, cross-account/space reuse, missing approval, unauthorized issuers, bootstrap for every issuer, replacement, concurrency, replay after withdrawal, restore, and removal during issuance/rotation.

Test verified-binding rejection of substituted keys; TOFU substitution followed by detection through an honest issuer's repo; changed pins and verification downgrades; isolation of issuers' local verification decisions; misuse of a published grant as a verification attestation; one TOFU issuer exposing a shared key; missing declaration bytes/history, forged grant audit records, suppressed evidence, publication failures, and attempts to deliver directly before publication is acknowledged. Validate retention through rotation, revocation, membership changes, and migration; offline catch-up while access remains authorized; and local auditing of synced evidence after removal without guaranteed further retrieval. Tests must distinguish incomplete audits from clean results and observations from issuance.

[Spec: grant profile](core.md#mandatory-grant-profile).

<a id="todo-11"></a>
## TODO-11: Deferred independent content authentication

Define device-authenticated content/location/revision binding, replay handling, and the effect of transferable signatures on deniable rebroadcast. This requires a separate profile; enrollment approvals do not upgrade Format 1's authorship guarantee.

[Spec: encrypted records](core.md#encrypted-records).

<a id="todo-12"></a>
## TODO-12: Platform integration validation

Validate Ed25519/X25519 operations, protected storage, installation identity, pairing, backup/restore, and independent-app behavior. Check Android KeyChain and hardware-backed facilities for algorithm compatibility; support is not assumed.

[Spec: storage](device-enrollment.md#storage--its-implications).

<a id="todo-13"></a>
## TODO-13: Deferred authenticated streaming

Define a separate versioned format for large media, seeking, or early playback. Authenticate chunk order/count, total length, object identity, and a final manifest; test truncation and cross-object substitution. Format 1 remains bounded and requires whole-file authentication.

[Spec: encrypted blobs](core.md#encrypted-blobs).
