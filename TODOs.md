# PEEP: Open Questions and Validation Work

The specs select optional independent verification, supported TOFU, and mandatory grant auditing through issuers' own repos. The items below track remaining decisions and validation; alternatives within them are not selected requirements. TODO-11 and TODO-13 are deferred extensions.

Suggested decision order: audit delivery/retention (09), trust/bootstrap (02), authority (03), approval (01), declarations/evidence (04–05), freshness/rotation/recovery (06–08), then validation (10, 12). IDs remain stable for links.

<a id="todo-01"></a>
## TODO-01: Authenticate the user's selection

Choose the approval and continuity mechanism for both TOFU and independently verified bindings. For the device-signature candidate, define placement, canonical signing input, domain separation, rejection rules, and how the client confirms keys and user intent. A shared space-key MAC cannot identify the consenting account. Verified bindings must prevent substitution before release; TOFU cannot make that first-contact guarantee. Freshness remains separate under [TODO-06](#todo-06).

[Spec: substitution prevention](device-enrollment.md#preventing-pds-substitution).

<a id="todo-02"></a>
## TODO-02: First trust and its distribution

Select independent verification methods and define what pairing/invitations authenticate, including space configuration. Specify who can attest to bindings, attestation scope, reuse across spaces, and how every issuer—including new or restored installations—obtains evidence. TOFU is supported: define pin storage, verification status, transition to verified trust, and explicit handling of changed bindings or lost state. Decide how a space can require verified issuance by all issuers.

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

Finalize the provisional `enrollmentReference.declaration` binding and approval, trust-status/bootstrap, membership, and issuer-authority evidence. Specify what accompanies a grant, what is retained/retrieved, rejection behavior, and validation of archived grants. Prefer reusing the signed grant as an issuance receipt where it meets [TODO-09](#todo-09), retaining exact declaration/key/approval bytes. Verification and audit evidence must be readable without the granted key or a substituted recipient private key.

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

Apply freshness to membership, recipients, and approving/issuing authority in both trust modes. Define behavior for unavailable evidence, stale approvers, clock uncertainty, cached state, and restore. Any revocation bound must state its assumptions; independent verification, audit receipts, or a fresh response alone do not establish globally current authorization.

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

Define the mandatory audit flow using device-signed evidence in each issuer's own permissioned repo:

- Choose the receipt/observation lexicon and signing context, binding exact declarations, keys, trust status, and grants; distinguish observations from issuance claims.
- Define retention of evidence and clients' authorization history, publication ordering relative to grant exposure, retries, and crash/failure handling. A repo write acknowledgment does not prove durable availability to other clients.
- Define issuer discovery and direct-sync coverage, catch-up, access before receiving keys and after removal, and behavior when a PDS withholds evidence or credentials expire. Set any retention window and its offline-audit limits explicitly.
- Specify comparison, alerts, missing-history handling, and what establishes unauthorized selection, stale authorization, or attributable misconduct. Account for legitimate revisions/concurrent edits, receipt-signer trust, and metadata/transferable-signature privacy.

No separate witness or global log is required. Detection remains conditional on an honest issuer and eventual access to retained evidence and authorization history; neither a detection deadline nor universal proof of a clean history is promised.

[Spec: inconsistent views](device-enrollment.md#detecting-inconsistent-views).

<a id="todo-10"></a>
## TODO-10: Interoperability and adversarial validation

Publish byte-exact vectors and validate independent implementations of fingerprints, CBOR contexts, signatures, HPKE grants, and content envelopes. Exercise malformed encodings, modified contexts, cross-account/space reuse, missing approval, unauthorized issuers, bootstrap for every issuer, replacement, concurrency, replay after withdrawal, restore, and removal during issuance/rotation.

Test verified-binding rejection of substituted keys; TOFU substitution followed by detection through an honest issuer's repo; changed pins and verification downgrades; one TOFU issuer exposing a shared key; missing declaration bytes/history, forged receipts, suppressed evidence, and publication failures. Tests must distinguish incomplete audits from clean results and observations from issuance.

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
