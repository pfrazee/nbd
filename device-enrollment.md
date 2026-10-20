# PEEP: Device Enrollment

Status: Discussion draft

1. Users publish device public keys publicly.
2. The trusted space host determines participating accounts through Spaces membership.
3. Each participant publishes an in-space declaration listing their complete selection of exact device keys.
4. Key issuers use those declarations to select recipients and publish device-signed grants, which also serve as the audit records.

Declarations are the enrollment state, constrained by account-wide device revocations. This model requires neither a separate enrollment registry service, a global chain, nor creator approval for every device addition. Independent key verification is optional where the [space's device verification policy](core.md#device-verification-policy) permits TOFU; signature validation, exact-key matching, continuity checks, and grant auditing are required. [Protocol Details](protocol.md) defines the baseline encodings and client procedures.

## Device keys

### Publication

Each app installation generates Ed25519 signing and X25519 recipient-encryption keys under [Core's profile](core.md#mandatory-grant-profile), keeps the private keys locally, and publishes:

```typescript
// Public repo record; rkey = device ID.
{
  $type: "com.example.peep.device",
  value: {
    account: string, // Repo owner's DID.
    device: { deviceId: string, authPubkey: bytes, encryptPubkey: bytes }
  }
}
```

Both public keys use the profile's 32-byte encodings. The publication is reusable across spaces and contains no membership or per-space selection. Replacing either key requires a new selection accepted under the enrollment trust policy; a mutable record URL cannot redirect an existing approval.

### Storage & its implications

A device identity represents an app installation. Independent apps on the same physical device enroll separately. Browser identities belong to an origin within a browser profile. Keys may be reused across spaces, but declarations and content keys are space-specific.

Platform stores can protect keys, but hardware backing and cross-app sharing are not assumed:

| Platform | Storage constraints |
| --- | --- |
| iOS / iPadOS | [Keychain sharing](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps) requires the same developer team. |
| Android | [Keystore](https://developer.android.com/privacy-and-security/keystore) is app-private; [KeyChain](https://developer.android.com/reference/android/security/KeyChain) offers user-approved sharing, subject to algorithm support. |
| macOS | [Modern Keychain](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains) uses access groups; older file-based keychains support per-app access lists. |
| Windows | [CNG](https://learn.microsoft.com/en-us/windows/desktop/SecCNG/key-storage-and-retrieval) stores keys; [DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) does not by itself isolate same-user apps. |
| Linux | [Secret Service](https://specifications.freedesktop.org/secret-service/latest-single/) leaves application access controls to implementations. |
| Web | [WebCrypto](https://www.w3.org/TR/WebCryptoAPI/#concepts-key-storage) storage is normally origin-separated, without a common device keychain. |

Operation, storage, and pairing validation remain [TODO-12](TODOs.md#todo-12). Storage protections do not protect plaintext from malicious application code or updates.

## In-space declarations

A declaration is a complete selection snapshot for one account in one space, listing each selected device ID and its exact signing/encryption key pair as embedded public-key bytes under the [declaration format](protocol.md#records-and-declarations). Device IDs alone are insufficient. Public key publication does not enroll a device, and a declaration cannot grant account membership. Removing a device from one space changes that space's declaration; it does not revoke the account/device binding or its use in other spaces.

A valid replacement supersedes the previous selection: omitted devices are no longer enrolled in that space. An authenticated empty selection means no devices are enrolled. These removals do not alter account membership or revoke device trust bindings. No snapshot may override a known account-wide revocation. A missing or deleted record is not an authenticated empty selection.

Accepted devices may approve selections for their own account as described below. Selection or key possession alone does not confer approval authority; membership and administration follow the [trusted space host](core.md#configuration-and-authorization).

### Snapshot history

Each declaration's signature binds content-addressed references to the snapshots it replaces. Referenced snapshots must belong to the same account and space. The initial snapshot has no predecessor; a normal update references one predecessor. A resolution references all known competing branch tips: snapshots not yet superseded by another known snapshot.

Clients establish replacement order through validated signed ancestry. Replaying an ancestor cannot restore its selection after a descendant has been accepted, and a new predecessor-free snapshot cannot reset known history. Timestamps and delivery order do not establish supersession. This history is scoped to one account in one space and does not prove that no updates were withheld.

### Bootstrap and incremental validation

First establish the declaration signer's exact account/device/key binding through retained trust, a valid same-account approval path, independent verification, or permitted initial TOFU. Authenticate the complete selection and apply normal membership, trust-policy, and known-withdrawal checks. A new space cannot reset an existing account pin or revocation; an unknown signer's self-signature alone is not independent verification.

On genuine first observation of an account's declarations in a space, with no retained declaration state or known conflict, a client may accept that authenticated snapshot as its local starting point. It need not fetch ancestry back to the initial declaration, even when the snapshot has predecessor references. Retain the exact signed snapshot and its references; this does not create a new predecessor-free root or prove the snapshot is latest, history is complete, or no revocation was withheld.

Thereafter, validate the ancestry needed to connect updates to known state or resolve all known competing tips. An ancestor cannot roll back state, and an unrelated snapshot cannot replace a known history. Missing evidence needed to establish that relationship blocks the affected grant. Newly learned history is checked against retained state under the same conflict and withdrawal rules; it is not ignored because it predates the starting snapshot.

Restored clients use their saved starting points and trust state. Lost history requires explicit recovery and must be reported as missing, not silently treated as first use. Bootstrap cannot manufacture prior acceptance for approver-withdrawal or revocation-cycle rules. Historical auditing continues in the background under normal access and retention rules; it does not require replaying every declaration before ordinary operation.

[Protocol Details](protocol.md#records-and-declarations) defines declarations and references, with [bounded incremental validation](protocol.md#synchronization-and-bounded-validation) and [restore rules](protocol.md#local-state-and-recovery).

### History retention

Each account must retain every published signed declaration snapshot and its space-specific authorization evidence indefinitely in its own space repo, including superseded snapshots, competing branches, and resolutions. Preserve this history during migration; snapshot replacement, conflict resolution, key rotation, device revocation, or membership changes must not prune it.

Issuers must retain and publish the starting snapshots and incremental ancestry used for issuance under [Core's grant-evidence scope](core.md#grant-evidence) and [retention rules](core.md#grant-delivery). Earlier private trust provenance is retained locally; reuse must not expose declarations from another space. Hash references alone do not preserve the published evidence. Declaration history follows the same normal Spaces access rules: former members may keep synced history, but further access is not guaranteed. Availability still depends on the repos remaining hosted and accessible; retention does not establish a complete or fresh view.

### Conflicting declarations

Distinct authenticated snapshots compete when validated ancestry shows neither supersedes the other; for example, two independent updates replacing the same predecessor. Once a client detects this, it must pause new grants involving that account as recipient or issuer in that space until an explicit resolution is accepted. Do not automatically merge selections or choose a branch. An ordinary authenticated replacement is not a conflict; invalid evidence cannot create one.

Resolution requires a complete selection snapshot referencing all known competing branch tips, signed by a locally accepted, unwithdrawn device of the same account. The resolving device need not be selected in the disputed snapshots. Normal trust and authorization checks still apply, including known account-wide revocations. A newly discovered unresolved conflict pauses grants again. This rule acts on locally observed evidence; it cannot prevent grants made before a hidden conflict is discovered.

Competing resolutions follow the same rule. Missing ancestry is not proof of a conflict or of supersession; missing evidence required to validate the selected state blocks grant release.

### Preventing PDS substitution

A PDS could show the user their original declaration and an issuer a forged one. Inspecting one's own declaration cannot prevent that disclosure. Clients apply the space's device verification policy before either granting a device a key or accepting a key from it. They support two trust modes:

- **Independently verified:** bind the intended account to exact keys through out-of-band (OOB) verification, a previously verified local binding, or valid same-account approval rooted in such a binding, then validate the recipient or issuer against that binding.
- **TOFU:** accept and pin an initial account-to-key binding without independent verification. This permits substitution at first acceptance; later continuity checks do not repair a compromised initial binding.

Optional verification concerns the account-to-key binding, not cryptographic validation. Neither mode permits skipping required signatures, exact-key matching, or continuity checks. A new binding must follow the approval or recovery policy rather than silently replacing a pin.

The declaration's Ed25519 signature is the selection approval; no separate approval record is required. An issuer may accept additional devices through a declaration signed by a device it already accepts for the same account, subject to withdrawals and freshness rules. The signature covers the protocol purpose/version, exact space, account, complete selected device bindings, and predecessor references. The approving client must authenticate the intended keys and user intent, such as through pairing, rather than blindly sign a PDS-supplied list.

For example, Alice's phone can approve her laptop. Bob validates that approval against the phone binding he already accepts, requires the approving and approved bindings to name Alice's account, and encrypts only to the exact selected laptop key. Approval learned solely through a TOFU binding remains TOFU; an approval path rooted in a locally verified binding can support verified trust, with its provenance retained. A self-signature or cycle of signatures between unknown keys cannot establish a verified root.

The new device binding follows the same reuse rules across spaces, but the signed declaration authorizes selection only in its named space. Approval does not confer account membership, authority over another account, or administrative powers. Retained signed declarations can supply approval paths for offline validation. [Protocol Details](protocol.md#records-and-declarations) specifies signing, pairing confirmation, path validation, and rejection rules.

An independently verified root, uncompromised approving devices, and valid exact-key approvals prevent PDS substitution for grants made against them. They do not prove that a selection or signer remains authorized. In a verified-only space, every client enforces verified bindings in both directions; TOFU cannot authorize either a grant or acceptance of a key. In spaces permitting TOFU, a substituted recipient can receive the key and a substituted issuer can supply a key it knows, despite other clients' verification.

### Establishing the first trusted binding

A local trust record binds the exact account DID, device ID, Ed25519 signing public key, and X25519 encryption public key. Both TOFU pins and independently verified status are reused for this binding across spaces; the binding contains no space identifier. Applications may compose a group or chat from many frequently created spaces, so trust records must persist independently of individual spaces. Creating, joining, leaving, or deleting a space must not reset the binding or require repeat OOB verification of an unchanged binding.

Changing any component creates a different binding and must not silently inherit verified status. An issuer with an existing pin requires valid same-account approval or explicit independent re-verification of a replacement under the [recovery rules](core.md#recovery-and-succession). A new space must not bypass a known key conflict. Each space still requires its own membership, authenticated device selection, authority checks, and freshness policy, including known withdrawals.

Self-signatures, possession challenges, PDS login, and repository publication do not independently bind a key to the intended user. An issuer can reuse its own verified binding or establish one through [independent verification](#independent-verification); an account-only invitation is insufficient. The joining device authenticates the space host and obtains the space configuration from it.

Verification is local to each client, whether issuing or accepting a key. Bob verifying Alice does not make her keys verified for Carol; Carol can make her own TOFU or verification decision under the applicable policy. Cross-user attestations that transfer verification are deferred. A published grant or reported verification status is audit evidence, not such an attestation. Same-account device approvals are supported because each issuer validates them against its own accepted account binding.

Every client, including new or restored installations, must record accepted bindings and distinguish TOFU from independently verified trust. Deletion, rejoining, reinstall, or state loss must not silently reset trust or downgrade verification. Device backup/transfer preserves trust under the [rules below](#device-backup-and-transfer). [Protocol Details](protocol.md#independent-verification) defines the verification representation and confirmation flow, with [private state procedures](protocol.md#local-state-and-recovery).

### Private trust history

Keep OOB verification records, earlier approval provenance, local acceptance history, and known revocations in private local trust state and its backups. A binding accepted in one space can authenticate that device's declaration in another without republishing the earlier space's declarations. For example, Bob may use the laptop binding he accepted in space A to validate Alice's laptop-signed declaration in space B; B's grant publishes B's authorization evidence.

The [published grant evidence](core.md#grant-evidence) records the issuance decision and its space-specific basis. It need not reconstruct the issuer's earlier reasons for trusting an already accepted binding. Another issuer or auditor uses its own trust records; the published trust status or starting snapshot does not transfer the issuer's verification decision or prove a complete history.

### Independent verification

Use one verification representation binding the exact account DID, device ID, Ed25519 signing public key, and X25519 encryption public key. It contains no space identifier. The baseline supports:

- A QR code scanned directly from the intended person's device.
- A human-readable safety code compared over an independently authenticated channel.

Both forms bind the same complete tuple. Before marking a binding verified, confirm the intended account and match the independently obtained representation against the exact binding the client will use. Merely receiving or scanning a code delivered through the same potentially malicious PDS does not establish independent verification. Existing space-authorization and withdrawal rules still apply.

The [verification encoding](protocol.md#independent-verification) defines the QR payload and full SHA-256 safety code for this binding, with strict comparison and explicit confirmation.

### Upgrading a TOFU binding

Successful independent verification of the exact pinned account DID, device ID, Ed25519 signing key, and X25519 encryption key upgrades that binding to locally verified trust for future grants and key acceptances across spaces. Valid same-account approval paths rooted in it can also establish verified trust in approved bindings; retain their approval provenance and distinguish them from directly verified bindings. All withdrawal and space-authorization rules still apply: verification cannot revive a withdrawn binding or authorize a new binding solely through a known-withdrawn approver.

Retain earlier grants and their evidence with the trust decisions made at issuance. Later verification must not relabel a TOFU grant as verified; it cannot undo disclosure or establish that every earlier grant was authorized. Other issuers' trust decisions remain local.

If independent verification conflicts with the pinned binding, record the mismatch and block grants and key acceptances relying on that disputed binding until explicit resolution through valid same-account approval or independent re-verification under the [recovery rules](core.md#recovery-and-succession). Do not silently overwrite the pin or fall back to TOFU. Use the same [verification encoding](protocol.md#independent-verification) for initial verification, upgrades, and recovery.

### Device backup and transfer

Device backup/transfer must include local trust state alongside the keys it preserves. Authenticate and encrypt transfers between the user's own trusted installations and protect backups for authenticated, confidential restore. Preserve exact account/device/key pins, TOFU or verified status, approval provenance, local acceptance history, known withdrawals, and retained declaration history/conflicts. This can carry the issuer's existing verification decisions to its replacement or additional installation; it does not transfer verification between users.

Import must not silently replace conflicting pins, clear known withdrawals or unresolved conflicts, or roll back newer known state. Report missing history explicitly; restore cannot manufacture prior acceptance or establish an ordering absent from the retained history. Keys alone cannot reconstruct lost trust records. A restored snapshot does not establish freshness, and normal authorization and withdrawal checks still apply.

Use the device backup/transfer mechanism for this state; a separate trust-sync protocol is deferred. [Local state and recovery](protocol.md#local-state-and-recovery) specifies required contents, protection, ordering, and merge rules. Applications use their protected backup/transfer container; implementations still require [backup](TODOs.md#todo-08) and [platform validation](TODOs.md#todo-12).

### Detecting inconsistent views

Auditing is part of the baseline. [Spaces applications sync each participant's repo directly from its host](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data#spaces), providing an evidence path outside the affected user's PDS:

1. Alice's PDS shows Bob a forged declaration selecting attacker-controlled keys.
2. Bob's device signs a grant identifying that declaration and the exact recipient keys, and publishes it with the supporting evidence in Bob's own permissioned repo for the space.
3. Alice syncs Bob's repo, validates the evidence, and compares it with her authorized selections. She can detect keys she never authorized even if her PDS keeps showing her the original declaration.

The signed grant itself is the audit record, binding the issuer, space, epoch/key ID, recipient account/device, and exact declaration and keys. Publish and retain it with the exact bytes required by [Core's grant-evidence scope](core.md#grant-evidence), including the signed declarations, resolved keys, and space-specific authorization/ancestry used. Earlier private trust provenance stays local. [Core's delivery and retention rules](core.md#grant-delivery) require publication before direct forwarding and indefinite retention of the published evidence. [Evidence manifests](protocol.md#evidence-manifests) bind that package; [publication procedures](protocol.md#activation-and-publication-state) define durable retries and uncertain outcomes.

Clients discover participant repos through authenticated host writer discovery, available membership information, and retained participant/issuer history. Writer discovery alone does not establish membership eligibility. Direct sync covers those known repos under normal Spaces access rules, including known former participants' repos while access remains permitted. Audit grants addressed to the client's account during sync, with resumable background catch-up that does not depend on obtaining content keys. Preserve audit progress and known coverage gaps across interruptions.

Clients must compare that evidence against retained authorization history and alert on unauthorized keys or conflicting selections. Verify the issuer's device signature under the recorded trust policy; repository authentication alone is insufficient. Distinguish legitimate revisions from conflicts, and stale authorized selections from keys never authorized. Observations without a signed grant do not establish issuance. An issuer's signature attests to its statement; by itself it does not prove PDS misconduct or that a recipient decrypted the grant.

Detection depends on an honest issuer retaining and publishing evidence, the affected client eventually obtaining it, and sufficient authorization history to recognize the mismatch. Direct sync removes the affected PDS as the sole evidence path; it does not guarantee discovery under withholding or colluding hosts, loss of read access, or indefinite isolation. Report unreachable repos, lost read access, missing history, and other known coverage gaps as an incomplete audit; matching grant records do not prove all grants were observed. Detection cannot undo disclosure and has no promised deadline.

Audit catch-up does not require waiting for every repo before ordinary reads, writes, or grant issuance. All normal authorization and writer checks still apply: missing or invalid evidence required for a particular grant, known withdrawals, or unresolved declaration conflicts still block that grant.

Authorized readers must be able to inspect evidence without the key being granted or the possibly substituted recipient private key. Normal Spaces access rules apply: after leaving or removal, users may retain synced evidence but have no guarantee of further audit access. [Synchronization procedures](protocol.md#synchronization-and-bounded-validation) specify discovery, checkpoints, gaps, comparison, and privacy boundaries; [evidence manifests](protocol.md#evidence-manifests) specify packaging.

## Key issuance and content flow

Any currently eligible participant's enrolled device holding the key can issue [encrypted grants](core.md#grant-creation) after applying [Core's authorization checks](core.md#authorization-before-grant-release). Current members' enrolled devices may receive all retained historical keys, including pre-join epochs. One valid grant from an authorized issuer supplies the epoch key when the issuer's check of the recipient and the recipient's check of the issuer both meet the [space's device verification policy](core.md#device-verification-policy). Verification by every participant is unnecessary. Issuance waits if no eligible key holder is available. Initial verification evidence must be accessible without the key being granted, using the [evidence package](protocol.md#evidence-manifests).

Historical reading follows [archived-grant validation](core.md#archived-grant-validation), separately from current authorization for new grants. Devices encrypt and decrypt locally; plaintext caches, search, previews, and exports stay on devices. Spaces still governs ciphertext access and writes. [Core](core.md) defines content formats and authorship limits.

## Revocation and recovery

### Device withdrawal authority

Any accepted, unwithdrawn device may withdraw itself or another device binding of the same account. The withdrawal must carry an Ed25519 signature binding the revocation purpose/version, account, exact target binding, and account-wide scope; no list of spaces is required. Before applying it, an issuer verifies the signature against its locally accepted signer binding, checks that the signer is not known to be withdrawn except under the [revocation-cycle rule](#device-revocation-cycles), and requires signer and target to belong to the same account. This applies in both TOFU and independently verified modes.

No separate creator or administrator approval is required. This authority confers no control over another account's devices or Spaces membership. A compromised accepted device can withdraw its peers. [Revocation records](protocol.md#revocation-records), [local acceptance history](protocol.md#local-state-and-recovery), and [bounded validation](protocol.md#synchronization-and-bounded-validation) specify implementation requirements.

### Device revocation cycles

A revocation cycle contains two or more distinct bindings of the same account, each revoking the next, with the last revoking the first. This includes mutual revocations and longer cycles such as A → B → C → A. Accept every revocation in a cycle if every signature, exact binding, and scope validates and the issuer had locally accepted all its bindings before learning a valid revocation of any of them. Once the complete cycle is available, withdraw all its devices regardless of statement delivery order, even if some signers have already been withdrawn.

Apply the exception separately to each qualifying cycle; revocations outside those cycles still require ordinary signer authority. Preserve every already accepted revocation. Require retained local acceptance history: claimed signing dates or another issuer's acceptance cannot substitute for it, and missing history cannot establish eligibility. The exception grants no general authority to withdrawn devices and cannot include a replacement binding accepted after a withdrawal of any device in that cycle was learned.

A late statement can complete a cycle and withdraw its remaining devices; signatures do not prove concurrent issuance. This availability tradeoff can leave no usable trusted device. Use the [recovery rules](core.md#recovery-and-succession): a surviving accepted device can approve a replacement, or an eligible issuer can independently verify fresh keys and grant the keys it holds.

### Account-wide device revocation

A validated revocation applies to the exact account DID, device ID, and signing/encryption key binding across all current and future spaces. Clients retain it with their account/device trust state and block new grants to that binding, new issuance by it, and new approvals or declarations relying on its authority. A space declaration cannot override it. Record deletion, old declarations, or creating/joining another space must not clear a known revocation.

Publish signed revocations in the account's public repo alongside device-key publications. Clients discover them with public device records; the original signed statements may also be copied into space repos or forwarded by peers. Each receiver validates the signer against its own accepted bindings; relaying a statement does not transfer the relay's verification decision. [Revocation records](protocol.md#revocation-records) specify publication, discovery, forwarding, and cycle-candidate retention.

Enforcement begins when each client learns and validates the revocation; withholding can delay it indefinitely. Revocation does not erase existing keys or plaintext. Each space where the device had access to the current key must [rotate](core.md#revocation-and-rotation) to exclude it from future content.

### Withdrawing an approving device

Withdrawing a device's approval authority does not automatically withdraw other bindings an issuer accepted through it before learning of the withdrawal. Preserve those bindings' trust status and provenance. Their own withdrawals and current space membership/selection still apply; surviving accepted devices may continue approving devices for their own account.

After learning of the withdrawal, an issuer must reject new bindings relying solely on the withdrawn approver, including approval paths through previously unaccepted devices. A claimed earlier signing date or another issuer's acceptance does not by itself establish prior local acceptance. New bindings need another valid trust basis, such as approval by an accepted, unwithdrawn device of the same account or independent verification. An issuer must not bypass this rejection by falling back to TOFU.

Preserving a binding does not authorize new declarations signed by the withdrawn device. Apply the [backup and transfer rules](#device-backup-and-transfer); [local state](protocol.md#local-state-and-recovery) preserves acceptance ordering without treating timestamps or unrelated imported histories as proof.

### Grant freshness

Approvals are reusable without automatic expiry. Issuers may reuse an otherwise valid approval while its approving device is offline; no fresh signature or approving-device contact is required for each grant. All [authorization checks](core.md#authorization-before-grant-release) still apply, including required evidence, signatures, exact-key matching, and continuity.

Clients must enforce authenticated withdrawals they learn about and must not let cached approvals override them. This applies to membership, recipients, and approving/issuing authority in both trust modes. [Revocation propagation](protocol.md#revocation-records), [cached host state](protocol.md#trusted-host-state), and [restore rules](protocol.md#local-state-and-recovery) preserve learned withdrawals. An epoch's [rotation context](protocol.md#rotation-context) additionally requires later issuers to apply the events it addresses.

No bounded revocation delay is promised. A PDS withholding updates can keep stale authorization usable indefinitely; hiding an approver's revocation can also enable new malicious approvals if its key is compromised. Neither OOB verification nor grant audit records establish freshness. Expiring and fresh per-grant approval profiles are deferred under TODO-06.

See Core for [content-key rotation](core.md#revocation-and-rotation) and [recovery/succession](core.md#recovery-and-succession).

## References

- [PEEP Core](core.md) and [TODOs](TODOs.md).
- [Spaces](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data): membership and ciphertext access.
- [Repository](https://atproto.com/specs/repository) and [sync](https://atproto.com/specs/sync): publication evidence and its limits.

Device publications, declarations, and enrollment evidence are proposed extensions.
