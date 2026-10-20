# PEEP: Device Enrollment

## Bindings and publication

A device is an app installation. Independent apps enroll separately; browser identities belong to an origin within a browser profile. Generate independent signing/encryption keys under [Core's profile](core.md#mandatory-grant-profile); keep private keys locally. [Platform storage constraints](#platform-notes) require implementation validation.

```typescript
type Device = { deviceId: string; authPubkey: bytes; encryptPubkey: bytes };
type Binding = { account: string; device: Device };
```

Both keys are 32 bytes: `authPubkey` uses Ed25519; `encryptPubkey` uses X25519. Fresh installations/replacement keys use a new `RandomId` device ID; importing the same private keys preserves the binding. The binding ID is lowercase hexadecimal `SHA-256(CBOR(["peep/device-binding", 1, binding]))`.

Publish `{ $type: "com.example.peep.device", value: binding }` in the account's public repo with `rkey = deviceId`; the binding account must match the repo owner. Publication discovers keys but grants neither enrollment nor membership. Signed selections embed exact keys, so mutable discovery cannot redirect an approval.

## Local trust

Trust binds the account DID, device ID, and both keys, with no space identifier. Persist TOFU pins and verified status independently of spaces; creating, leaving, deleting, or rejoining a space neither resets trust nor requires repeat verification of an unchanged binding. Changing any component requires valid same-account approval or explicit independent re-verification. Never silently replace a pin, downgrade trust, or treat reinstall/state loss as fresh TOFU; use [recovery](#recovery).

TOFU permits initial PDS substitution; later continuity cannot repair it. Independent verification or approval rooted in it prevents substitution by the PDS when approving devices remain uncompromised. Self-signatures, possession challenges, PDS login/publication, and account-only invitations do not independently establish identity. Both modes require signatures, exact-key matching, and continuity; [Core's policy](core.md#device-verification-policy) determines which mode is allowed in each exchange.

Each client keeps its own trust decisions, distinguishing direct verification, approval-derived verification, and TOFU provenance. One user's decision does not verify a device for another user. OOB records, earlier approval evidence, acceptance history, and revocations remain in [private state](#private-state); reusing trust in another space must not publish the original space's declarations.

## Independent verification

The payload is `CBOR(["peep/verify-device", 1, binding])`. A QR encodes `peep:verify:` followed by unpadded base64url of that payload. Strictly decode/re-encode and compare every binding component. The safety code is its full lowercase hexadecimal SHA-256, displayed as sixteen groups of four characters; compare every group. No space, handle, display name, or timestamp participates.

Display the account DID and device. Require confirmation of a QR scanned directly from the intended person's device or a complete code match over an independently authenticated channel. Delivery through the same potentially malicious PDS is insufficient. A friendlier display must not silently shorten comparison.

Verifying an exact TOFU pin upgrades future local decisions, including valid approval paths rooted in it. Preserve prior grants' trust decisions; the upgrade proves neither past authorization nor absence of disclosure. A mismatch records a dispute and blocks dependent grants/key acceptance until approval or independent recovery resolves it. Verification cannot revive revoked bindings or bypass [withdrawn-approver rules](#withdrawing-an-approver).

## Declarations

Selection is explicit authorization of an app installation for a particular space. Adding an app/device does not select it account-wide. This preserves access boundaries between applications and spaces; reused account DIDs and device keys do not provide cross-space unlinkability.

A declaration is the complete device selection for one account in one space. A valid replacement removes omitted devices; an authenticated empty selection selects none. Missing/deleted records are not empty selections. Per-space removal changes neither membership nor reusable device trust, and cannot override account-wide revocation.

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

Sign with `Ed25519.Sign(signerKey, CBOR(["peep/declaration", 1, declarationWithoutProof]))`. Selected devices inherit `account`. The signature is the selection approval; no separate approval record is needed. Publish in the declaring account's space repo under [record conventions](core.md#records); [enrollment history](#enrollment-history) defines predecessors, bootstrap, and conflicts.

Before signing, authenticate added bindings through pairing or independent verification and confirm the account, space, and every selection change, including removal of the last device. Possession alone or a PDS-supplied list is insufficient user intent. Persist the signed snapshot and authorization locally before publication.

An accepted, unwithdrawn device may approve selections for its own account. Validate paths outward from a locally accepted binding, checking each signature, exact selection, and same-account scope. Preserve the root's TOFU/verified provenance and exact approval records for offline validation. Self-signatures or cycles among unknown keys cannot establish a root. Approval grants neither membership, cross-account authority, nor administration. Apply [revocations](#device-revocations) before accepting new authority.

Applications may offer one enrollment action for a user-chosen set of spaces, reusing device verification but signing a separate declaration against each space's current history. Confirm the exact keys, selected spaces, and changes together. Preserve other selections, durably track each publication, retry safely, and report incomplete updates. Reconcile concurrent changes under the normal ancestry/conflict rules; retries must not expand the authorized set of spaces or bypass withdrawals. This batches the interaction, while still requiring one declaration update per space.

## Enrollment history

### Declaration ancestry

Each [declaration](#declarations) references predecessors from the same account and space: none for the initial snapshot, one for an ordinary replacement, or all known competing tips for a resolution. A tip is a snapshot not superseded by another known snapshot. Signed ancestry establishes order; timestamps, delivery order, mutable head pointers, ancestor replay, and new roots cannot override retained history.

Authenticate the signer through local trust, a valid approval path, independent verification, or permitted initial TOFU. On genuine first observation in a space, with no retained declaration state or known conflict, a complete authenticated snapshot may become the local starting point without fetching its predecessors. Preserve its exact bytes/references and apply normal authorization checks; bootstrap proves neither freshness nor complete history.

Later updates must connect to saved state or resolve every known conflicting tip. Missing comparison paths block affected grants; an unrelated snapshot cannot replace known history. Check newly discovered earlier history too. Restore saved starting points; lost history requires explicit [recovery](#recovery), not silent first use or invented prior acceptance.

### Conflicts

Authenticated snapshots compete when validated ancestry shows neither supersedes the other. Pause new grants to or from that account in that space until an accepted, unwithdrawn same-account device signs a complete resolution covering all known tips. The signer need not be selected in the disputed snapshots. Never automatically merge selections or select a winner.

Competing resolutions and newly discovered forks pause grants again. Ordinary replacements and invalid evidence are not conflicts; missing ancestry establishes neither conflict nor supersession. Enforcement cannot precede discovery of a hidden fork.

### Device revocations

```typescript
type Revocation = {
  version: 1;
  scope: "account";
  signer: Binding;
  target: Binding;
  proof: bytes;
};
```

Sign `CBOR(["peep/device-revocation", 1, revocationWithoutProof])`. Signer and target must name the same account. A locally accepted, unwithdrawn device may revoke itself or a peer; withdrawn signers have only the cycle exception below. Verify the signature and exact scope/bindings using the receiver's trust, not a relay's judgment. A compromised accepted device can revoke its peers; no creator/admin approval is required.

A valid revocation permanently excludes that exact binding across current and future spaces: no new grants to it, issuance by it, or approvals/declarations relying on its authority. Deletion, stale selections, and new spaces cannot clear it. Replacement requires fresh keys under [approval or recovery](#replacement). Revocation cannot erase copied keys/plaintext; affected current keys require [rotation](core.md#triggers).

Publish under [record conventions](core.md#records). Enumerate public revocations alongside device records during discovery and periodic public-repo catch-up. Peers may forward unchanged signed values by CID or copy them into space repos. Preserve valid statements, exact targets, and local acceptance/withdrawal ordering even if records disappear.

### Withdrawing an approver

Preserve bindings accepted locally before learning their approver's withdrawal, including trust status/provenance. They remain subject to their own withdrawals and space authorization; surviving devices can approve further additions. This does not authorize new declarations by the withdrawn signer.

Reject new bindings relying solely on that signer, including paths through previously unaccepted intermediates. Require another accepted, unwithdrawn approver or independent verification; do not fall back to TOFU. The required ordering comes from retained [private history](#private-state), not claimed signing dates or another issuer's acceptance.

### Revocation cycles

Accept every edge in a closed cycle of two or more distinct same-account bindings if all signatures/scopes/bindings validate and every binding was locally accepted before learning any valid revocation of any member. Withdraw all members regardless of delivery order or whether some signers are already withdrawn. Apply this separately to each qualifying cycle, including overlaps; preserve already accepted revocations.

Missing or incomparable local history cannot establish eligibility. Later-accepted replacements, open chains, and outgoing edges outside qualifying cycles receive no exception. Retain cryptographically valid candidates with withdrawn signers as inactive until a qualifying cycle is complete; evaluate ordering before applying the batch. A late closing edge can disable all remaining devices and require recovery; signatures do not establish simultaneous issuance.

### Bounded validation

Use visited references, cached signatures, resumable progress, and finite byte/node/depth/work budgets. Authenticate ancestry edges before using them; reject cross-account/space ancestry and declaration-ancestry cycles, while allowing shared ancestors. The revocation cycles above are a separate authority rule.

Publish supported limits and check each block before allocation. Resource exhaustion or unavailable required paths means incomplete validation, not permission to skip edges, accept partial cycles, truncate selections/contexts, choose branches, discard revocations, or weaken verification. Large histories may require more work or a more capable client.

### Freshness

For client decisions, "current" means the latest authenticated state known locally under the relevant ancestry and monotonic-revision rules, including all learned withdrawals and unresolved conflicts. Arrival order is not authority; missing required evidence still blocks.

Approvals are reusable without expiry or fresh per-grant approval, including while approvers are offline. Enforce authenticated membership/device/approval-authority withdrawals as soon as learned; cached approvals cannot override them. Neither a host read, OOB verification, audit record, nor an empty revocation update establishes freshness. Withholding may leave stale authorization usable indefinitely, including compromised approvers issuing new approvals. No bounded propagation delay is promised; stricter profiles are [deferred](TODOs.md#todo-06).

## Recovery

### Private state

Durably retain keys and exact binding pins; TOFU/direct/approval-derived verification and disputes; private OOB/approval evidence; acceptance and learned-withdrawal ordering; revocation statements/candidates; declaration starting points/tips/conflicts; authenticated host observations; epoch/key acceptance decisions; pending operations; authored selections; and audit checkpoints/gaps.

Keep this state confidential and authenticated. Use an append-only local journal with unique installation/history identity and monotonic sequence. Preserve imported histories' identities/order and record the import as a local event. Timestamps and unrelated histories cannot establish acceptance before withdrawal. Local trust survives space lifecycles under [binding rules](#local-trust).

### Backup and transfer

Use the application's protected backup or pairing container for keys and state together. Transfers must be authenticated and encrypted between the user's own trusted installations. Bind format/version, owner account, source installation/history, and the full payload; authenticate before import. Protect encryption with independent high-entropy key material that PDS login/reset cannot reveal or replace. Document key wrapping/KDF, integrity, rollback-detection limits, and atomic restore. [Platform support](#platform-notes) must be validated; a new interoperable backup or separate trust-sync protocol is not required.

Before atomic import, validate ownership, key/public-binding consistency, references, provenance, and journal integrity. Union revocations; preserve disputes/conflicts; merge declaration tips by signed ancestry and host state by monotonic revisions. Resolve conflicting pins explicitly. Preserve verification provenance without promoting TOFU, clearing withdrawals, or rolling back newer known state. Transfer may carry a user's decisions to their own installations, never to another user as verified trust.

An old backup cannot detect wholly lost newer state without a surviving reference. Report missing coverage/freshness, reconcile available sources, and never invent prior acceptance or ordering for withdrawal exceptions. A key-only restore recovers no trust/declaration/audit history; report the loss and require explicit recovery.

### Replacement

A surviving, locally accepted, unwithdrawn device may approve fresh same-account keys while preserving TOFU/verified provenance. Otherwise an issuer with an existing account pin must independently re-verify the replacement. PDS recovery cannot reset trust, permit fresh TOFU, revive revoked bindings, or authorize signed withdrawals. Use [the same verification policy](core.md#device-verification-policy) for subsequent grants and acceptance.

One eligible helper holding keys can restore access to those epochs; other clients keep their own trust decisions. Recover declaration history and resolve known tips/conflicts before issuance; missing required comparison paths remain blocking. Publish the replacement declaration and, where an authorized signer survives, withdrawals. Each peer validates them locally. This also handles revocation cycles that disable every device.

Removal/re-invitation follows host administration but cannot reset pins, withdrawals, or declaration/audit history. Keep old grants and [rotate affected spaces](core.md#triggers). Administration, device authority, and key recovery are separate: losing all key copies, decryptable backups, and usable [history-wrapping paths](core.md#backward-history-wrapping) loses historical plaintext. Future writes can resume through [a fresh epoch](core.md#availability-recovery). Dedicated recovery-key authority and cross-application backup portability are outside the baseline.

## Platform notes

Hardware backing and cross-app sharing are not assumed.

| Platform | Storage constraints |
| --- | --- |
| iOS / iPadOS | [Keychain sharing](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps) requires the same developer team. |
| Android | [Keystore](https://developer.android.com/privacy-and-security/keystore) is app-private; [KeyChain](https://developer.android.com/reference/android/security/KeyChain) offers user-approved sharing, subject to algorithm support. |
| macOS | [Modern Keychain](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains) uses access groups; older file-based keychains support per-app access lists. |
| Windows | [CNG](https://learn.microsoft.com/en-us/windows/desktop/SecCNG/key-storage-and-retrieval) stores keys; [DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) does not by itself isolate same-user apps. |
| Linux | [Secret Service](https://specifications.freedesktop.org/secret-service/latest-single/) leaves application access controls to implementations. |
| Web | [WebCrypto](https://www.w3.org/TR/WebCryptoAPI/#concepts-key-storage) storage is normally origin-separated, without a common device keychain. |

Browser clients trust the application origin and its code-delivery infrastructure. Replacement code served on a subsequent load can use available installation keys to decrypt and exfiltrate content without enrolling another device. Non-extractable keys do not prevent this. Device verification and grant auditing neither prevent nor guarantee detection of this compromise.

Operation, storage, and pairing validation remain [TODO-12](TODOs.md#todo-12). Storage protections do not protect plaintext from malicious application code or updates.
