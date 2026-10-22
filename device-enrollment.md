# PEEP: Device Enrollment

## Bindings and publication

A device is an app installation. Independent apps enroll separately; browser identities belong to an origin within a browser profile. Installations MUST generate independent signing/encryption keys under [Core's profile](core.md#mandatory-grant-profile); they MUST keep private keys locally. [Platform storage constraints](#platform-notes) require implementation validation.

```typescript
type Device = { deviceId: string; authPubkey: bytes; encryptPubkey: bytes };
type Binding = { account: string; device: Device };
```

Both keys are 32 bytes: `authPubkey` uses Ed25519; `encryptPubkey` uses X25519. Fresh installations/replacement keys use a new `RandomId` device ID; importing the same private keys preserves the binding. The binding ID is lowercase hexadecimal `SHA-256(CBOR(["peep/device-binding", 1, binding]))`.

Publish `{ $type: "com.example.peep.device", value: binding }` in the account's public repo with `rkey = deviceId`; the binding account MUST match the repo owner. Publication discovers keys but grants neither enrollment nor membership. Signed approvals embed exact keys, so mutable discovery cannot redirect one.

## Local trust

PEEP uses trust on first use (TOFU). Trust binds the account DID, device ID, and both keys, with no space identifier. Clients MUST persist pins independently of spaces; creating, leaving, deleting, or rejoining a space neither resets trust nor requires accepting an unchanged binding again. A client accepts a binding through:

- **First use.** A binding of an account for which it holds no accepted binding, pinned on first sight.
- **Approval.** A binding approved by a same-account binding it accepts ([approvals](#approvals)).
- **TOFU key change.** A new or changed binding without an approval path, including one replacing a pinned binding. The client MUST durably record the change, including any superseded pin, and MUST visibly surface it identifying the account ("Bob's devices changed"). Notices add no approval gate. Revoked bindings stay revoked.

Clients MUST NOT silently replace a pin. A client that loses its own state MAY pin again on first use, and MUST report the loss. Pairing copies pins to a new installation; afterwards each installation pins independently, so a user's installations may hold different pins.

A malicious PDS can therefore substitute keys at first contact or later through a TOFU key change, and a substituted device that any member accepts receives the space key and all retained history. [Auditing](audit.md#direct-sync) and change notices are the defense: they can detect substitution after the disclosure, but cannot prevent or undo it. Self-signatures, possession challenges, PDS login/publication, and account-only invitations do not establish identity. Independent device verification, which would prevent PDS substitution, is a [deferred extension](TODOs.md#deferred-extensions).

Each client MUST keep its own trust decisions; one user's decisions never establish trust for another user. Approval evidence, acceptance history, and revocations remain in [private state](#private-state).

## Approvals

An account's devices are defined by signed approvals and [revocations](#device-revocations), not by per-space selection. Every accepted, unwithdrawn device of an account is eligible in every space the account is a member of. Per-space selection would not contain a compromised installation: an accepted installation can approve devices and join spaces, and remote validators cannot tell whether the user confirmed. Containment of an application depends on host membership and on the PDS's permissions for repo access, not on PEEP. Devices [request keys](core.md#distribution-scheduling) only for spaces they use, which keeps honest applications from holding keys they do not need but is not a boundary.

```typescript
type Approval = {
  version: 1;
  signer: Binding;         // Accepted device of the same account.
  target: Binding;         // Device being added.
  proof: bytes;
};
```

Sign with `Ed25519.Sign(signerKey, CBOR(["peep/device-approval", 1, approvalWithoutProof]))`. Signer and target MUST name the same account. Publish in the signer's public repo under [record conventions](core.md#records). Approvals only add devices; removing a device is [revocation](#device-revocations), which is permanent.

Before signing, the approving installation MUST authenticate the target binding through pairing and obtain the user's confirmation of adding a device to the account. The UI MUST state that the device gains access to all of the account's spaces and SHOULD warn the user to link only devices they own, because tricking users into scanning an attacker's linking code yields full access. It MAY show a name reported by the new device, which that device supplies and is not otherwise authenticated. Keys need not be displayed. Possession alone or a PDS-supplied list is insufficient user intent. The approving installation MUST persist the signed approval locally before publication.

An accepted, unwithdrawn device MAY approve devices for its own account. Clients MUST validate paths outward from a locally accepted binding, checking each signature, exact binding, and same-account scope. Clients MUST preserve exact approval records for offline validation. Self-signatures or cycles among unknown keys cannot establish a root. Approval grants neither membership, cross-account authority, nor administration. Clients MUST apply [revocations](#device-revocations) before accepting new authority.

### Approval validation

Enumerate approvals alongside device records and revocations during discovery and periodic public-repo catch-up. `ObserveApproval(value, state)` MUST perform D1–D3 before accepting the target:

1. **D1 — Validate.** Check schema, CID, same-account scope, both bindings, and signature. Invalid input returns `INVALID` and gains no authority.
2. **D2 — Signer.** Require the signer to be locally accepted and unwithdrawn under [local trust](#local-trust), applying [withdrawn-approver rules](#withdrawing-an-approver). An approval whose signer is not yet accepted is retained and returns `INCOMPLETE`; re-evaluate it when the signer becomes accepted. A withdrawn signer returns `BLOCKED`.
3. **D3 — Commit.** Unless the target is withdrawn, accept it, and persist the approval and acceptance position atomically. An approval of an already accepted binding adds evidence only.

Approvals do not conflict: each one adds a device, and validation order does not change the accepted set except through [revocation cutoffs](#revocation-processing). Withholding an approval delays a device's acceptance; it cannot remove an accepted device.

## Revocation and freshness

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

Sign `CBOR(["peep/device-revocation", 1, revocationWithoutProof])`. Signer and target MUST name the same account. Clients MUST use [R1–R4](#revocation-processing) to validate and apply each revocation using their own trust, not a relay's judgment. A compromised accepted device can revoke its peers; no creator/admin approval is required.

A valid revocation permanently excludes that exact binding across current and future spaces: no new grants to it, issuance by it, or approvals relying on its authority. Deletion and new spaces cannot clear it. Replacement requires fresh keys under [approval or recovery](#replacement). Revocation cannot erase copied keys/plaintext, and PEEP does not [rotate](core.md#no-rotation) space keys: the revoked device keeps keys it already holds. Revocation also does not end the device's Spaces access; the user must remove its access at their PDS ([ending access](core.md#ending-access)).

Publish under [record conventions](core.md#records). Enumerate public revocations alongside device records during discovery and periodic public-repo catch-up. Peers MAY forward unchanged signed values by CID or copy them into space repos. Clients MUST preserve valid statements, exact targets, and local acceptance/withdrawal ordering even if records disappear.

### Withdrawing an approver

Clients MUST preserve bindings accepted locally before learning their approver's withdrawal. They remain subject to their own withdrawals and space authorization; surviving devices can approve further additions. This does not authorize new approvals by the withdrawn signer.

Clients MUST reject new bindings relying solely on that signer, including paths through previously unaccepted intermediates. Clients MUST NOT treat such an approval as establishing trust. The binding MAY still be accepted as a [TOFU key change](#local-trust), with its notice and audit. The required ordering comes from retained [private history](#private-state), not claimed signing dates or another issuer's acceptance.

### Revocation processing

`ObserveRevocation(value, state)` MUST evaluate each candidate independently against retained local state, with R2–R4 serialized as one atomic local transition. Revocation authority does not depend on finding a cycle.

Let `A(v)` be the retained position at which exact binding `v` was first accepted locally, and `W(v)` the position when the client first accepted a valid revocation of it. A known unwithdrawn binding has no `W(v)`; missing withdrawal history is unknown, not proof that it is unwithdrawn. Earlier receipt of an inactive candidate MUST NOT backdate withdrawal; replay MUST NOT move either position. Comparisons MUST use [private history](#private-state), including imported histories' comparability, never claimed signing times or another issuer's observations.

1. **R1 — Candidate.** Validate encoding, account scope, both bindings, CID, and signature. Invalid candidates return `INVALID` and gain no authority. Retain valid bytes and their receipt position. If this exact statement was already accepted, return `OK` without changing acceptance/withdrawal positions or reauthorizing the signer.
2. **R2 — Signer.** Require retained evidence that the signer was previously accepted locally. A signer known never to have been accepted returns `BLOCKED`; unavailable required acceptance evidence or unknown local withdrawal status returns `INCOMPLETE`. The candidate cannot establish trust in its signer or target.
3. **R3 — Authority.** Run `eligible` below. An accepted, unwithdrawn signer may revoke any exact same-account target, including one not yet accepted. A withdrawn signer may revoke only targets accepted strictly before its own first withdrawal. A non-`OK` result leaves this candidate inactive and MUST NOT erase other accepted revocations.
4. **R4 — Commit.** Accept the statement and withdraw its target. Set `W(target)` to this acceptance position only when the target was known unwithdrawn; otherwise preserve its prior cutoff, including an unknown position, without inventing or advancing it. Preserve every earlier accepted statement and withdrawal, even if its signer is later withdrawn; return `OK`. Re-evaluate inactive candidates when relevant trust or ordering evidence becomes available; a revocation that becomes active this way takes effect at that position and is never backdated. Missing evidence or exhausted work budgets return `INCOMPLETE` for affected candidates and MUST NOT delay independently validated withdrawals.

After R1–R2 succeed:

```text
eligible(signer, target, state):
    if signer is not withdrawn: return OK
    if target is known never to have been accepted: return BLOCKED
    if A(target) or W(signer) is unavailable or they cannot be compared:
        return INCOMPLETE
    return OK if A(target) < W(signer) else BLOCKED
```

This rule includes self-revocation, mutual revocations, and open chains. A withdrawn signer retains revocation authority over targets before its cutoff indefinitely, including for statements created after withdrawal. It can therefore withdraw the entire older device set and force [recovery](#replacement). It gains no approval, declaration, grant, or other authority. Fresh bindings accepted after its withdrawal are protected from this signer on that client.

For a fixed set of devices all accepted before any withdrawal, revocation delivery order does not change which valid statements take effect. This is not global convergence: clients that accept a new binding on opposite sides of a signer's locally observed withdrawal can disagree permanently about its revocation. No trusted issuance time or freshness bound is implied.

### Bounded validation

Validators MUST use visited references, resumable progress, and finite byte/node/depth/work budgets; they MAY cache validated signatures. Validators MUST authenticate approval paths before using them and reject cross-account approvals; cycles among unaccepted keys establish nothing.

Implementations MUST publish supported limits and check each block before allocation. Resource exhaustion or unavailable required paths means incomplete validation, not permission to skip required checks, discard revocations, or weaken trust checks. Large histories may require more work or a more capable client.

### Freshness

For client decisions, "current" means the latest authenticated state known locally under the relevant monotonic-revision rules. Clients MUST include every learned withdrawal. Receipt alone does not establish authority; missing required evidence still blocks the affected operation.

Clients MUST enforce each authenticated change as soon as learned:

| Change | Required effect |
| --- | --- |
| Account becomes ineligible | Block new grants to and from that account in the space until a later eligible host decision permits them. |
| Device revocation | Permanently block grants to/from the exact binding and new approvals relying on its authority in every space. Preserve already accepted bindings under [withdrawn-approver rules](#withdrawing-an-approver). |

Cached approvals MUST NOT override these effects. Approvals MAY be reused without expiry or fresh per-grant approval, including while the approver is offline. Neither a host read, an audit record, nor an empty revocation update establishes freshness. Withholding may leave stale authorization usable indefinitely, including compromised approvers issuing new approvals. No bounded propagation delay is promised; stricter profiles are [deferred](TODOs.md#todo-06).

## Recovery

### Private state

Clients MUST durably retain keys and exact binding pins; first-observed host configuration values; TOFU key changes with superseded pins; approval evidence; acceptance and learned-withdrawal ordering; approval and revocation statements/candidates; authenticated host observations; key acceptance decisions; pending operations; and audit checkpoints/gaps.

Clients MUST keep this state confidential and authenticated and use an append-only local journal with unique installation/history identity and monotonic sequence. Clients MUST preserve imported histories' identities/order and record the import as a local event. Timestamps and unrelated histories cannot establish acceptance before withdrawal. Local trust survives space lifecycles under [binding rules](#local-trust).

### Backup and transfer

Use the application's protected backup or pairing container for keys and state together. Transfers MUST be authenticated and encrypted between the user's own trusted installations. Bind format/version, owner account, source installation/history, and the full payload; authenticate before import. Protect encryption with independent high-entropy key material that PDS login/reset cannot reveal or replace. Document key wrapping/KDF, integrity, rollback-detection limits, and atomic restore. [Platform support](#platform-notes) must be validated; a new interoperable backup protocol is not required.

Before atomic import, clients MUST validate ownership, key/public-binding consistency, references, provenance, and journal integrity. Importers MUST union approvals and revocations and merge host state by monotonic revisions. Importers MUST resolve conflicting pins explicitly and MUST NOT clear withdrawals or roll back newer known state. Transfer may carry a user's decisions to their own installations, never to another user.

An old backup cannot detect wholly lost newer state without a surviving reference. Report missing coverage/freshness, reconcile available sources, and never invent prior acceptance or withdrawal cutoffs. A key-only restore recovers no trust/approval/audit history; report the loss and require explicit recovery.

### Replacement

A surviving, locally accepted, unwithdrawn device may approve fresh same-account keys. Otherwise, clients MAY accept the replacement as a [TOFU key change](#local-trust). PDS recovery cannot revive revoked bindings or authorize signed withdrawals.

One eligible helper holding keys can restore access to those spaces; other clients keep their own trust decisions. Where an accepted signer survives, it publishes an approval of the replacement binding and revocations of lost ones. Each peer validates them locally. If every older device is withdrawn, another user can help establish fresh bindings under these recovery rules. The cutoff protects replacements from an old signer on clients that accepted its withdrawal before those replacement bindings.

Removal/re-invitation follows host administration but cannot reset pins, withdrawals, or approval/audit history. Keep old grants; removal does not [rotate](core.md#no-rotation) space keys. Administration, device authority, and key recovery are separate: losing all key copies and decryptable backups [loses the space](core.md#key-loss). Cross-application backup portability is outside the baseline.

### Total device loss

There is currently no process for recovering from the loss of every installation and decryptable backup. Such a user falls back to [replacement](#replacement) without a surviving approver: peers accept a key change, members re-grant keys they hold, and the user cannot publish signed withdrawals of the lost bindings. Keys held only by the lost installations are gone. A dedicated mechanism is an open design question ([TODO-08](TODOs.md#todo-08)).

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

Background issuance needs installation keys while the app is not in the foreground, including from notification-handling extensions on iOS. Making keys available after first unlock rather than only while unlocked trades some at-rest protection for availability; applications MUST document the choice.

Browser clients trust the application origin and its code-delivery infrastructure. Replacement code served on a subsequent load can use available installation keys to decrypt and exfiltrate content without enrolling another device. Non-extractable keys do not prevent this. Grant auditing neither prevents nor guarantees detection of this compromise.

Operation, storage, and pairing validation remain [TODO-12](TODOs.md#todo-12). Storage protections do not protect plaintext from malicious application code or updates.
