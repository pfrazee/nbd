# PEEP: Device Enrollment

## Bindings and publication

A device is an app installation. Independent apps enroll separately; browser identities belong to an origin within a browser profile. Installations MUST generate independent signing/encryption keys under [Core's profile](core.md#mandatory-grant-profile); they MUST keep private keys locally. [Platform storage constraints](#platform-notes) require implementation validation.

```typescript
type Device = { deviceId: string; authPubkey: bytes; encryptPubkey: bytes };
type Binding = { account: string; device: Device };
```

Both keys are 32 bytes: `authPubkey` uses Ed25519; `encryptPubkey` uses X25519. Fresh installations/replacement keys use a new `RandomId` device ID; importing the same private keys preserves the binding. The binding ID is lowercase hexadecimal `SHA-256(CBOR(["peep/device-binding", 1, binding]))`.

Publish `{ $type: "com.example.peep.device", value: binding }` in the account's public repo with `rkey = deviceId`; the binding account MUST match the repo owner. Publication discovers keys but grants neither enrollment nor membership. Signed selections embed exact keys, so mutable discovery cannot redirect an approval.

## Local trust

Trust binds the account DID, device ID, and both keys, with no space identifier. Clients MUST persist TOFU pins and verified status independently of spaces; creating, leaving, deleting, or rejoining a space neither resets trust nor requires repeat verification of an unchanged binding. Verified pins are binding; TOFU pins are advisory:

- **Verified accounts.** If a client holds an unwithdrawn verified binding (direct, approval-derived, or synced) for an account, any new or changed binding for that account requires same-account approval rooted in a verified binding or independent verification. A changed component of a verified binding without approval records a dispute.
- **TOFU key change.** Otherwise, in a space whose [verification policy](core.md#device-verification-policy) is `tofu-permitted`, a client MAY accept a new or changed binding without an approval path as a TOFU key change. It MUST durably record the change, including any superseded pin, and MUST visibly surface it identifying the account ("Bob's devices changed"). Notices add no approval gate. Revoked bindings stay revoked.
- **Approved changes.** Same-account approval rooted in a pinned binding carries its TOFU or verified provenance.

Clients MUST NOT silently replace a pin or downgrade trust. A client that loses its own state MAY pin again under TOFU only where TOFU is permitted, and MUST report the loss.

In TOFU-permitted exchanges, a malicious PDS can substitute keys at first contact or later through a TOFU key change. [Auditing](audit.md#direct-sync) and change notices are the defense: they can detect substitution but do not prevent it. Independent verification or approval rooted in it prevents substitution by the PDS when approving devices remain uncompromised. Self-signatures, possession challenges, PDS login/publication, and account-only invitations do not independently establish identity. Both modes require signatures, exact-key matching, and continuity; [Core's policy](core.md#device-verification-policy) determines which mode is allowed in each exchange.

Each client MUST keep its own trust decisions, distinguishing direct verification, approval-derived verification, synced, and TOFU provenance. One user's decision does not verify a device for another user; [own-device trust sync](#own-device-trust-sync) carries it only to that user's own installations. OOB records, earlier approval evidence, acceptance history, and revocations remain in [private state](#private-state); reusing trust in another space MUST NOT publish the original space's declarations.

## Independent verification

Independent verification is a mutual verification session between two installations. The initiator creates a single-use secret and delivers it to the responder over an out-of-band channel; both then run a password-authenticated key exchange through an untrusted relay. A successful session authenticates both exact bindings to each other in one ceremony. No space, handle, display name, or timestamp participates.

### Channels

| Channel | Secret | Delivery | `expectedResponder` |
| --- | --- | --- | --- |
| `qr` | 32 random bytes | QR scanned directly from the initiator's screen. | Account DID or `null`. |
| `link` | 32 random bytes | Link sent through an application independent of both parties' PDSes. | REQUIRED. |
| `pin` | Six uniformly random decimal digits, as ASCII bytes | Read aloud or sent through an application independent of both parties' PDSes. | REQUIRED. |

QR and link payloads are `peep:verify:` followed by unpadded base64url of `CBOR(["peep/verify-invite", 1, sessionId, initiatorAccount, secret])`. Links MUST carry the payload where web servers do not receive it, such as a URL fragment. For `pin`, the responder discovers the session from an `open` message naming its account and the user enters the digits.

Delivery through either party's PDS, the relay, or Spaces content is insufficient: anyone who learns the secret before the intended responder can complete the session in its place. Verification UI MUST state this for `link` and `pin`.

### Session messages

```typescript
type VerifyOpen = {
  version: 1;
  kind: "open";
  sessionId: string;                 // RandomId.
  channel: "qr" | "link" | "pin";
  initiator: Binding;
  expectedResponder: string | null;  // Account DID; see channel table.
  share: bytes;                      // SPAKE2 pA.
};

type VerifyRespond = {
  version: 1;
  kind: "respond";
  sessionId: string;
  responder: Binding;
  share: bytes;                      // SPAKE2 pB.
  confirm: bytes;                    // SPAKE2 cB.
};

type VerifyConfirm = {
  version: 1;
  kind: "confirm";
  sessionId: string;
  confirm: bytes;                    // SPAKE2 cA.
};
```

Messages use the [shared encoding rules](core.md#encoding-and-identifiers) but are ephemeral: they are not published as records and confer no authority outside the session. The relay is untrusted; its transport mapping remains [TODO-14](TODOs.md#todo-14).

### Key exchange

Profile `peep-verify-v1` uses [SPAKE2](https://www.rfc-editor.org/rfc/rfc9382.html) with the edwards25519, SHA-256, HKDF-SHA256, HMAC-SHA256 ciphersuite. The initiator is party A and the responder party B, with:

```text
pw  = CBOR(["peep/verify-secret", 1, sessionId, channel, secret])
A   = CBOR(initiator)
B   = CBOR(responder)
AAD = CBOR(["peep/verify-session", 1, sessionId, channel, expectedResponder])
```

`w` is derived from `pw` as RFC 9382 specifies; MHF parameters and test vectors remain [TODO-14](TODOs.md#todo-14). Confirmation MACs cover the RFC 9382 transcript, binding both exact bindings, both shares, and `AAD`. Implementations MUST apply RFC 9382's point validation and MUST NOT accept a session without verifying the peer's confirmation. Security against an active relay rests on single use: each session permits at most one online guess, and a wrong guess fails visibly.

### Procedure

1. **V1 — Open.** The initiator generates `sessionId` and the secret from a cryptographically secure source, durably records the session as open with a local expiry, sends `open`, and displays or exports the channel payload. `pin` sessions MUST expire within 15 minutes; other sessions SHOULD expire within 24 hours.
2. **V2 — Respond.** The responder obtains the secret out of band, fetches `open`, and checks that `expectedResponder` is `null` or its own account. It durably records its single attempt for `sessionId` before computing the exchange and sending `respond`. A responder MUST NOT make a second attempt for the same session.
3. **V3 — Consume.** The initiator discards a `respond` whose responder account does not equal a non-null `expectedResponder`. Otherwise it durably marks the session consumed before verifying `confirm`; the first such `respond` consumes the session whatever the outcome. Expired or consumed sessions accept nothing.
4. **V4 — Confirm.** If `cB` verifies, the initiator sends `confirm`. The responder verifies `cA`. Either failure ends the session for both parties.
5. **V5 — Record.** On success, each party records direct verification of the other's exact binding with the channel used. Verification UI MUST display the peer's account DID and device and require the user to confirm it is the intended person, especially for `qr` sessions without `expectedResponder`.

A failed, expired, or consumed session MUST NOT change pins, trust, or disputes; typing errors and interference are indistinguishable. Clients MUST NOT retry a session automatically, SHOULD present a new session as the remedy, and SHOULD recommend `qr` after repeated failures with the same account.

### Effects

Verifying an exact TOFU pin upgrades future local decisions, including valid approval paths rooted in it. Clients MUST preserve prior grants' trust decisions; the upgrade proves neither past authorization nor absence of disclosure. A successful session verifying keys that differ from an existing verified pin for the same account and device ID records a dispute and blocks dependent grants/key acceptance until approval or independent recovery resolves it. If they differ from a TOFU pin, the verified binding replaces it; the client records the superseded binding and surfaces that earlier exchanges with it may have used substituted keys. Verification cannot revive revoked bindings or bypass [withdrawn-approver rules](#withdrawing-an-approver).

## Own-device trust sync

A user's installations MAY share trust decisions with each other so that verification performed on one device applies on the others, including always-on devices that cannot run verification sessions themselves. Sync carries one user's decisions to that user's own installations, never to another account.

### Sync messages

```typescript
type TrustEntry = {
  binding: Binding;                  // Another account's exact binding.
  mode: "verified" | "tofu" | "disputed";
  provenance: "direct" | "approval" | "sync";
  channel: "qr" | "link" | "pin" | null; // For direct verification.
};

type TrustSyncPayload = {
  version: 1;
  account: string;                   // Sender and recipient account.
  sequence: number;                  // Per-source monotonic.
  trust: TrustEntry[];               // Set; at most one entry per binding ID.
  enrollment: EnrollmentPreference[]; // Set; at most one entry per deviceId.
};

type EnrollmentPreference = {
  deviceId: string;                  // The source itself.
  preference: "automatic" | "ask" | "never";
};

type TrustSync = {
  version: 1;
  source: Binding;
  recipient: DeviceIdentity;
  recipientKeyId: string;            // Fingerprint of the recipient X25519 key.
  sequence: number;
  encapsulation: bytes;
  ciphertext: bytes;                 // HPKE-sealed CBOR(TrustSyncPayload).
  proof: bytes;                      // Ed25519 signature by source.
};
```

The sender seals `CBOR(TrustSyncPayload)` to the recipient's X25519 key under the [mandatory grant profile](core.md#mandatory-grant-profile) with `info = CBOR(["peep/trust-sync-info", 1, H])` and `aad = CBOR(["peep/trust-sync-aad", 1, H])`, where `H` is the message without `encapsulation`, `ciphertext`, and `proof`, then signs `CBOR(["peep/trust-sync", 1, messageWithoutProof])`. A payload is a complete snapshot of the source's shareable decisions, not a delta. Messages are ephemeral and confidential; they MUST NOT appear in evidence manifests or space repos. Transport remains [TODO-15](TODOs.md#todo-15).

### Sending

An accepted, unwithdrawn installation SHOULD send an updated snapshot to each of its account's locally accepted, unwithdrawn installations after recording a verification, pin, dispute, or [enrollment preference](#enrollment-preferences) change, and after accepting a new own installation. Entries MUST reflect the sender's recorded decision and provenance without promotion.

### Receiving

1. **S1 — Validate.** Strictly decode the message, require the local binding as recipient, verify the signature, and open the payload. Require `source` and every payload `account` to equal the local account. Invalid input returns `INVALID`.
2. **S2 — Authorize source.** Require `source` to be a locally accepted, unwithdrawn binding of the local account, established through pairing, approval, or independent verification. Reject messages first observed after the source's withdrawal under [withdrawn-approver ordering](#withdrawing-an-approver); retain decisions applied before it.
3. **S3 — Order.** Ignore a `sequence` not greater than the highest applied from that source.
4. **S4 — Apply.** For each entry, record a synced decision with provenance `sync`, naming the source:
   - `verified` upgrades an exact TOFU pin or creates a verified pin. It satisfies [verified-only policy](core.md#device-verification-policy) for this installation.
   - `tofu` creates a TOFU pin only where TOFU first use would be permitted. It never upgrades.
   - `disputed` records a dispute for that binding.
   - An entry whose binding differs from a local verified pin for the same account and device ID records a dispute; it MUST NOT replace the pin. A `verified` entry replaces a differing TOFU pin as a direct session would. A differing `tofu` entry is handled as a [TOFU key change](#local-trust) where permitted, and otherwise records a dispute.
   - Revoked bindings stay revoked.
   Record each `enrollment` entry for the source itself, replacing its earlier synced preference; ignore entries for other devices.
5. **S5 — Commit.** Persist applied decisions, the source, and its sequence atomically.

Synced decisions are retained if the source later withdraws or stops sending; a later snapshot omitting an entry does not remove it. Downgrading or clearing trust requires explicit local action, as for any pin. Sync cannot verify the local account's own new installations; those use [pairing or approval](#declarations).

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

Before signing, the approving installation MUST authenticate added bindings through pairing or independent verification and obtain the user's confirmation:

- **Adding a new installation** (linking): the user MUST confirm adding a device to the account. The UI MUST state that the device gains access to the account's spaces and SHOULD warn the user to link only devices they own, because tricking users into scanning an attacker's linking code yields full access. It MAY show a name reported by the new device, which that device supplies and is not otherwise authenticated. Spaces MAY follow the device's [enrollment preference](#enrollment-preferences) without being listed, and keys need not be displayed.
- **Other selection changes:** the user MUST confirm the account, space, and change, including removal of the last device, except where [enrollment preferences](#enrollment-preferences) satisfy this duty at join.

Possession alone or a PDS-supplied list is insufficient user intent. The approving installation MUST persist the signed snapshot and authorization locally before publication.

An accepted, unwithdrawn device MAY approve selections for its own account. Clients MUST validate paths outward from a locally accepted binding, checking each signature, exact selection, and same-account scope. Clients MUST preserve the root's TOFU/verified provenance and exact approval records for offline validation. Self-signatures or cycles among unknown keys cannot establish a root. Approval grants neither membership, cross-account authority, nor administration. Clients MUST apply [revocations](#device-revocations) before accepting new authority.

Applications MAY offer one enrollment action for a user-chosen set of spaces, reusing device verification but signing a separate declaration against each space's current history. A batch enrollment UI MUST confirm the added device as above; when it lists spaces, it MUST show them and the changes together. Batching clients MUST preserve other selections, durably track each publication, retry safely, and report incomplete updates. Reconcile concurrent changes under the normal ancestry/conflict rules; retries MUST NOT expand the authorized set of spaces or bypass withdrawals. This batches the interaction, while still requiring one declaration update per space.

### Enrollment preferences

Each own installation MAY carry a standing preference for spaces the user joins later: `automatic`, `ask`, or `never`. The user sets an installation's preference on that installation or while linking it; changes never alter existing selections. Preferences reach other installations through [trust sync](#own-device-trust-sync).

When the user explicitly joins a space on an installation, that installation MAY satisfy the confirmation duty above for its own account's locally accepted, unwithdrawn bindings by applying their previously confirmed preferences: select `automatic` bindings, offer `ask` bindings unselected, and omit `never` bindings unless the user adds them. The join action and those previously confirmed preferences satisfy the duty; the join UI MAY show the resulting device set and allow changes before signing. Only the joining installation signs, producing one declaration; other installations MUST NOT sign declarations from preferences without a join action on themselves. Host admission alone is not a join action. Adding a binding not yet accepted still requires pairing or independent verification.

## Enrollment history

### Declaration ancestry

Each declaration's `previous` set names same-account, same-space predecessors: none for an initial snapshot, one for replacement, or all known competing tips for resolution. A tip is an authenticated snapshot not superseded by another known snapshot. `descends(x, y)` means a validated path from `x` through `previous` reaches `y`; a missing path is unknown, not false.

`ObserveDeclaration(candidate, account, space, state)` MUST perform D1–D4 before changing the current selection:

1. **D1 — Validate.** Check schema, CID, exact account/space, and signature. Authenticate the signer through [retained trust, permitted first-use TOFU, or a permitted TOFU key change](#local-trust), [approval](#declarations), or [independent verification](#independent-verification), applying [withdrawn-approver rules](#withdrawing-an-approver). Invalid data returns `INVALID`; missing required evidence returns `INCOMPLETE`; prohibited new authority returns `BLOCKED`. Previously accepted snapshots and historical ancestors MAY be checked as retained evidence without restoring authority or accepting new approvals; a withdrawn signer cannot authorize a newly accepted selection.
2. **D2 — Bootstrap.** On genuine first observation with no saved declaration state or known conflict, a client MAY persist the complete authenticated candidate as starting point/current selection and return `OK` without fetching predecessors. Otherwise continue to D3. Existing account pins and withdrawals still apply. Known state loss MUST use [recovery](#recovery), not this shortcut, except that a client MAY bootstrap again in TOFU-permitted spaces, recording the loss.
3. **D3 — Compare.** Otherwise fetch and authenticate enough ancestry to compare the candidate, retained tips, and newly discovered branches, including history preceding bootstrap when needed. Check every traversed edge's scope and reject cycles. Persist unresolved authenticated candidates and return `INCOMPLETE` if a required comparison is unknown or exceeds the work budget; affected grants remain blocked. Missing paths MUST NOT create a conflict or erase saved tips.
4. **D4 — Commit.** Apply the following cases to the validated graph and persist snapshots, tips, and the result atomically. A complete signed resolution must cover all known competing tips, directly or through validated resolution ancestry.

```text
tips = authenticated snapshots not superseded in the compared graph
if tips contains multiple incomparable snapshots:
    retain every tip; record conflict; return BLOCKED(conflict)
head = the sole tip
if head equals the saved head:
    retain new historical evidence; return OK(unchanged)
if head does not descend from all saved tips:
    return INCOMPLETE(comparison)  # no replacement or automatic branch choice
persist head's complete selection and resolved-tip history
clear the conflict covered by that complete signed resolution
return OK(head)
```

Clients MUST NOT use timestamps, delivery order, mutable head pointers, ancestor replay, or new roots to override this procedure. Bootstrap establishes neither freshness nor complete history. An unrelated root with fully proven incompatible ancestry is a conflict; one with unresolved ancestry remains incomplete.

### Conflicts

A recorded conflict MUST block new grants to and from that account in that space until D4 accepts a signed complete resolution. An accepted, unwithdrawn same-account device MAY sign it without being selected in the disputed snapshots. Clients MUST NOT merge selections or choose a winner automatically. Competing resolutions and later forks run D1–D4 again. Invalid evidence and ordinary replacements are not conflicts; hidden forks cannot be enforced before discovery.

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

A valid revocation permanently excludes that exact binding across current and future spaces: no new grants to it, issuance by it, or approvals/declarations relying on its authority. Deletion, stale selections, and new spaces cannot clear it. Replacement requires fresh keys under [approval or recovery](#replacement). Revocation cannot erase copied keys/plaintext; affected current keys require [rotation](core.md#triggers).

Publish under [record conventions](core.md#records). Enumerate public revocations alongside device records during discovery and periodic public-repo catch-up. Peers MAY forward unchanged signed values by CID or copy them into space repos. Clients MUST preserve valid statements, exact targets, and local acceptance/withdrawal ordering even if records disappear.

### Withdrawing an approver

Clients MUST preserve bindings accepted locally before learning their approver's withdrawal, including trust status/provenance. They remain subject to their own withdrawals and space authorization; surviving devices can approve further additions. This does not authorize new declarations by the withdrawn signer.

Clients MUST reject new bindings relying solely on that signer, including paths through previously unaccepted intermediates. Clients MUST NOT treat such an approval as establishing trust. In a TOFU-permitted space where no verified binding for the account exists, the binding MAY still be accepted as a [TOFU key change](#local-trust), with its notice and audit; otherwise clients MUST require another accepted, unwithdrawn approver or independent verification. The required ordering comes from retained [private history](#private-state), not claimed signing dates or another issuer's acceptance.

### Revocation processing

`ObserveRevocation(value, state)` MUST evaluate each candidate independently against retained local state, with R2–R4 serialized as one atomic local transition. Revocation authority does not depend on finding a cycle.

Let `A(v)` be the retained position at which exact binding `v` was first accepted locally, and `W(v)` the position when the client first accepted a valid account-wide revocation of it. A known unwithdrawn binding has no `W(v)`; missing withdrawal history is unknown, not proof that it is unwithdrawn. Earlier receipt of an inactive candidate MUST NOT backdate withdrawal; replay MUST NOT move either position. Comparisons MUST use [private history](#private-state), including imported histories' comparability, never claimed signing times or another issuer's observations.

1. **R1 — Candidate.** Validate encoding, account scope, both bindings, CID, and signature. Invalid candidates return `INVALID` and gain no authority. Retain valid bytes and their receipt position. If this exact statement was already accepted, return `OK` without changing acceptance/withdrawal positions or reauthorizing the signer.
2. **R2 — Signer.** Require retained evidence that the signer was previously accepted locally. A signer known never to have been accepted returns `BLOCKED`; unavailable required acceptance evidence or unknown local withdrawal status returns `INCOMPLETE`. The candidate cannot establish trust in its signer or target.
3. **R3 — Authority.** Run `eligible` below. An accepted, unwithdrawn signer may revoke any exact same-account target, including one not yet accepted. A withdrawn signer may revoke only targets accepted strictly before its own first withdrawal. A non-`OK` result leaves this candidate inactive and MUST NOT erase other accepted revocations.
4. **R4 — Commit.** Accept the statement and withdraw its target. Set `W(target)` to this acceptance position only when the target was known unwithdrawn; otherwise preserve its prior cutoff, including an unknown position, without inventing or advancing it. Preserve every earlier accepted statement and withdrawal, even if its signer is later withdrawn; return `OK`. Re-evaluate inactive candidates when relevant trust or ordering evidence becomes available. Missing evidence or exhausted work budgets return `INCOMPLETE` for affected candidates and MUST NOT delay independently validated withdrawals.

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

Validators MUST use visited references, resumable progress, and finite byte/node/depth/work budgets; they MAY cache validated signatures. Validators MUST authenticate ancestry edges before using them and reject cross-account/space ancestry and declaration-ancestry cycles, while allowing shared ancestors.

Implementations MUST publish supported limits and check each block before allocation. Resource exhaustion or unavailable required paths means incomplete validation, not permission to skip required checks, truncate selections/contexts, choose branches, discard revocations, or weaken verification. Large histories may require more work or a more capable client.

### Freshness

For client decisions, "current" means the latest authenticated state known locally under the relevant ancestry and monotonic-revision rules. Clients MUST include every learned withdrawal and unresolved conflict. Receipt alone does not establish authority; missing required evidence still blocks the affected operation.

Clients MUST enforce each authenticated change as soon as learned:

| Change | Required effect |
| --- | --- |
| Account becomes ineligible | Block new grants to and from that account in the space until a later eligible host decision permits them. |
| Declaration omits a device, including an empty selection | Block new grants to and from that binding in that space until a valid selection permits them again; account-wide trust is unchanged. |
| Account-wide device revocation | Permanently block grants to/from the exact binding and new approvals/declarations relying on its authority in every space. Preserve already accepted bindings under [withdrawn-approver rules](#withdrawing-an-approver). |

Cached approvals MUST NOT override these effects. Approvals MAY be reused without expiry or fresh per-grant approval, including while the approver is offline. Neither a host read, OOB verification, an audit record, nor an empty revocation update establishes freshness. Withholding may leave stale authorization usable indefinitely, including compromised approvers issuing new approvals. No bounded propagation delay is promised; stricter profiles are [deferred](TODOs.md#todo-06).

## Recovery

### Private state

Clients MUST durably retain keys and exact binding pins; first-observed host policies and the policy recorded with each decision; TOFU/direct/approval-derived/synced verification, verification channels, disputes, and TOFU key changes with superseded pins; per-source trust-sync sequences; enrollment preferences; open, attempted, and consumed [verification sessions](#procedure); private OOB/approval evidence; acceptance and learned-withdrawal ordering; revocation statements/candidates; declaration starting points/tips/conflicts; authenticated host observations; epoch/key acceptance decisions; pending operations; authored selections; and audit checkpoints/gaps.

Clients MUST keep this state confidential and authenticated and use an append-only local journal with unique installation/history identity and monotonic sequence. Clients MUST preserve imported histories' identities/order and record the import as a local event. Timestamps and unrelated histories cannot establish acceptance before withdrawal. Local trust survives space lifecycles under [binding rules](#local-trust).

### Backup and transfer

Use the application's protected backup or pairing container for keys and state together. Transfers MUST be authenticated and encrypted between the user's own trusted installations. Bind format/version, owner account, source installation/history, and the full payload; authenticate before import. Protect encryption with independent high-entropy key material that PDS login/reset cannot reveal or replace. Document key wrapping/KDF, integrity, rollback-detection limits, and atomic restore. [Platform support](#platform-notes) must be validated; a new interoperable backup protocol is not required; ongoing decisions use [own-device trust sync](#own-device-trust-sync).

Before atomic import, clients MUST validate ownership, key/public-binding consistency, references, provenance, and journal integrity. Importers MUST union revocations, preserve disputes/conflicts, and merge declaration tips by signed ancestry and host state by monotonic revisions. Importers MUST resolve conflicting pins explicitly. Importers MUST preserve verification provenance and MUST NOT promote TOFU, clear withdrawals, or roll back newer known state. Transfer may carry a user's decisions to their own installations, never to another user as verified trust.

An old backup cannot detect wholly lost newer state without a surviving reference. Report missing coverage/freshness, reconcile available sources, and never invent prior acceptance or withdrawal cutoffs. A key-only restore recovers no trust/declaration/audit history; report the loss and require explicit recovery.

### Replacement

A surviving, locally accepted, unwithdrawn device may approve fresh same-account keys while preserving TOFU/verified provenance. Otherwise, clients holding a verified binding for the account MUST independently re-verify the replacement; in TOFU-permitted exchanges, other clients MAY accept it as a [TOFU key change](#local-trust). PDS recovery cannot reset verified trust, revive revoked bindings, or authorize signed withdrawals. Use [the same verification policy](core.md#device-verification-policy) for subsequent grants and acceptance.

One eligible helper holding keys can restore access to those epochs; other clients keep their own trust decisions. Recovery clients MUST recover declaration history and resolve known tips/conflicts before issuance; missing required comparison paths remain blocking. Publish the replacement declaration and, where an authorized signer survives, withdrawals. Each peer validates them locally. If every older device is withdrawn, another user can help establish fresh bindings under these recovery rules. The cutoff protects replacements from an old signer on clients that accepted its withdrawal before those replacement bindings.

Removal/re-invitation follows host administration but cannot reset pins, withdrawals, or declaration/audit history. Keep old grants and [rotate affected spaces](core.md#triggers). Administration, device authority, and key recovery are separate: losing all key copies, decryptable backups, and usable [history-wrapping paths](core.md#backward-history-wrapping) loses historical plaintext. Future writes can resume through [a fresh epoch](core.md#availability-recovery). Cross-application backup portability is outside the baseline.

### Total device loss

There is currently no process for recovering from the loss of every installation and decryptable backup. Such a user falls back to [replacement](#replacement) without a surviving approver: peers holding verified bindings re-verify, TOFU peers may accept a key change, members re-grant keys they hold, and the user cannot publish signed withdrawals of the lost bindings. Keys held only by the lost installations are gone. A dedicated mechanism is an open design question ([TODO-08](TODOs.md#todo-08)).

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

Background issuance and trust sync need installation keys while the app is not in the foreground, including from notification-handling extensions on iOS. Making keys available after first unlock rather than only while unlocked trades some at-rest protection for availability; applications MUST document the choice.

Browser clients trust the application origin and its code-delivery infrastructure. Replacement code served on a subsequent load can use available installation keys to decrypt and exfiltrate content without enrolling another device. Non-extractable keys do not prevent this. Device verification and grant auditing neither prevent nor guarantee detection of this compromise.

Operation, storage, and pairing validation remain [TODO-12](TODOs.md#todo-12). Storage protections do not protect plaintext from malicious application code or updates.
