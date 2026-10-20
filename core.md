# PEEP: Core

## Scope

Each space uses a symmetric content key per epoch. Usable keys, plaintext, caches, search, previews, and exports stay on clients; servers store ciphertext, declarations, evidence, and encrypted grants. PEEP provides no forward secrecy, post-compromise security, or general metadata-hiding guarantee. Endpoints, software/updates, authorized key holders, and the space host are trusted; other PDSes, repo hosts, and storage providers may be malicious.

The [space host](#trusted-host-state) determines account eligibility, configuration, administration, and epoch order. Credentials and writer discovery do not establish membership or device trust. [Signed declarations](device-enrollment.md#declarations) select devices; no enrollment registry, global enrollment chain, creator-device approval, or issuer appointment is required.

Any eligible participant's enrolled device may grant keys it holds. Current members' selected devices are eligible for all retained epochs, including pre-join content. Key possession grants no administrative or device-approval authority. A grant also unlocks connected [historical keys](#backward-history-wrapping). Reading an existing epoch requires a recoverable key; [device recovery](device-enrollment.md#recovery) cannot recreate lost secrets.

PEEP does not protect confidentiality against malicious host decisions: the host can admit accounts to receive current keys and retained history, or relax the verification policy. Admission alone cannot bypass the policy in force; device verification authenticates bindings without establishing users' consent to membership. Independently verified bindings prevent substituted-key grants under the [local trust assumptions](device-enrollment.md#local-trust); TOFU provides only [conditional subsequent detection](audit.md#direct-sync).

## Protocol conventions

Names under `com.example.peep` and host operations are proposed extensions. Production namespaces and concrete Spaces transport mapping remain [TODO-03](TODOs.md#todo-03).

### Conformance and validation results

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL are interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html)) only when uppercase. Core, Device Enrollment, and Auditing are normative, including their schemas, procedures, and transition tables. Examples and [rationale](rationale.md) are informative. Implementations MUST preserve the procedures' checks, security ordering, and state effects; equivalent implementations need not use identical code.

Procedures use these results, with a reason and affected references:

| Result | Meaning |
| --- | --- |
| `OK` | All checks required for this operation passed. |
| `INVALID` | Supplied data violates encoding, scope, signature, hash, or other integrity requirements. |
| `INCOMPLETE` | Required bytes, authentication basis, local ordering evidence, keys, or validation work are unavailable. |
| `BLOCKED` | Known authorization state or local policy forbids the operation, including withdrawal, conflict, or insufficient verification. |

Only `OK` permits the requested operation. Clients MUST NOT treat missing evidence as an empty state or a successful check. They MUST preserve independently authenticated withdrawals, conflicts, and observations even if another check fails; unvalidated input MUST NOT acquire authority through partial processing. Before releasing a grant or committing a new key acceptance, clients MUST repeat checks affected by newly learned state. These results do not assert global freshness or replace the [archive audit assessments](audit.md#archived-grants).

### Encoding and identifiers

`CBOR(x)` means normalized ATProto CBOR, including byte strings and CID links. Decoders MUST apply finite limits and reject duplicate/unknown fields, non-normalized encodings, trailing bytes, wrong types, unknown versions, invalid key/signature encodings, and integers outside 0 through 2^53−1. All fields shown are REQUIRED; `null` is permitted only where shown. Implementations MUST NOT hash JSON or a displayed CID string. Sets are arrays sorted by unsigned lexicographic order of their elements' normalized CBOR bytes, with duplicates rejected; other arrays retain their specified order.

`Ref(x)` is a CIDv1 with codec `dag-cbor` (`0x71`) and SHA-256 multihash of `CBOR(x)`. Resolvers MUST obtain exactly those bytes and check the hash before interpreting a reference. This commits to content, not authority, freshness, or availability. `Digest` is a 32-byte SHA-256 result. `RandomId` is 16 independently random bytes encoded as 32 lowercase hexadecimal characters. Implementations MUST use exact DIDs for identities, never mutable handles. Space identifiers use the exact canonical URI obtained from the authenticated host; implementations MUST NOT normalize identifiers differently for signing and verification.

### Records

Except for [public device records](device-enrollment.md#bindings-and-publication), protocol values are immutable, wrapped as `{ $type: collection, value }`. The record key is lowercase hexadecimal SHA-256 of `CBOR(value)`; references identify the inner value. Different bytes at an existing identity are an error.

| Collection suffix under `com.example.peep` | Location |
| --- | --- |
| `declaration` | Declaring account's space repo. |
| `revocation` | Signer's public repo; unchanged copies may be relayed in space repos. |
| `grant`, `evidence` | Issuer's space repo. |
| `compromise` | Reporting account's space repo. |

All use the [retention/access rules](audit.md#retention-and-access).

### Trusted host state

Clients MUST authenticate the host through the space authority's DID and deployed [Spaces protocol](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data). Clients MUST obtain membership decisions from its management implementation; `listRepos` enumerates writers, not membership. Existing management authority controls configuration and membership updates.

Retain these authenticated values by content reference:

| Value | Required fields |
| --- | --- |
| Configuration | `version: 1`, `kind: "configuration"`, `space`, positive monotonic `revision`, `grantProfile: "peep-hpke-v1"`, `deviceVerification: "tofu-permitted" \| "verified-only"`, positive `maxEncryptedBlobBytes` (default 16,777,216). |
| Membership decision | `version: 1`, `kind: "membership"`, `space`, `account`, positive per-account monotonic `revision`, `eligible: boolean`. Eligibility is the host's explicit PEEP participation decision under its management rules. |
| Epoch metadata | `version: 1`, `space`, positive `epoch`, `keyId: RandomId`, `commitment: Digest`, `previous: CID \| null`, `context: CID`, `history: HistoryWrap \| null` ([backward wrapping](#backward-history-wrapping)). |
| Activation outcome | `version: 1`, `space`, `requestId: RandomId`, `request: CID`, `status: "accepted" \| "stale" \| "rejected"`, `active: CID \| null`. An accepted outcome identifies the exact epoch accepted for that request. |

The host MUST expose authenticated reads of current configuration, per-account membership, active epoch, historical values by CID, and each epoch's accepted activation request/outcome. The host MUST preserve exact history and monotonic revisions through restart/migration. Unknown history is unavailable, not reconstructed as current state. Defaults apply only to authenticated creation. Clients MUST retain their highest known revisions: lower revisions cannot replace them, and equal revisions with different bytes are errors. A later eligible membership decision may re-admit an account without resetting device trust/history.

Clients MUST authenticate values by direct host retrieval or a retained local observation of that retrieval. Published copies supply bytes, not independent host authentication; readers lacking their own basis must resolve the reference against the host. Failure leaves required evidence unavailable. Clients MUST keep the authentication basis private. A host read supplies neither trusted issuance time nor proof against later changes.

The host MUST expose change notifications and resumable reconciliation for membership, configuration, and epochs. Notifications are fetch hints; cached validated state follows [freshness rules](device-enrollment.md#freshness). Unsupported deployments MUST report the missing capabilities. [Rotation](#rotation) defines epoch/activation semantics.

When learned, clients MUST visibly surface authenticated member additions, removals, readmissions, and verification-policy changes, identifying the affected account or old/new policy. Membership UI MUST explain that admission permits access to retained history. Notices add no approval gate and need not precede grants; learning about a change has no deadline.

## Device verification policy

Authenticated configuration selects a policy for both granting and accepting keys:

- **TOFU permitted (default):** clients MAY use TOFU or independently verified bindings.
- **Verified-only:** a client MUST independently verify the other device's exact binding, or validate same-account approval rooted in its own verified binding, before granting that device a key or accepting a key from it.

The issuer checks the recipient; the recipient checks the issuer. One issuer suffices when both clients pass their local checks. [Binding trust](device-enrollment.md#local-trust) is reusable across spaces; reported trust in a grant is not transferable verification. Missing verification blocks the operation, and clients MUST NOT fall back to TOFU when configuration is missing or unauthenticated.

The policy covers current and historical keys, publication retries, direct delivery, and first acceptance from archived grants. Tightening it does not undo disclosure, rewrite earlier decisions, or retroactively invalidate accepted keys or historically valid grants.

## Key grants

### Grant authorization

`AuthorizeExchange(space, epochRef, issuer, recipient, role, state)` checks a current exchange. `role` identifies the local installation as issuer or recipient; the other binding is the device it verifies. Implementations MUST perform G1–G6, returning the [specified failure result](#conformance-and-validation-results) at a failed check:

1. **G1 — Host evidence.** Resolve and authenticate configuration, the accepted epoch/request/outcome, and both accounts' membership decisions under [host rules](#trusted-host-state). Check exact space, references, profile, and epoch identity. A proposal without authenticated acceptance cannot authorize an exchange.
2. **G2 — Local state.** Incorporate authenticated observations using [declaration ancestry](device-enrollment.md#declaration-ancestry), [revocation processing](device-enrollment.md#revocation-cycles), and [freshness](device-enrollment.md#freshness). Use the latest locally known configuration, membership, and selections. Missing required paths return `INCOMPLETE`; a known declaration conflict returns `BLOCKED` for either role involving that account.
3. **G3 — Eligibility and selection.** Require both accounts to be eligible and both exact bindings to be selected. Require the local installation to match its stated role. A currently effective account removal or selection omission returns `BLOCKED`, even if the device holds a key; later valid readmission/reselection may restore eligibility. An account-wide exact-binding revocation remains permanent.
4. **G4 — Verification.** Apply the [device verification policy](#device-verification-policy) to the other binding using the local client's trust and approval provenance. Missing independent verification in verified-only mode returns `BLOCKED`; missing required approval evidence returns `INCOMPLETE`. Another client's reported trust is insufficient.
5. **G5 — Context.** Run [context validation](#context-validation) for both parties. Propagate any failure; host ordering and an event label cannot substitute for this check.
6. **G6 — Decision.** Return `OK` with the exact declarations, host decisions, context evidence, and local trust decision used. Persist that decision with any issuance or key acceptance; it MUST NOT reset pins, withdrawals, or conflicts.

An issuer MUST additionally hold exactly 32 key bytes matching the epoch commitment before constructing a grant. It MUST publish the signed grant and its [evidence](audit.md#evidence) in its own space repo through the [publication state machine](audit.md#publication). Each release attempt repeats authorization; credentials never authorize raw-key responses or arbitrary recipient keys. New grants of old keys use this same procedure. Reading an existing grant uses [grant acceptance](#grant-acceptance), including its archive mode.

### Distribution scheduling

After activation, the generator MUST make the first grant pass for selected devices it can authorize. Other eligible holders SHOULD fill gaps after randomized backoff or a recipient request when online and able to authorize delivery; newly selected devices use the same path. For a given epoch and recipient binding, reuse prepared grants under the [publication rules](audit.md#publication); observed grants may defer duplicate work but never establish recipient acceptance or complete coverage. The generator has no exclusive authority or mandatory delivery deadline.

Recipients MAY request another eligible issuer even when a grant exists: its issuer may fail their local verification policy, or its evidence/ciphertext may be unusable. Applications MUST provide a request path usable without the missing content key. Requests identify the space, epoch reference, and exact recipient binding; they are scheduling hints, never authorization. Issuers MUST resolve selections and apply normal grant checks independently. Implementations MUST bound request processing/retries; delays and partial views can still cause duplicates or gaps.

### Grant format

Use the [shared encoding and storage rules](#protocol-conventions). All shown fields are required; `CID` is a CBOR link. The authorization references identify the exact evidence used, and the full header is bound by HPKE and the signature.

```typescript
type DeviceIdentity = { account: string; deviceId: string };

type SpaceKeyGrant = {
  version: 1;
  space: string;             // Exact canonical space URI from trusted configuration.
  epoch: number;             // Positive integer identifying the content-key epoch.
  keyId: string;             // 16 random bytes encoded as 32 lowercase hex characters.
  recipient: DeviceIdentity;
  recipientKeyId: string;    // Fingerprint of the exact recipient X25519 public key.
  authorization: {
    recipientDeclaration: CID;
    issuerDeclaration: CID;
    configuration: CID;
    recipientMembership: CID;
    issuerMembership: CID;
    epoch: CID;             // Host-authenticated metadata, including rotation context.
    evidence: CID;          // Manifest of exact retained evidence values.
  };
  recipientTrust: "tofu" | "verified"; // Issuer's decision; not transferable verification.
  grantProfile: "peep-hpke-v1";
  encapsulation: Uint8Array; // 32-byte HPKE enc value.
  ciphertext: Uint8Array;    // 32-byte content key plus 16-byte HPKE authentication tag.
  issuer: DeviceIdentity;
  issuerKeyId: string;       // Fingerprint of the issuer's Ed25519 signing key.
  proof: Uint8Array;         // 64-byte Ed25519 signature.
};
```

### Mandatory grant profile

`peep-hpke-v1` uses [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) Base mode (`0x00`), DHKEM(X25519, HKDF-SHA256) (`0x0020`), HKDF-SHA256 (`0x0001`), and ChaCha20Poly1305 (`0x0003`). Signatures use [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) pure Ed25519 without an additional prehash. Clients MUST generate signing and encryption keypairs independently and MUST NOT convert one into the other or reuse short-lived DPoP keys.

X25519 public keys/encapsulations use RFC 9180's 32-byte encodings; Ed25519 public keys and signatures use RFC 8032's 32-byte and 64-byte `R || S` encodings. Implementations MUST require canonical encodings, reject malformed points/noncanonical signatures, and apply HPKE's KEM input and all-zero shared-secret checks.

A key fingerprint is lowercase hexadecimal SHA-256 of `CBOR(["peep/public-key", 1, algorithm, publicKeyBytes])`, with `algorithm` exactly `X25519` or `Ed25519`. Mutable discovery cannot redirect it to another key.

Let `H` be the grant map without `encapsulation`, `ciphertext`, and `proof`. Issuers MUST seal the raw 32-byte content key in a fresh single-shot HPKE context:

```text
info = CBOR(["peep/grant-info", 1, H])
aad  = CBOR(["peep/grant-aad", 1, H])
(encapsulation, ciphertext) = SealBase(recipientPublicKey, info, aad, spaceKey)
proof = Ed25519.Sign(issuerPrivateKey,
  CBOR(["peep/grant-signature", 1, grantWithoutProof]))
```

HPKE Base mode does not authenticate the sender; the issuer signature is REQUIRED. Verification failure MUST NOT trigger suite fallback. Profile changes require authenticated configuration updates. Content uses the separate [record/blob encryption format](#content-encryption).

### Grant acceptance

`AcceptGrant(grant, expectedSpace, localBinding, mode, state)` returns a key only after A1–A7. `mode` is `current` for a current exchange or `archive` for historical reading of an existing grant. Archive mode MUST NOT authorize publication retries or direct forwarding.

1. **A1 — Decode.** Strictly validate grant fields, lengths, profile, and references. Require the expected space and the local account, device ID, and encryption-key fingerprint as recipient. Mismatches return `INVALID`.
2. **A2 — Evidence and signature.** Resolve the [required evidence](audit.md#evidence), authenticate host values, and validate both declarations, their binding/approval evidence, and the issuer signature as issuance evidence. Match both identities and key fingerprints to the selected bindings in the referenced declarations; the recipient binding MUST equal `localBinding` in account, device ID, and both public keys. Missing required evidence returns `INCOMPLETE`; invalid evidence or a binding mismatch returns `INVALID`. Authorization is checked separately in A4.
3. **A3 — Epoch.** Match space, epoch, and key ID to authenticated accepted metadata and validate its structure, context references, and activation evidence. Later history traversal is not required to accept the starting key.
4. **A4 — Authorization.** In both modes, check the [recorded authorization basis](audit.md#archived-grants). Current mode MUST additionally run `AuthorizeExchange` with role `recipient`; retain that decision separately from the issuer's recorded basis. Archive mode does not require current enrollment; later membership/selection removal or revocation alone MUST NOT invalidate historical reading. A client MUST NOT relabel a failed current operation as an authorized current exchange by switching modes.
5. **A5 — Identity policy.** Before first key acceptance in either mode, require the issuer binding to satisfy the locally current verification policy. Archive reading MAY use retained verification of a formerly authorized binding; this grants it no current authority. New approval paths still obey withdrawn-approver rules. Valid signatures, decryption, and reported recipient trust cannot bypass verification.
6. **A6 — Open.** Use the mandatory HPKE profile and exact header-derived `info`/AAD. Require successful authentication and exactly 32 plaintext bytes matching the epoch commitment; otherwise return `INVALID` and discard the candidate key.
7. **A7 — Commit.** Recheck any authorization/policy affected by newly learned state. Durably retain the key, exact grant/evidence, local trust decision, and audit assessments before exposing the key to content operations. Return `OK`; historical acceptance MUST NOT roll back the active write epoch or restore authority.

## Content encryption

### Encryption envelope

Records and blobs share this envelope:

```typescript
{
  $type: "com.example.peep.envelope"
  format: 1
  keyId: string // "71329bda9cf34bf7a8f68f475e166981"
  nonce: bytes // exactly 24 bytes
  ciphertext: bytes // encrypted payload frame and appended 16-byte tag
  blobs: [references to encrypted blobs]
}
```

Format 1 uses XChaCha20-Poly1305 with the 256-bit key identified by `keyId`. Writers MUST generate a fresh cryptographically random 24-byte nonce for every encryption, including edits and re-encryption. Clients MUST NOT reuse a nonce with the same key across records, blobs, or history wraps. Ciphertext includes the appended 16-byte authentication tag and is exactly 16 bytes longer than the encoded [payload frame](#payload-framing-and-padding).

Associated-data arrays below use normalized CBOR: labels are literal strings, `1` is an integer, and identifiers are strings. Use the exact authenticated `spaceURI` and its corresponding `keyId`. Distinct record/blob labels separate their cryptographic contexts.

Only the shown envelope fields are permitted; `nonce` and `ciphertext` are CBOR byte strings. Receivers MUST reject an incorrect `$type`, duplicate or unexpected fields, unknown formats, invalid nonce lengths, ciphertext shorter than 19 bytes, unavailable keys, and failed authentication. Receivers MUST authenticate the complete ciphertext in the expected context before exposing plaintext.

### Payload framing and padding

Format 1 writers MUST encrypt `CBOR([payload, padding])`, exactly two byte strings. `payload` holds encoded record content or original file bytes; `padding` contains only zero bytes and may be empty. Even unpadded content uses this frame. Payload length is encoded inside encryption; no outer original-length or padding field is added. Grants and history wraps retain their separate plaintext formats.

After whole-ciphertext authentication, receivers MUST decode the frame with bounded lengths/work and reject non-normalized CBOR, wrong element counts/types, nonzero padding, or trailing bytes. Decoders MUST check declared lengths against available bytes and resource limits before allocation. Receivers MUST discard padding and process only `payload`; they MUST NOT fall back to unframed content.

Applications choose padding amounts or size buckets, accounting for CBOR overhead. Readers MUST support empty and nonempty padding within their resource limits. Ciphertext limits include the frame, padding, and tag; blob limits cover the entire encrypted envelope. Padding can obscure exact content lengths; counts, timing, blob relationships, and padded record/blob sizes remain visible.

### Encrypted records

`payload` is the normalized ATProto CBOR encoding of one map containing the application's content object and `$type`. Each record lexicon declares its outer collection/type and inner schema. After authentication and frame validation, receivers MUST decode `payload` and reject non-normalized encoding, duplicate keys, trailing bytes, a non-map root, or an incorrect content `$type`; receivers MUST validate the inner schema before rendering or indexing.

The outer `$type` MUST match the collection. Application semantics belong inside the encrypted content; additional outer fields need separate authentication before influencing trusted presentation. Applications MUST declare finite ciphertext-size, nesting-depth, and collection-size limits and enforce them before allocation and during bounded decoding, including for authenticated content.

```typescript
const content = { $type: "app.example.message#content", text: "Hello!" };
const plaintext = CBOR([CBOR(content), new Uint8Array(0)]);
// Encrypt plaintext with the record associated data below.
{
  $type: "app.example.message",
  envelope: {
    $type: "com.example.peep.envelope",
    format: 1,
    keyId: "71329bda9cf34bf7a8f68f475e166981",
    nonce: Uint8(...),
    ciphertext: Uint8(...),
    blobs: []
  }
}
```

Blob references MUST appear in the envelope for PDS retention, even when also included in content. After authentication and schema validation, receivers MUST check every blob reference throughout the decoded content, including nested maps/arrays, for an identical entry in the authenticated envelope `blobs` list. Receivers MUST compare the complete normalized CBOR reference, including CID, MIME type, and size; reject missing or mismatched entries before rendering, indexing, or using the references. Ordinary CID links are not blob references; extra envelope entries are allowed for retention. Record associated data is:

```text
["peep/record", 1, spaceURI, authorDID, collection, recordKey, keyId, blobs]
```

`blobs` is the complete envelope reference array in stored order, with CIDs as CBOR links. Allocate `recordKey` before encryption. Receivers reconstruct the context from the expected record location and envelope.

This binding prevents relocation by someone without the key. It neither establishes authorship against another key holder nor prevents replay at the same location. Applications MUST verify Spaces repository/sync authentication for the expected author, space, revision, and contents; enforce write permissions; and retain sync checkpoints to reject known rollback. Successful decryption or an inner `author` field is not proof of authorship.

A malicious author PDS colluding with a key holder can forge attribution. Applications requiring independent device authorship need a separate profile selected at space creation; Format 1 and enrollment approvals do not provide it. Content/location/revision binding, replay handling, and deniable rebroadcast remain [TODO-11](TODOs.md#todo-11).

### Encrypted blobs

Blob writers MUST frame the original file bytes as `payload`, then encrypt the frame as one envelope with `blobs: []`. Upload its normalized CBOR encoding as `application/octet-stream`. Blob associated data is:

```text
["peep/blob", 1, spaceURI, keyId]
```

Omitting the blob CID and containing record location permits reuse within the same space. Following the [ATProto blob format](https://atproto.com/specs/blob), the reference uses CIDv1 with the raw codec and SHA-256 of the entire uploaded envelope; `size` counts all those envelope bytes, including framing, padding, and the authentication tag. Store the original MIME type, filename, and other metadata in the encrypted record. Record authentication binds the resulting reference. A reused blob retains its original `keyId`.

Blob readers MUST verify the referenced CID and size before decoding, then apply envelope validation, authentication, and frame validation. Blob readers MUST reject malformed or non-normalized CBOR and trailing bytes, and return only the recovered `payload` as the original file.

The authenticated configuration sets a positive, finite `maxEncryptedBlobBytes`, defaulting to 16 MiB (16,777,216 bytes), for the complete envelope. Configuration updates may change it; enforce any smaller transport limit. Clients MUST check size before download/allocation and cap actual bytes received regardless of the server's reported size.

Blob readers MUST NOT release plaintext before whole-file authentication. Any temporary plaintext produced internally MUST remain inaccessible and be discarded on failure. Format 1 does not support independently authenticated chunks or range decryption; streaming requires a separate format under [TODO-13](TODOs.md#todo-13).

## Rotation

### Triggers

A fresh replacement is REQUIRED after an account is removed, a device with access to the current key is removed/revoked, or that key is known or suspected compromised, under the [pending-event rules](#rotation-context). An accepted replacement that already addresses the event satisfies this requirement; clients MUST NOT rotate again solely because they learn or replay that event later. Device removal includes declaration omission; account-wide revocation applies in each space where the device had current-key access. Additions alone and access only to older keys do not require rotating an unaffected key; mixed updates enforce removals.

Act when authenticated changes are learned. Exclusion requires a fresh key, authorized grants, and writers switching; copied keys/plaintext cannot be withdrawn. [Freshness](device-enrollment.md#freshness) provides no propagation deadline.

### Epochs

The creator generates the first key; an eligible enrolled client generates each replacement. Generators MUST use a fresh independent random 256-bit key after processing the inherited context and any newly known events. Generators MUST NOT reuse a candidate generated/distributed under an earlier authorization context.

The [trusted host](#trusted-host-state) orders accepted epoch metadata; a local proposal or grant cannot activate it. Epoch numbers start at 1 and increment through 2^53−1. Each has a unique random `keyId` and commitment `SHA-256(CBOR(["peep/key", 1, spaceURI, epoch, keyId, keyBytes]))`. The commitment checks agreement; it does not give the host usable key material.

### Backward history wrapping

Epoch metadata has a required `history` field: `null` at creation, otherwise either `null` or:

```typescript
type HistoryWrap = {
  nonce: bytes;       // Fresh random 24-byte nonce.
  ciphertext: bytes;  // Raw 32-byte predecessor key plus 16-byte authentication tag.
};
```

When the generator holds an accepted key for `previous`, the generator MUST include its wrap before activation. Otherwise it MUST use `null`; missing history never blocks availability recovery. Encrypt that predecessor key with the new epoch key using [XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction). Associated data is `CBOR(["peep/history", 1, H])`, where `H` is the proposed epoch metadata without `history`. This binds the space, both epoch identities through `previous`, new key commitment, and rotation context without a reference cycle. Nonces MUST NOT repeat under the same key, including content encryption.

The activation signature and authenticated epoch reference commit to the exact wrap. Once accepted, the host MUST NOT change its bytes or replace a `null` value. Clients MUST NOT later publish supplementary wraps under an existing epoch key: removed devices may still hold it. Backfill missing keys through ordinary device grants using current authorization; each such grant can unlock its own connected history.

A signed grant supplies its starting key and all keys reachable through these committed wraps. First acceptance of each derived key MUST apply the [device verification policy](#device-verification-policy) to that grant's issuer, including after policy tightening. Historical traversal needs no separate grant from each earlier generator and transfers no device-verification status. Readers MUST resolve predecessor metadata by CID and authenticate it under the host rules. Readers MUST require the same space, the immediately preceding epoch number, exact fields/lengths, successful AEAD authentication, exactly 32 decrypted bytes, and a matching predecessor commitment before using each key. Readers MUST preserve the starting grant and traversal evidence.

Readers MUST use finite resumable byte/node/work limits and MAY traverse lazily with cached results. Creation ends traversal normally. A later null wrap, unavailable/invalid predecessor metadata, failed wrap authentication/commitment, or exhausted budget stops that path and is reported explicitly. Structural errors in the starting metadata fail the starting grant; traversal failures do not invalidate an otherwise accepted starting key. Request a normal grant for a missing historical epoch and continue from there. Older-key reads MUST NOT roll back the active write epoch. The host MUST retain exact wraps indefinitely as part of immutable epoch history; initial key acceptance need not replay it all.

One starting grant replaces per-device grants along a connected chain, while reading its full history still costs one small wrap per epoch. A leaked key exposes all history reachable from it. Older keys cannot derive fresh successors, and deleting a wrap cannot undo exposure. A key is lost only when no direct copy, decryptable backup, or decryptable path from a surviving later key remains.

### Rotation context

Every epoch references `{ version: 1, space, events: CID[] }`, with `events` a set. Creation is empty unless applicable restrictions are already known. Each successor MUST include the predecessor's entire event set plus newly addressed events. Hosts and issuers MUST retain event/context bytes in epoch history and grant evidence, respectively.

Each event is an exact map with `version: 1`, `space`, and:

| `kind` | Additional fields | Effect |
| --- | --- | --- |
| `membership` | `decision: CID` | A host-authenticated ineligible membership decision. Grants involving that account require a later authenticated eligible decision. |
| `selection` | `before: CID`, `after: CID` | Same-account signed declarations with validated replacement ancestry. The omitted exact bindings are removed. Grants involving that account require `after` or a valid descendant/resolution, not an older selection. |
| `revocation` | `revocation: CID` | An account-wide signed revocation, validated under local trust. Permanently excludes that exact binding as recipient or issuer and applies the normal approval-authority rules. |
| `compromise` | `report: CID` | A device-signed report identifying the compromised epoch/key; requires a fresh replacement for that key. It creates no account/device ban by itself. |

Selection evidence MUST establish replacement ancestry and removals. Later valid membership/selection authorization may re-admit an account or per-space removed device; account-wide exact-binding revocation is permanent. The context retains the earlier event while enforcing this distinction.

A compromise report is `{ version: 1, space, epoch: CID, reporter: Binding, declaration: CID, proof: bytes }`, signed over `CBOR(["peep/key-compromise", 1, reportWithoutProof])`. Validate reports from eligible enrolled key holders with supporting authorization evidence; clients may also act on their own knowledge. The epoch reference fixes the affected key commitment. Reports assert suspected disclosure without revealing the key or proving a leak; older-key reports do not repeatedly rotate unaffected successors.

#### Context validation

For each current exchange, retry, or direct delivery, the client MUST apply C1–C4 to the epoch's full context:

1. **C1 — Identify scope.** Resolve the context and every event, checking hashes, version, kind, and space. Resolve the event's referenced decision/declarations/revocation/report far enough to identify its affected account, exact binding, or epoch. If any event's scope cannot be established, return `INCOMPLETE` for the exchange; the client cannot assume it is unrelated. Malformed or contradictory scope returns `INVALID`.
2. **C2 — Validate relevant evidence.** For events affecting either party or the key being issued, authenticate the required host decision, signatures, approval authority, and declaration ancestry. Missing required evidence returns `INCOMPLETE` for affected exchanges; invalid evidence returns `INVALID`. Scope established as unrelated does not impose another account's private verification history on this exchange. Required published evidence remains mandatory under [evidence rules](audit.md#evidence).
3. **C3 — Enforce effects.** Apply the event table to the affected parties: a later eligible decision may satisfy membership restrictions; selection must be `after` or its valid descendant/resolution; exact-binding revocation is permanent. Compromise reports follow the [trigger rules](#triggers) and the pending-event rule below; they create no membership/device ban or separate write pause. An inherited report already addressed by a replacement MUST NOT trigger another rotation. Unsatisfied authorization restrictions return `BLOCKED`.
4. **C4 — Include local knowledge.** Also enforce learned withdrawals and declaration conflicts absent from the context. Return `OK` only after all relevant restrictions pass; another issuer's trust status is not evidence for this client's checks.

Clients MUST track each pending event with its at-risk key. It is addressed only by an accepted fresh replacement containing that exact event or its inherited reference, with restrictions enforced. A competing epoch omitting it requires a fresh proposal against the accepted epoch; re-observing an addressed event does not. Unauthorized disclosure of the replacement is a new event naming that key.

### Activation

Request `{ version: 1, requestId: RandomId, proposal: EpochMetadata, proposer: Binding, declaration: CID, evidence: CID, proof: bytes }`, signed over `CBOR(["peep/activate-epoch", 1, requestWithoutProof])`. [Evidence](audit.md#evidence) supplies proposer authorization and context/events. The signature binds the proposal/commitment/context/history and asserts eligibility, enrollment, durable key possession, and generation after processing events. `proposal.previous` is the expected active epoch, or `null` at creation.

#### Host request processing

The host MUST authenticate the caller, scope request IDs by `(space, proposer account, requestId)`, and perform H1 before admission or current-eligibility checks. An admitted new request MUST be durably bound to its exact CID before H2 validation; throttling before admission creates no binding or terminal outcome. The host MUST retain bindings and terminal outcomes. An outcome and the accepted epoch/active pointer MUST commit atomically; a crash cannot leave an activation without its durable outcome.

| Step | Condition | Required effect/result |
| --- | --- | --- |
| H1 | ID already bound | Different bytes are an integrity error and MUST NOT replace the binding. If the same request has a terminal outcome, return it unchanged before applying current eligibility, uniqueness, or throttling checks. |
| H2 | No terminal outcome | Verify signature, presented declaration/binding/selection, caller/proposer account match, eligibility, required evidence, commitment/history structure, unique key ID, predecessor-based epoch number, and full context inheritance. Non-null creation history and overflow are invalid. A definitive validation failure yields durable `rejected`. If required validation is unavailable or admission is throttled, return a nonterminal error without activation; the exact request remains retryable. |
| H3 | Valid request, expected predecessor no longer active | Atomically store `stale` and the active reference; MUST NOT queue automatic activation. |
| H4 | Valid request, expected predecessor still active | Atomically recheck eligibility and state-dependent H2 checks, accept the exact proposal, advance the active pointer, and store `accepted` referencing that epoch. |

The host MUST serialize these decisions against membership and epoch changes. History ciphertext decryption and the proposer's claimed key durability are not host-verifiable. Host checks do not supply the recipients' local device verification.

#### Client activation states

Clients MUST use the following durable states for each immutable request, or equivalent state preserving these effects. Acceptance of a request, the latest known active epoch, and whether further request transmission is enabled are separate facts.

| Step | State/event | Required action and next state |
| --- | --- | --- |
| T1 | New proposal | Process inherited/new events, generate a fresh key/ID, and durably store key bytes, proposal, context, exact request/ID, status, and transmission enabled. Enter `prepared`; MUST NOT send before persistence. |
| T2 | `prepared`, transmission enabled | Persist `outcome-unknown` before submitting the exact request. |
| T3 | `outcome-unknown`, timeout/restart/no terminal result | Query authenticated request status, or resend identical bytes/ID only while transmission remains enabled. Remain `outcome-unknown` until an authenticated terminal result arrives. |
| T4 | Authenticated terminal result | Match space, account-scoped ID, and request CID; persist `accepted`, `stale`, or `rejected`. An accepted result MUST identify the exact proposed epoch. |
| T5 | `accepted` | Grants MAY proceed under current exchange/publication checks. Fetch current active metadata separately; replayed outcomes for this request MUST NOT roll back a later epoch. |
| T6 | `stale` or `rejected` | MUST NOT write or grant using the losing proposal. Follow the accepted active epoch; if rotation or availability recovery is still needed, start T1 with a new key/ID and proposal. |
| T7 | Cancellation or abandonment | Durably disable further request transmission; restart and late results MUST NOT re-enable it. Retain the request and its known outcome or uncertainty. Read-only reconciliation MAY continue through T4. Cancellation MUST NOT be recorded as host rejection or nonacceptance. |

Exact retries MUST return the original host outcome even after later rotations. Generator authority is evaluated at activation; later withdrawal does not invalidate the historical commitment. Activation requires no grants, self-grants, recipient acknowledgment, or complete recipient evidence. Offline recipients do not prevent activation; later grants still require current authorization. Acceptance proves neither delivery nor key availability: devices without the key cannot read the epoch, and loss of every copy, backup, and usable later wrap loses its content. It also proves no independent device verification, randomness, issuance time, or absence of hidden events/leakage.

### Availability recovery

Any eligible enrolled device MAY propose a fresh successor when it cannot obtain the active key, without holding that key or presenting a new security trigger. No proof of zero grants, recipient acknowledgment, or protocol-wide timeout is required. Applications MAY use local retrieval retries/backoff or offer a user-initiated recovery action.

Recovery clients MUST use normal activation and grant procedures, inheriting the full rotation context and incorporating newly known events; no availability event type is needed. Recovery cannot bypass required authorization/context evidence or the verification policy for granting and accepting keys. After acceptance, distribute the successor key and resume content writes as clients obtain it. Content under the unavailable key remains unreadable unless that key is recovered.

### Abuse controls

The host MUST apply configurable activation-request budgets per authenticated account, with bounded queues/work; additional device IDs do not reset the account budget. The host MUST preserve idempotent results and terminal outcomes under throttling. Hosts and clients MUST bound compromise-report processing and deduplicate identical reports. Proposers SHOULD combine applicable known events when doing so does not delay required action. Coalescing MUST NOT postpone enforcing learned withdrawals or discard unresolved events.

Signed reports establish who asserted compromise, not proof of a leak; availability recovery requires no security trigger. The protocol imposes no minimum interval between accepted epochs. Allow existing administrators to adjust limits for urgent rotation or remove abusers; expose throttling rather than claiming a request succeeded. Repeated disruption can still prevent progress; limits may delay recovery and provide no unconditional availability guarantee.

### Writers

Writers MUST use the latest authenticated active epoch known, including cached state. A trigger initiates rotation without a separate write pause; normal Spaces write authorization and immediate learned-withdrawal enforcement for grants still apply.

After learning a newer active epoch, writers MUST re-encrypt unpublished records, edits, and blobs with fresh nonces. They MUST pause content publication if its key is unavailable; [availability recovery](#availability-recovery) remains permitted. Writers MUST NOT fall back or roll back. They MUST recheck the known active epoch before each publication operation. In-flight old-key uploads may already be exposed despite cancellation: retain that fact, upload replacements as needed, and do not link old-key objects as though they excluded former holders.

Offline reads and protected local drafts remain available. Old-key content remains readable by former key holders who obtain it, including reused blobs. There is no deadline for all writers to learn the new epoch. [Private state and restore](device-enrollment.md#recovery) preserve known epochs and pending operations.
