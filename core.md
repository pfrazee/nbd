# PEEP: Core

## Scope

Each space uses a symmetric content key per epoch. Usable keys, plaintext, caches, search, previews, and exports stay on clients; servers store ciphertext, declarations, evidence, and encrypted grants. PEEP provides neither forward secrecy, post-compromise security, nor metadata hiding. Endpoints, software/updates, authorized key holders, and the space host are trusted; other PDSes and repo hosts may be malicious.

The [space host](#trusted-host-state) determines account eligibility, configuration, administration, and epoch order. Credentials and writer discovery do not establish membership or device trust. [Signed declarations](device-enrollment.md#declarations) select devices; no enrollment registry, global enrollment chain, creator-device approval, or issuer appointment is required.

Any eligible participant's enrolled device may grant keys it holds. Current members' selected devices are eligible for all retained epochs, including pre-join content. Key possession grants no administrative or device-approval authority. Availability requires an eligible key holder; [recovery](device-enrollment.md#recovery) cannot recreate lost keys.

## Protocol conventions

Names under `com.example.peep` and host operations are proposed extensions. Production namespaces and concrete Spaces transport mapping remain [TODO-03](TODOs.md#todo-03).

### Encoding and identifiers

`CBOR(x)` means normalized ATProto CBOR, including byte strings and CID links. Decode with finite limits and reject duplicate/unknown fields, non-normalized encodings, trailing bytes, wrong types, unknown versions, invalid key/signature encodings, and integers outside 0 through 2^53−1. All fields shown are required; `null` is permitted only where shown. Never hash JSON or a displayed CID string. Sets are arrays sorted by unsigned lexicographic order of their elements' normalized CBOR bytes, with duplicates rejected; other arrays retain their specified order.

`Ref(x)` is a CIDv1 with codec `dag-cbor` (`0x71`) and SHA-256 multihash of `CBOR(x)`. Resolve a reference to exactly those bytes and check its hash before interpreting it. This commits to content, not authority, freshness, or availability. `Digest` is a 32-byte SHA-256 result. `RandomId` is 16 independently random bytes encoded as 32 lowercase hexadecimal characters. All identities use exact DIDs, never mutable handles. Space identifiers use the exact canonical URI obtained from the authenticated host; do not normalize identifiers differently for signing and verification.

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

Authenticate the host through the space authority's DID and deployed [Spaces protocol](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data). Obtain membership decisions from its management implementation; `listRepos` enumerates writers, not membership. Existing management authority controls configuration and membership updates.

Retain these authenticated values by content reference:

| Value | Required fields |
| --- | --- |
| Configuration | `version: 1`, `kind: "configuration"`, `space`, positive monotonic `revision`, `grantProfile: "peep-hpke-v1"`, `deviceVerification: "tofu-permitted" \| "verified-only"`, positive `maxEncryptedBlobBytes` (default 16,777,216). |
| Membership decision | `version: 1`, `kind: "membership"`, `space`, `account`, positive per-account monotonic `revision`, `eligible: boolean`. Eligibility is the host's explicit PEEP participation decision under its management rules. |
| Epoch metadata | `version: 1`, `space`, positive `epoch`, `keyId: RandomId`, `commitment: Digest`, `previous: CID \| null`, `context: CID`. |
| Activation outcome | `version: 1`, `space`, `requestId: RandomId`, `request: CID`, `status: "accepted" \| "stale" \| "rejected"`, `active: CID \| null`. An accepted outcome identifies the exact epoch accepted for that request. |

Expose authenticated reads of current configuration, per-account membership, active epoch, historical values by CID, and each epoch's accepted activation request/outcome. Preserve exact history and monotonic revisions through restart/migration. Unknown history is unavailable, not reconstructed as current state. Defaults apply only to authenticated creation. Clients retain their highest known revisions: lower revisions cannot replace them, and equal revisions with different bytes are errors. A later eligible membership decision may re-admit an account without resetting device trust/history.

Authenticate values by direct host retrieval or a retained local observation of that retrieval. Published copies supply bytes, not independent host authentication; readers lacking their own basis must resolve the reference against the host. Failure leaves required evidence unavailable. Keep the authentication basis private. A host read supplies neither trusted issuance time nor proof against later changes.

Expose change notifications and resumable reconciliation for membership, configuration, and epochs. Notifications are fetch hints; cached validated state follows [freshness rules](device-enrollment.md#freshness). Unsupported deployments must report the missing capabilities. [Rotation](#rotation) defines epoch/activation semantics.

## Device verification policy

Authenticated configuration selects a policy for both granting and accepting keys:

- **TOFU permitted (default):** clients may use TOFU or independently verified bindings.
- **Verified-only:** a client must independently verify the other device's exact binding, or validate same-account approval rooted in its own verified binding, before granting that device a key or accepting a key from it.

The issuer checks the recipient; the recipient checks the issuer. One issuer suffices when both clients pass their local checks. [Binding trust](device-enrollment.md#local-trust) is reusable across spaces; reported trust in a grant is not transferable verification. Missing verification blocks the operation, and missing/unauthenticated configuration never permits TOFU fallback.

The policy covers current and historical keys, publication retries, direct delivery, and first acceptance from archived grants. Tightening it does not undo disclosure, rewrite earlier decisions, or retroactively invalidate accepted keys or historically valid grants.

## Key grants

### Grant authorization

Before releasing a grant to a recipient or relay, verify:

1. Both accounts are eligible and both exact device bindings are selected by authenticated, current declarations.
2. The recipient meets the device verification policy, with the local trust decision and approval evidence retained.
3. The issuer holds the requested key; [declaration continuity/conflict](device-enrollment.md#enrollment-history) and [withdrawal/freshness](device-enrollment.md#freshness) checks pass for both parties.
4. The epoch's [rotation context](#rotation-context) permits the grant, including inherited restrictions.

Missing or invalid required evidence blocks release. Known removals and withdrawals apply even to key holders. Credentials never authorize raw-key responses or grants to arbitrary supplied keys. New grants of old keys use these same current checks; historical reading uses [archive validation](audit.md#archived-grants).

Publish each signed grant with its [evidence](audit.md#evidence) in the issuer's own space repo. The [publication procedure](audit.md#publication) governs retries and direct forwarding; the grant is its audit record.

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

`peep-hpke-v1` uses [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) Base mode (`0x00`), DHKEM(X25519, HKDF-SHA256) (`0x0020`), HKDF-SHA256 (`0x0001`), and ChaCha20Poly1305 (`0x0003`). Signatures use [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) pure Ed25519 without an additional prehash. Generate signing and encryption keypairs independently; never convert one into the other or reuse short-lived DPoP keys.

X25519 public keys/encapsulations use RFC 9180's 32-byte encodings; Ed25519 public keys and signatures use RFC 8032's 32-byte and 64-byte `R || S` encodings. Require canonical encodings, reject malformed points/noncanonical signatures, and apply HPKE's KEM input and all-zero shared-secret checks.

A key fingerprint is lowercase hexadecimal SHA-256 of `CBOR(["peep/public-key", 1, algorithm, publicKeyBytes])`, with `algorithm` exactly `X25519` or `Ed25519`. Mutable discovery cannot redirect it to another key.

Let `H` be the grant map without `encapsulation`, `ciphertext`, and `proof`. Seal the raw 32-byte content key in a fresh single-shot HPKE context:

```text
info = CBOR(["peep/grant-info", 1, H])
aad  = CBOR(["peep/grant-aad", 1, H])
(encapsulation, ciphertext) = SealBase(recipientPublicKey, info, aad, spaceKey)
proof = Ed25519.Sign(issuerPrivateKey,
  CBOR(["peep/grant-signature", 1, grantWithoutProof]))
```

Before opening a grant, validate its fields/types/lengths/profile, both declarations, issuer signature, and both parties' [membership/enrollment evidence](#grant-authorization) under the applicable trust and freshness rules. Match grant identities/key fingerprints to selected bindings and the space/epoch/key ID to authenticated host metadata. Apply the device verification policy to the issuer using the recipient's own trust; use [historical validation](audit.md#archived-grants) for archives. A valid signature or successful decryption cannot substitute for verification. Require exactly 32 plaintext bytes matching the authenticated [epoch commitment](#epochs).

HPKE Base mode does not authenticate the sender; the issuer signature is mandatory. Verification failure must not trigger suite fallback. Profile changes require authenticated configuration updates. Content uses the separate [record/blob encryption format](#content-encryption).

## Content encryption

### Encryption envelope

Records and blobs share this envelope:

```typescript
{
  $type: "com.example.envelope"
  format: 1
  keyId: string // "71329bda9cf34bf7a8f68f475e166981"
  nonce: bytes // exactly 24 bytes
  ciphertext: bytes // combined ciphertext and authentication tag
  blobs: [references to encrypted blobs]
}
```

Format 1 uses XChaCha20-Poly1305 with the 256-bit key identified by `keyId`. Generate a fresh cryptographically random 24-byte nonce for every encryption, including edits and re-encryption. Never reuse a nonce with the same key across records or blobs. Ciphertext includes the appended 16-byte authentication tag and is exactly 16 bytes longer than plaintext.

Associated-data arrays below use normalized CBOR: labels are literal strings, `1` is an integer, and identifiers are strings. Use the exact authenticated `spaceURI` and its corresponding `keyId`. Distinct record/blob labels separate their cryptographic contexts.

Only the shown envelope fields are permitted; `nonce` and `ciphertext` are CBOR byte strings. Reject duplicate or unexpected fields, unknown formats, invalid nonce lengths, ciphertext shorter than 16 bytes, unavailable keys, and failed authentication. Authenticate the complete ciphertext in the expected context before exposing plaintext.

### Encrypted records

Plaintext is one normalized ATProto CBOR map containing the application's content object and `$type`. Each record lexicon declares its outer collection/type and inner schema. After authentication, reject non-normalized encoding, duplicate keys, trailing bytes, a non-map root, or an incorrect content `$type`; validate the inner schema before rendering or indexing.

The outer `$type` must match the collection. Application semantics belong inside the encrypted content; additional outer fields need separate authentication before influencing trusted presentation. Applications must declare finite ciphertext-size, nesting-depth, and collection-size limits and enforce them before allocation and during bounded decoding, including for authenticated content.

```typescript
{
  $type: "app.example.message",
  envelope: {
    $type: "com.example.envelope",
    format: 1,
    keyId: "71329bda9cf34bf7a8f68f475e166981",
    nonce: Uint8(...),
    ciphertext: /* encrypted blob that contains: */ {
      $type: "app.example.message#content",
      text: "Hello!"
    },
    blobs: []
  }
}
```

Blob references must appear in the envelope for PDS retention, even when also included in plaintext. Record associated data is:

```text
["peep/record", 1, spaceURI, authorDID, collection, recordKey, keyId, blobs]
```

`blobs` is the complete envelope reference array in stored order, with CIDs as CBOR links. Allocate `recordKey` before encryption. Receivers reconstruct the context from the expected record location and envelope.

This binding prevents relocation by someone without the key. It neither establishes authorship against another key holder nor prevents replay at the same location. Applications verify Spaces repository/sync authentication for the expected author, space, revision, and contents; enforce write permissions; and retain sync checkpoints to reject known rollback. Successful decryption or an inner `author` field is not proof of authorship.

A malicious author PDS colluding with a key holder can forge attribution. Applications requiring independent device authorship need a separate profile selected at space creation; Format 1 and enrollment approvals do not provide it. Content/location/revision binding, replay handling, and deniable rebroadcast remain [TODO-11](TODOs.md#todo-11).

### Encrypted blobs

Encrypt the original file bytes as one envelope with `blobs: []`. Upload its normalized CBOR encoding as `application/octet-stream`. Blob associated data is:

```text
["peep/blob", 1, spaceURI, keyId]
```

Omitting the blob CID and containing record location permits reuse within the same space. Following the [ATProto blob format](https://atproto.com/specs/blob), the reference uses CIDv1 with the raw codec and SHA-256 of the entire uploaded envelope; `size` counts those envelope bytes. Store the original MIME type, filename, and other metadata in the encrypted record. Record authentication binds the resulting reference. A reused blob retains its original `keyId`.

Verify the referenced CID and size before decoding, then apply envelope validation and authentication. Reject malformed or non-normalized CBOR and trailing bytes.

The authenticated configuration sets a positive, finite `maxEncryptedBlobBytes`, defaulting to 16 MiB (16,777,216 bytes), for the complete envelope. Configuration updates may change it; enforce any smaller transport limit. Check size before download/allocation and cap actual bytes received regardless of the server's reported size.

Release no plaintext before whole-file authentication. Any temporary plaintext produced internally must remain inaccessible and be discarded on failure. Format 1 does not support independently authenticated chunks or range decryption; streaming requires a separate format under [TODO-13](TODOs.md#todo-13).

## Rotation

### Triggers

Require a new epoch after an account is removed, a device with access to the current key is removed/revoked, or that key is known or suspected compromised. Device removal includes declaration omission; account-wide revocation applies in each space where the device had current-key access. Additions alone and access only to older keys do not require rotating an unaffected key; mixed updates enforce removals.

Act when authenticated changes are learned. Exclusion requires a fresh key, authorized grants, and writers switching; copied keys/plaintext cannot be withdrawn. [Freshness](device-enrollment.md#freshness) provides no propagation deadline.

### Epochs

The creator generates the first key; an eligible enrolled client generates each replacement. Use a fresh independent random 256-bit key after processing the trigger evidence and its restrictions. Never reuse a candidate generated/distributed under an earlier authorization context.

The [trusted host](#trusted-host-state) orders accepted epoch metadata; a local proposal or grant cannot activate it. Epoch numbers start at 1 and increment through 2^53−1. Each has a unique random `keyId` and commitment `SHA-256(CBOR(["peep/key", 1, spaceURI, epoch, keyId, keyBytes]))`. The commitment checks agreement; it does not give the host usable key material.

### Rotation context

Every epoch references `{ version: 1, space, events: CID[] }`, with `events` a set. Creation is empty unless applicable restrictions are already known. Each successor includes the predecessor's entire event set plus newly addressed events. Retain event/context bytes in host epoch history and grant evidence.

Each event is an exact map with `version: 1`, `space`, and:

| `kind` | Additional fields | Effect |
| --- | --- | --- |
| `membership` | `decision: CID` | A host-authenticated ineligible membership decision. Grants involving that account require a later authenticated eligible decision. |
| `selection` | `before: CID`, `after: CID` | Same-account signed declarations with validated replacement ancestry. The omitted exact bindings are removed. Grants involving that account require `after` or a valid descendant/resolution, not an older selection. |
| `revocation` | `revocation: CID` | An account-wide signed revocation, validated under local trust. Permanently excludes that exact binding as recipient or issuer and applies the normal approval-authority rules. |
| `compromise` | `report: CID` | A device-signed report identifying the compromised epoch/key; requires a fresh replacement for that key. It creates no account/device ban by itself. |

Selection evidence must establish replacement ancestry and removals. Later valid membership/selection authorization may re-admit an account or per-space removed device; account-wide exact-binding revocation is permanent. The context retains the earlier event while enforcing this distinction.

A compromise report is `{ version: 1, space, epoch: CID, reporter: Binding, declaration: CID, proof: bytes }`, signed over `CBOR(["peep/key-compromise", 1, reportWithoutProof])`. Validate reports from eligible enrolled key holders with supporting authorization evidence; clients may also act on their own knowledge. The epoch reference fixes the affected key commitment. Reports assert suspected disclosure without revealing the key or proving a leak; older-key reports do not repeatedly rotate unaffected successors.

For each grant, retry, or direct delivery, enforce relevant context restrictions for both parties under local trust. Missing bytes needed to identify event scope block validation; missing required authority/ancestry blocks affected grants. Enforce learned revocations/conflicts even if absent from the context. Host order, labels, and another issuer's trust status cannot replace these checks.

Track each pending event with its at-risk key. It is addressed only by an accepted fresh replacement containing that exact event or its inherited reference, with restrictions enforced. A competing epoch omitting it requires a fresh proposal against the accepted epoch; re-observing an addressed event does not. Unauthorized disclosure of the replacement is a new event naming that key.

### Activation

Request `{ version: 1, requestId: RandomId, proposal: EpochMetadata, proposer: Binding, declaration: CID, evidence: CID, proof: bytes }`, signed over `CBOR(["peep/activate-epoch", 1, requestWithoutProof])`. [Evidence](audit.md#evidence) supplies proposer authorization and context/events. The signature binds the proposal/commitment/context and asserts eligibility, enrollment, durable key possession, and generation after processing events.

Before sending, durably persist key bytes, proposal, context, exact request/ID, and local status. `proposal.previous` names the expected active epoch, or `null` at creation. The host authenticates the requesting account, verifies signature/presented declaration binding and eligibility, and rejects malformed commitments, repeated key IDs, incorrect context inheritance, or incorrect/overflowed epoch numbers.

The host atomically checks the expected predecessor, persists the outcome/metadata, and advances the active pointer. Competing requests become stale and must never activate later. Request IDs are scoped to space/proposer account; different bytes under one ID are an error. Durably retain terminal outcomes. Exact retries return the original outcome even after later rotations; fetch current active metadata separately without rolling back known state. If an uncertain request has no terminal result, resend identical bytes; cancellation does not prove nonacceptance.

A stale/rejected proposal authorizes neither writes nor grants. Follow the accepted active epoch; if a trigger remains, generate a new key/ID and proposal against it. Distribute grants only after authenticated acceptance, under [Core's exchange rules](core.md). Generator authority is evaluated at activation; later withdrawal does not invalidate the historical commitment.

Activation requires no grants, including self-grants, or recipient acknowledgments. Missing recipient evidence or offline recipients need not block it; eligible holders may grant later using current authorization. Devices without the key cannot read the epoch. Loss of the sole copy without a recoverable backup loses its content. Host acceptance proves neither durable key storage, delivery, nor independent device verification. Generation/order assertions are not cryptographic proof of randomness, timing, absence of leakage/hidden events, or universal exclusion.

### Writers

Use the latest authenticated active epoch known, including cached state. A trigger initiates rotation without a separate write pause; normal Spaces write authorization and immediate learned-withdrawal enforcement for grants still apply.

After learning a newer active epoch, re-encrypt unpublished records, edits, and blobs with fresh nonces. Pause publication if its key is unavailable; never fall back or roll back. Recheck the known active epoch before each publication operation. In-flight old-key uploads may already be exposed despite cancellation: retain that fact, upload replacements as needed, and do not link old-key objects as though they excluded former holders.

Offline reads and protected local drafts remain available. Old-key content remains readable by former key holders who obtain it, including reused blobs. There is no deadline for all writers to learn the new epoch. [Private state and restore](device-enrollment.md#recovery) preserve known epochs and pending operations.
