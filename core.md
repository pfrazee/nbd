# PEEP: Core

## Scope

Each space uses one symmetric content key for its whole life. Usable keys, plaintext, caches, search, previews, and exports stay on clients; servers store ciphertext, device approvals, key requests, evidence, and encrypted grants. PEEP provides no forward secrecy, post-compromise security, cryptographic exclusion of removed participants, or general metadata-hiding guarantee. Endpoints, software/updates, authorized key holders, and the space host are trusted; other PDSes, repo hosts, and storage providers may be malicious.

The [space host](#trusted-host-state) determines account eligibility, configuration, and administration. Credentials and writer discovery do not establish membership or device trust. An account's devices are those its accepted devices have [approved](device-enrollment.md#approvals), minus those the account's PDS has [revoked](device-enrollment.md#device-revocations) by deleting their records, and each is eligible in every space the account is a member of; another client may accept a device only in some spaces when its trust rests on [witnesses](device-enrollment.md#acceptance-in-a-space). No enrollment registry, per-space device selection, creator-device approval, or issuer appointment is required.

Any eligible participant's enrolled device may grant keys it holds. Current members' accepted devices are eligible for the space key, which reads all retained content, including pre-join content. Key possession grants no administrative or device-approval authority. PEEP never [rotates](#no-rotation) a space's key: removal stops new grants, and Spaces access control keeps later content from the removed party once its existing credentials expire; removing a device also requires the user to remove its access at their PDS ([ending access](#ending-access)). A [new space](#replacing-a-space) is only for a credible threat of ongoing compromise that access control cannot prevent. Reading a space requires a recoverable key; [device recovery](device-enrollment.md#recovery) cannot recreate lost secrets.

PEEP does not protect confidentiality against malicious host decisions: the host can admit accounts to receive the space key and retained history, or serve ciphertext to removed participants who still hold the key. PEEP uses [trust on first use](#device-trust) at first contact with an account: a malicious PDS, whether the space host's, a member's, or the user's own, can substitute device keys before a client has pinned that account. A substituted device that any member accepts receives the space key and all retained history. [Auditing](audit.md#direct-sync) detects first-contact substitution after that disclosure; it does not prevent or undo it. After first contact, new devices need a signed [approval](device-enrollment.md#approvals) from an accepted device of the same account. Devices are revoked by deleting their records from the account's repo, never by other devices. Whoever can do that, including the PDS or anyone with the account password, can revoke every device and [re-enroll](device-enrollment.md#re-enrollment) one, but only after a hold surfaced to members and the account's own installations. That hold stops takeover of an account at an honest PDS if the user notices in time; against a malicious PDS it gives only detection.

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
| `BLOCKED` | Known authorization state forbids the operation, including revocation or an unaccepted binding. |

Only `OK` permits the requested operation. Clients MUST NOT treat missing evidence as an empty state or a successful check. They MUST preserve independently authenticated revocations and observations even if another check fails; unvalidated input MUST NOT acquire authority through partial processing. Before releasing a grant or committing a new key acceptance, clients MUST repeat checks affected by newly learned state. These results do not assert global freshness or replace the [archive audit assessments](audit.md#archived-grants).

### Encoding and identifiers

`CBOR(x)` means normalized ATProto CBOR, including byte strings and CID links. Decoders MUST apply finite limits and reject duplicate/unknown fields, non-normalized encodings, trailing bytes, wrong types, unknown versions, invalid key/signature encodings, and integers outside 0 through 2^53−1. All fields shown are REQUIRED; `null` is permitted only where shown. Implementations MUST NOT hash JSON or a displayed CID string. Sets are arrays sorted by unsigned lexicographic order of their elements' normalized CBOR bytes, with duplicates rejected; other arrays retain their specified order.

`Ref(x)` is a CIDv1 with codec `dag-cbor` (`0x71`) and SHA-256 multihash of `CBOR(x)`. Resolvers MUST obtain exactly those bytes and check the hash before interpreting a reference. This commits to content, not authority, freshness, or availability. `Digest` is a 32-byte SHA-256 result. `RandomId` is 16 independently random bytes encoded as 32 lowercase hexadecimal characters. Implementations MUST use exact DIDs for identities, never mutable handles. Space identifiers use the exact canonical URI obtained from the authenticated host; implementations MUST NOT normalize identifiers differently for signing and verification.

### Records

Except for [public device records](device-enrollment.md#bindings-and-publication), protocol values are immutable, wrapped as `{ $type: collection, value }`. The record key is lowercase hexadecimal SHA-256 of `CBOR(value)`; references identify the inner value. Different bytes at an existing identity are an error.

| Collection suffix under `com.example.peep` | Location |
| --- | --- |
| `approval` | Account's public repo; counts only when [proven present](device-enrollment.md#repo-observations) there. |
| `grant`, `evidence` | Issuer's space repo. |
| `keyRequest` | Requesting account's space repo. |

All use the [retention/access rules](audit.md#retention-and-access).

### Trusted host state

Clients MUST authenticate the host through the space authority's DID and deployed [Spaces protocol](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data). Clients MUST obtain membership decisions from its management implementation; `listRepos` enumerates writers, not membership. Existing management authority controls configuration and membership updates. Applications creating a PEEP space MUST configure a read policy under which the space authority issues credentials only to authenticated users it considers members, which in Spaces means requiring a delegation token from the user's PDS. Under a public read policy anyone can fetch ciphertext, so removal would have no effect on former key holders. A host that later relaxes the read policy is a malicious host decision.

Retain these authenticated values by content reference:

| Value | Required fields |
| --- | --- |
| Configuration | `version: 1`, `kind: "configuration"`, `space`, positive monotonic `revision`, `grantProfile: "peep-hpke-v1"`, `keyId: RandomId`, `commitment: Digest` ([space key](#key-generation)), positive `maxEncryptedBlobBytes` (default 16,777,216). `keyId` and `commitment` are fixed at creation. |
| Membership decision | `version: 1`, `kind: "membership"`, `space`, `account`, positive per-account monotonic `revision`, `eligible: boolean`. Eligibility is the host's explicit PEEP participation decision under its management rules. |

The host MUST expose authenticated reads of current configuration, per-account membership, and historical values by CID. The host MUST preserve exact history and monotonic revisions through restart/migration. Unknown history is unavailable, not reconstructed as current state. Defaults apply only to authenticated creation. Clients MUST retain their highest known revisions: lower revisions cannot replace them, and equal revisions with different bytes are errors. A later eligible membership decision may re-admit an account without resetting device trust/history.

The host MUST reject configuration updates that change `keyId` or `commitment`. Clients MUST retain the first authenticated values observed for each exact space URI and reject a configuration with a different value for either as `INVALID`, retaining the last valid configuration. Clients MUST surface such a configuration as a host integrity alarm, not as a key change. Changing the key requires a new space.

Clients MUST authenticate values by direct host retrieval or a retained local observation of that retrieval. Published copies supply bytes, not independent host authentication; readers lacking their own basis must resolve the reference against the host. Failure leaves required evidence unavailable. Clients MUST keep the authentication basis private. A host read supplies neither trusted issuance time nor proof against later changes.

The host MUST expose change notifications and resumable reconciliation for membership and configuration. Notifications are fetch hints; cached validated state follows [freshness rules](device-enrollment.md#freshness). Unsupported deployments MUST report the missing capabilities.

When learned, clients MUST visibly surface authenticated member additions, removals, and readmissions, identifying the affected account. A removal notice MUST NOT claim cryptographic exclusion ([no rotation](#no-rotation)). Applications MUST make discoverable that members can read the space's retained history, for example in space information, and SHOULD explain it when admitting a member. Notices add no approval gate and need not precede grants; learning about a change has no deadline. Device additions and removals approved by the affected account's own installations need no notice to other members; applications MAY show them in device lists. The account's own installations [notify its user](audit.md#direct-sync) of them.

## Device trust

Every exchange uses [local trust](device-enrollment.md#local-trust): trust on first use at first contact with an account, and signed approvals for its later devices. The issuer checks the recipient; the recipient checks the issuer. One issuer suffices when both clients pass their local checks. Binding trust is reusable across spaces; trust reported in a grant is not transferable. These checks cover current exchanges, publication retries, direct delivery, and first acceptance from archived grants. Defense against first-contact substitution by a malicious PDS is detection through [auditing](audit.md#direct-sync).

Spaces have no verification policy. Verification protects a shared key only when every exchange in a space requires it: a substituted device that any member accepts can read everything, so one pair of members verifying each other would protect nothing. [Verified-only spaces](TODOs.md#deferred-extensions) are a deferred extension. Configuration decoding rejects unknown fields, so current clients will reject a future configuration carrying a verification policy rather than treat that space as TOFU.

## Key grants

### Grant authorization

`AuthorizeExchange(space, issuer, recipient, role, state)` checks a current exchange. `role` identifies the local installation as issuer or recipient; the other binding is the device it verifies. Implementations MUST perform G1–G5, returning the [specified failure result](#conformance-and-validation-results) at a failed check:

1. **G1 — Host evidence.** Resolve and authenticate configuration and both accounts' membership decisions under [host rules](#trusted-host-state). Check exact space, references, profile, and key ID.
2. **G2 — Local state and trust.** Incorporate authenticated observations using [approval validation](device-enrollment.md#approval-validation), [repo observations](device-enrollment.md#repo-observations), and [freshness](device-enrollment.md#freshness). Use the latest locally known configuration, membership, approvals, and revocations. Then apply [local trust](device-enrollment.md#local-trust) to the other binding, accepting it on [first use](device-enrollment.md#first-use-anchors), by approval, or by [re-enrollment](device-enrollment.md#re-enrollment) once its hold has passed. A binding of an already pinned account without an approval path, a binding unreachable from the account's anchors, a re-enrollment candidate still in its hold, or missing required approval evidence returns `INCOMPLETE`.
3. **G3 — Eligibility.** Require both accounts to be eligible and both exact bindings to be accepted and unrevoked under [local trust](device-enrollment.md#local-trust), and accepted in this space under [acceptance in a space](device-enrollment.md#acceptance-in-a-space). Require the local installation to match its stated role. A currently effective account removal returns `BLOCKED`, even if the device holds a key; later valid readmission may restore eligibility. A device revocation remains permanent.
4. **G4 — Trust source.** Require that acceptance rest on this client's own local trust state from G2. Another account's reported trust, including a grant's recorded trust decision, is insufficient; anchors are evidence for first use, not trust transferred from their issuers.
5. **G5 — Decision.** Return `OK` with the exact bindings and approval paths, host decisions, and local trust decision used. Persist that decision with any issuance or key acceptance; it MUST NOT reset pins, revocations, or conflicts.

An issuer MUST additionally hold exactly 32 key bytes matching the configuration's commitment before constructing a grant. It MUST publish the signed grant and its [evidence](audit.md#evidence) in its own space repo through the [publication state machine](audit.md#publication). Each release attempt repeats authorization; credentials never authorize raw-key responses or arbitrary recipient keys. Reading an existing grant uses [grant acceptance](#grant-acceptance), including its archive mode.

### Distribution scheduling

Distribution is request-driven. A device [requests](#key-requests) a space's key when it first opens the space, and eligible holders answer when online and able to authorize delivery, after randomized backoff when the request names no issuer. A holder MAY also grant without a request to devices it knows will use the space, such as installations of the same application that paired with it. After creation, the creator SHOULD do so promptly for its own account's such installations, so the key does not rest on one device. Holders SHOULD NOT grant unrequested keys to other devices: requesting keeps applications from holding keys for spaces they do not use. For a given recipient binding, reuse prepared grants under the [publication rules](audit.md#publication); observed grants may defer duplicate work but never establish recipient acceptance or complete coverage. The creator has no exclusive authority or mandatory delivery deadline.

Delivery requires a running holder, so clients SHOULD process newly observed [key requests](#key-requests) promptly, including in the background where the platform permits. Applications SHOULD notify eligible holders' devices of new requests, for example through push notifications that wake background processing; notifications are fetch hints and carry no authorization. When no grant arrives within an application-defined window, the requester's application MAY ask other members to open the space. Prompts MUST NOT include key material or establish trust. An always-on device, such as a desktop or a hosted agent, improves availability as an ordinary device; it is a trusted endpoint holding keys, and hosting it trusts its operator.

Recipients MAY [request](#key-requests) another eligible issuer even when a grant exists: its issuer may not be accepted under the recipient's local trust, or its evidence/ciphertext may be unusable. Delays and partial views can still cause duplicates or gaps.

### Key requests

Applications MUST support unencrypted `com.example.peep.keyRequest` records in the requesting account's space repo, under normal Spaces access controls. Publish and discover them through ordinary repo writes and [direct sync](audit.md#direct-sync), including notification catch-up and periodic reconciliation, without requiring any content key. Issuers answer through normal [grant publication](audit.md#publication) in their own space repos; no separate delivery service is required.

A request is `{ version: 1, space, recipient: Binding, issuer: DeviceIdentity | null, proof: bytes }`. `recipient` is the requester's [exact binding](device-enrollment.md#bindings-and-publication). `issuer` names a preferred issuer device or is `null` for any eligible holder. The recipient device signs `CBOR(["peep/key-request", 1, requestWithoutProof])` using [Ed25519](#mandatory-grant-profile). Apply the [immutable record rules](#records); retries MUST reuse exact signed bytes and record identity. A different preferred issuer requires a new request.

Before acting, issuers MUST validate encoding and signature, match `space` and `recipient.account` to the authenticated repo location, and independently resolve the configuration, approvals, and all [grant authorization](#grant-authorization) checks. The signature proves possession of the stated signing key, not identity verification or authorization. Requests MUST NOT establish device trust, bypass local trust checks, authorize raw-key responses, or appear in evidence manifests. A preferred issuer is only a scheduling hint and grants no exclusive authority.

Clients MUST bound pending requests, retries, and per-account processing, deduplicate by `(space, exact recipient binding, issuer)`, and use randomized retry backoff. Pending requests SHOULD be reconsidered when relevant authorization or key availability changes. Requesters SHOULD delete requests after accepting the needed key or abandoning the request; they MAY remove obsolete requests to bound storage. Requests have no indefinite retention requirement. Deletion or a published response proves neither key receipt nor non-disclosure and MUST NOT delete grants or their evidence. Withholding, denied access, or offline holders can still prevent delivery; if no holder remains, the key is [lost](#key-loss).

### Grant format

Use the [shared encoding and storage rules](#protocol-conventions). All shown fields are required; `CID` is a CBOR link. The authorization references identify the exact evidence used, and the full header is bound by HPKE and the signature.

```typescript
type DeviceIdentity = { account: string; deviceId: string };

type SpaceKeyGrant = {
  version: 1;
  space: string;             // Exact canonical space URI from trusted configuration.
  keyId: string;             // The configuration's key ID.
  recipient: DeviceIdentity;
  recipientKeyId: string;    // Fingerprint of the exact recipient X25519 public key.
  authorization: {
    recipientBinding: CID;  // Ref of the exact recipient Binding.
    issuerBinding: CID;     // Ref of the exact issuer Binding.
    configuration: CID;
    recipientMembership: CID;
    issuerMembership: CID;
    evidence: CID;          // Manifest of exact retained evidence values.
  };
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
2. **A2 — Evidence and signature.** Resolve the [required evidence](audit.md#evidence), authenticate host values, and validate both bindings, their approval evidence, and the issuer signature as issuance evidence. Match both identities and key fingerprints to the referenced bindings; the recipient binding MUST equal `localBinding` in account, device ID, and both public keys. Missing required evidence returns `INCOMPLETE`; invalid evidence or a binding mismatch returns `INVALID`. Embedded repo commits are audit evidence verified under [historical rules](device-enrollment.md#repo-observations): one signed by a since-rotated key that cannot be established is reported as incomplete audit evidence and does not block acceptance. Authorization is checked separately in A4.
3. **A3 — Key.** Match space and key ID to the authenticated configuration.
4. **A4 — Authorization.** In both modes, check the [recorded authorization basis](audit.md#archived-grants). Current mode MUST additionally run `AuthorizeExchange` with role `recipient`; retain that decision separately from the issuer's recorded basis. Archive mode does not require current enrollment; later membership removal or revocation alone MUST NOT invalidate historical reading. A client MUST NOT relabel a failed current operation as an authorized current exchange by switching modes.
5. **A5 — Issuer trust.** Before first key acceptance in either mode, require the issuer binding to be accepted under [local trust](device-enrollment.md#local-trust). Archive reading MAY use retained acceptance of a formerly authorized binding; this grants it no current authority. Valid signatures and decryption cannot substitute for acceptance.
6. **A6 — Open.** Use the mandatory HPKE profile and exact header-derived `info`/AAD. Require successful authentication and exactly 32 plaintext bytes matching the configuration's commitment; otherwise return `INVALID` and discard the candidate key.
7. **A7 — Commit.** Recheck any authorization affected by newly learned state. Durably retain the key, exact grant/evidence, local trust decision, and audit assessments before exposing the key to content operations. Return `OK`; archive acceptance MUST NOT restore authority.

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

Format 1 uses XChaCha20-Poly1305 with the 256-bit key identified by `keyId`. Writers MUST generate a fresh cryptographically random 24-byte nonce for every encryption, including edits and re-encryption. Clients MUST NOT reuse a nonce with the same key across records or blobs. Ciphertext includes the appended 16-byte authentication tag and is exactly 16 bytes longer than the encoded [payload frame](#payload-framing-and-padding).

Associated-data arrays below use normalized CBOR: labels are literal strings, `1` is an integer, and identifiers are strings. Use the exact authenticated `spaceURI` and its corresponding `keyId`. Distinct record/blob labels separate their cryptographic contexts.

Only the shown envelope fields are permitted; `nonce` and `ciphertext` are CBOR byte strings. Receivers MUST reject an incorrect `$type`, duplicate or unexpected fields, unknown formats, invalid nonce lengths, ciphertext shorter than 19 bytes, unavailable keys, and failed authentication. Receivers MUST authenticate the complete ciphertext in the expected context before exposing plaintext.

### Payload framing and padding

Format 1 writers MUST encrypt `CBOR([payload, padding])`, exactly two byte strings. `payload` holds encoded record content or original file bytes; `padding` contains only zero bytes and may be empty. Even unpadded content uses this frame. Payload length is encoded inside encryption; no outer original-length or padding field is added. Grants retain their separate plaintext format.

After whole-ciphertext authentication, receivers MUST decode the frame with bounded lengths/work and reject non-normalized CBOR, wrong element counts/types, nonzero padding, or trailing bytes. Decoders MUST check declared lengths against available bytes and resource limits before allocation. Receivers MUST discard padding and process only `payload`; they MUST NOT fall back to unframed content.

Writers SHOULD use a shared default: choose the smallest attainable power-of-two ciphertext length of at least 256 bytes (256, 512, 1,024, ...), including the frame and 16-byte tag. For payload length `n` and zero-padding length `p`, that length is `L(n, p) = 1 + h(n) + n + h(p) + p + 16`, where the CBOR byte-string header length `h(x)` is 1 for `x < 24`, 2 for `x < 256`, 3 for `x < 65,536`, 5 for `x < 2^32`, and 9 otherwise. Choose nonnegative `p` satisfying the bucket exactly; skip buckets made unattainable by header-length changes.

The chosen bucket MUST fit every applicable ciphertext, record, transport, and whole-blob limit, counting outer encoding overhead where applicable. If no bucket fits, the default uses empty padding; if that also exceeds a limit, the writer MUST reject the write. Compute lengths with bounded, overflow-safe arithmetic before allocating padding. Other padding choices remain permitted; readers MUST accept empty, nonempty, and non-default sizes within their resource limits.

Shared buckets reduce padding-specific application fingerprints but can roughly double larger payloads; small payloads incur the 256-byte minimum. Padding does not hide visible collections, counts, timing, blob relationships, or padded sizes. No general metadata-hiding guarantee is added.

### Encrypted records

`payload` is the normalized ATProto CBOR encoding of one map containing the application's content object and `$type`. Each record lexicon declares its outer collection/type and inner schema. After authentication and frame validation, receivers MUST decode `payload` and reject non-normalized encoding, duplicate keys, trailing bytes, a non-map root, or an incorrect content `$type`; receivers MUST validate the inner schema before rendering or indexing.

The outer `$type` MUST match the collection. Application semantics belong inside the encrypted content; additional outer fields need separate authentication before influencing trusted presentation. Applications MUST declare finite ciphertext-size, nesting-depth, and collection-size limits and enforce them before allocation and during bounded decoding, including for authenticated content.

```typescript
const content = { $type: "app.example.message#content", text: "Hello!" };
const plaintext = CBOR([CBOR(content), padding]); // Zero bytes chosen under the padding rules.
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

PEEP introduces no independent message-authorship proofs. A content-key holder colluding with the claimed author's PDS can forge messages, but can also export the content key directly to that PDS. Such collusion is outside PEEP's confidentiality guarantees because authorized key holders are trusted. Enrollment and grant signatures authenticate protocol statements, not message authorship.

### Encrypted blobs

Blob writers MUST frame the original file bytes as `payload`, then encrypt the frame as one envelope with `blobs: []`. Upload its normalized CBOR encoding as `application/octet-stream`. Blob associated data is:

```text
["peep/blob", 1, spaceURI, keyId]
```

Omitting the blob CID and containing record location permits reuse within the same space. Following the [ATProto blob format](https://atproto.com/specs/blob), the reference uses CIDv1 with the raw codec and SHA-256 of the entire uploaded envelope; `size` counts all those envelope bytes, including framing, padding, and the authentication tag. Store the original MIME type, filename, and other metadata in the encrypted record. Record authentication binds the resulting reference. A reused blob retains its original `keyId`.

Blob readers MUST verify the referenced CID and size before decoding, then apply envelope validation, authentication, and frame validation. Blob readers MUST reject malformed or non-normalized CBOR and trailing bytes, and return only the recovered `payload` as the original file.

The authenticated configuration sets a positive, finite `maxEncryptedBlobBytes`, defaulting to 16 MiB (16,777,216 bytes), for the complete envelope. Configuration updates may change it; enforce any smaller transport limit. Clients MUST check size before download/allocation and cap actual bytes received regardless of the server's reported size.

Blob readers MUST NOT release plaintext before whole-file authentication. Any temporary plaintext produced internally MUST remain inaccessible and be discarded on failure. Format 1 does not support independently authenticated chunks or range decryption; streaming requires a separate format under [TODO-13](TODOs.md#todo-13).

## Space key lifecycle

### Key generation

The creator generates the space key: a fresh independent random 256-bit key and a `RandomId` key ID. Its commitment is `SHA-256(CBOR(["peep/key", 1, spaceURI, keyId, keyBytes]))`. The creator MUST durably store the key before creating the space and supplies `keyId` and `commitment` in the creating [configuration](#trusted-host-state). The commitment checks agreement; it does not give the host usable key material. The host stores them unchanged for the life of the space.

Writers encrypt all content under the space key. A writer without the key cannot publish content and SHOULD [request a grant](#key-requests). Offline reads and protected local drafts remain available; pending publications MUST be retained until the key is obtained. [Private state and restore](device-enrollment.md#recovery) preserve keys and pending operations.

### No rotation

PEEP never replaces a space's key. Removing an account or [revoking a device](device-enrollment.md#device-revocations) blocks new grants to and from that party under [grant authorization](#grant-authorization), but the party keeps any key and plaintext it already holds. Afterwards, keeping later content from it depends on Spaces access control denying it ciphertext, which takes the [steps below](#ending-access): a malicious or breached host, a colluding PDS storing members' records, or a member who passes on ciphertext can expose that content to it. A known or suspected key compromise has the same effect for whoever obtained the key.

Applications MUST NOT describe a removal, revocation, or suspected compromise as excluding the affected party from later content. Removal and revocation, with the [access steps](#ending-access) they require, are nonetheless complete responses; [replacing the space](#replacing-a-space) is reserved for a credible threat of ongoing compromise that access control cannot prevent.

### Ending access

PEEP controls key grants; Spaces controls who can fetch ciphertext. Space credentials are short-lived, and the space authority issues them only to members whose PDS supplies a delegation token for the requesting application, under the [read policy](#trusted-host-state) PEEP requires. Credentials already issued stay valid until they expire: 10 minutes by default and 60 at most under the current Spaces proposal, sooner if the authority sends `notifyCredentialRevoked` to repo hosts.

- **Removing a member.** The authority stops issuing credentials to that account, so its access ends within one credential lifetime.
- **Removing a device.** This takes two separate steps: deleting the device record, through an authorization that requires the user to sign in at their PDS, [revokes](device-enrollment.md#device-revocations) the binding, and ending the device's session at the PDS ends its access. Revocation is invisible to the space authority, which issues credentials to accounts, not devices. A revoked device that still holds an OAuth session with the account's PDS keeps obtaining delegation tokens and credentials indefinitely, and can still publish approvals. The user MUST end the device's session at their PDS; its access then ends within one credential lifetime. PEEP does not map device bindings to PDS sessions, and no PDS interface combines the two steps. Applications MUST tell the user to end the session whenever they remove a device, and MAY offer to take it for them where the PDS allows ([TODO-16](TODOs.md#todo-16)). If the device, or whoever holds it, knows the account's login, it can sign in again, so applications SHOULD also advise changing the password when a device is lost or unrecognized.
- **Shared application backends.** An application can obtain credentials through any of its users' sessions, so removing one user's session does not stop a backend that serves other members of the space. A backend that passes ciphertext to a removed party is colluding with it, which is outside PEEP's guarantees.

Applications MUST NOT describe removal as immediately ending a party's ability to read. New grants stop when the removal is learned; ciphertext access ends only as described here.

### Replacing a space

A new space has a fresh key, a new URI, and its own membership and grants. Device trust and approvals are account-wide under the [binding rules](device-enrollment.md#local-trust), so members' devices with existing pins can receive grants as soon as they request them. Content does not carry over: members MAY republish content they can read in the new space, encrypted under its key as their own records. Republished records do not retain their original authorship. The old space remains readable to holders of its key under its own access rules.

Replacement is not a response to removal. Removing a member, removing a lost device, or revoking a device is complete once access ends as described in [ending access](#ending-access). Replacement is for when users believe there is a credible threat of ongoing compromise that the host and PDSes cannot prevent, such as a breached or malicious host or PDS, or a leaked space key paired with a path to ciphertext outside access control. Applications MUST NOT make replacement the default in any flow and SHOULD NOT prompt it in removal or lost-device flows. They MAY offer it from space settings and alongside alarms that indicate such compromise, such as [host integrity alarms](#trusted-host-state) and [unauthorized own-account bindings](audit.md#direct-sync).

### Key loss

A space's key is lost when no device holds a copy and no decryptable backup remains. Its content is then unreadable, and no further content can be published in it. Members recover by creating a replacement space; [device recovery](device-enrollment.md#recovery) cannot recreate lost keys.
