# PEEP: Core

Status: Discussion draft · October 20, 2026

## Scope

PEEP keeps usable content keys and plaintext on user app installations. Servers store and relay ciphertext, declarations, evidence, and encrypted grants. Only enrolled devices authorized to issue a key they hold may create grants.

Each space uses a symmetric content key per epoch. Grants can include retained historical keys; revocation cannot withdraw keys already disclosed. PEEP provides neither forward secrecy, post-compromise security, nor metadata hiding. Endpoints, their software and updates, and authorized recipients remain trusted.

[Device Enrollment](device-enrollment.md) defines TOFU or independently verified recipient bindings and mandatory grant auditing. Prevention of PDS substitution depends on independent verification; detection depends on evidence reaching the affected client. Approval, bootstrap, and audit formats remain unresolved.

## Configuration and authorization

The creator's device generates a cryptographically random 256-bit content key. The space configuration identifies the canonical space URI, grant profile, initial epoch, and attachment limit. Joiners' authentication of this configuration remains [TODO-02](TODOs.md#todo-02).

Standard Spaces membership determines account eligibility; each participant's declaration selects their recipient devices. A space credential permits ciphertext access but does not authenticate a device key. Membership must be trustworthy: device approvals cannot compensate for a PDS able to admit arbitrary accounts. Membership authentication and approval/issuer roles remain [TODO-03](TODOs.md#todo-03).

### Authorization before grant release

Before exposing a grant to any recipient or relay, the issuer must verify:

1. The account's eligibility to participate.
2. The declaration's exact recipient keys for this space, required signatures, and continuity against the issuer's locally accepted account-to-key binding, recording whether that binding is TOFU or independently verified.
3. Its own authority to issue the requested current or historical key.
4. Compliance with the [grant freshness policy](device-enrollment.md#grant-freshness), including known withdrawals.

Missing or invalid required evidence blocks release. Independent verification is optional where policy permits TOFU; failed signatures or conflicting pins cannot be treated as first use. A space credential alone never authorizes a raw-key response or a grant to an arbitrary supplied key. Device selection does not implicitly confer approval, issuance, or administrative powers.

The signed grant itself is the audit record and must be retained and published with its supporting evidence in the issuer's own in-space repo under the [audit requirements](device-enrollment.md#detecting-inconsistent-views). Auditing records the issuance decision; it does not turn a TOFU binding into verified consent. An issuer's reported verification status does not transfer verified trust to another issuer or replace a recipient's or auditor's own trust checks.

## Grant creation

An eligible issuer encrypts to the selected recipient encryption key using `peep-hpke-v1`. Recipient keys are separate from authentication and short-lived DPoP keys.

The following draft encoding requires all shown fields and rejects extra fields. Its declaration/evidence binding and packaging with supporting evidence in the published record remain provisional under [TODO-05](TODOs.md#todo-05). `CID` is a CBOR link.

```typescript
type DeviceIdentity = { account: string; deviceId: string };

type SpaceKeyGrant = {
  space: string;             // Exact canonical space URI from trusted configuration.
  epoch: number;             // Positive integer identifying the content-key epoch.
  keyId: string;             // 16 random bytes encoded as 32 lowercase hex characters.
  recipient: DeviceIdentity;
  recipientKeyId: string;    // Fingerprint of the exact recipient X25519 public key.
  enrollmentReference: {
    declaration: CID;        // Exact declaration selecting this recipient's key binding.
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

`peep-hpke-v1` uses RFC 9180 Base mode (`0x00`), DHKEM(X25519, HKDF-SHA256) (`0x0020`), HKDF-SHA256 (`0x0001`), and ChaCha20Poly1305 (`0x0003`). Content envelopes separately use XChaCha20-Poly1305. Grant signatures use RFC 8032 pure Ed25519 without an additional prehash. Generate signing and encryption keypairs independently; do not convert one into the other.

X25519 public keys and encapsulations use RFC 9180's 32-byte encodings. Ed25519 public keys use RFC 8032's 32-byte encoding; signatures use its 64-byte `R || S` encoding. Require canonical encodings, reject malformed points and noncanonical signatures, and apply HPKE's KEM input and all-zero shared-secret checks.

A public-key fingerprint is lowercase hexadecimal SHA-256 of `CBOR(["peep/public-key", 1, algorithm, publicKeyBytes])`, where `algorithm` is exactly `X25519` or `Ed25519`. Mutable discovery must not redirect that fingerprint to another key.

All CBOR uses the normalized [ATProto data model](https://atproto.com/specs/data-model), including byte strings and CID links. Let `H` be the grant map without `encapsulation`, `ciphertext`, and `proof`. Seal the raw 32-byte content key in a fresh single-shot HPKE context:

```text
info = CBOR(["peep/grant-info", 1, H])
aad  = CBOR(["peep/grant-aad", 1, H])
(encapsulation, ciphertext) = SealBase(recipientPublicKey, info, aad, spaceKey)
proof = Ed25519.Sign(issuerPrivateKey,
  CBOR(["peep/grant-signature", 1, grantWithoutProof]))
```

Before opening a grant, the recipient validates its fields, types, lengths, profile, space, epoch, and key ID; verifies the referenced declaration and exact recipient binding; checks [membership, selection approval, and issuer-authority evidence](#authorization-before-grant-release) under the applicable trust and freshness policies; and verifies the issuer signature. A CID authenticates bytes, not consent or freshness. The opened plaintext must be exactly 32 bytes and match the authenticated [epoch commitment](#revocation-and-rotation).

HPKE Base mode does not authenticate the sender, so the issuer signature is mandatory. Do not fall back to another suite after verification failure; profile changes require authenticated configuration updates. Interoperability vectors and independent validation remain [TODO-10](TODOs.md#todo-10).

## Grant delivery

The issuer publishes the signed grant together with its exact supporting evidence as a record in its own permissioned repo for the space. This is the normal delivery path and produces the [audit record](device-enrollment.md#detecting-inconsistent-views) as part of releasing the grant. Retrieval uses normal Spaces credential and DPoP checks.

Direct delivery may forward the same published record after the issuer's repo acknowledges publication. Acknowledgment does not prove durable availability to other clients; a failed or missing acknowledgment does not prove the grant was never exposed. Retry and crash handling remain [TODO-09](TODOs.md#todo-09).

The supporting evidence must be accessible to authorized readers before opening the grant and for auditing, without the content key being granted or the possibly substituted recipient private key. Record packaging remains [TODO-05](TODOs.md#todo-05).

Issuers must retain published grants and their exact supporting evidence indefinitely, preserving them during migration. There is no automatic expiration or pruning on key rotation, device revocation, or membership changes. Continued availability depends on the repo remaining hosted and accessible.

Retrieval and auditing follow normal Spaces access rules. Users who leave or are removed may keep and audit what they already synced; further audit access is not guaranteed, including access to grants addressed to their own account. Indefinite retention does not extend read authorization.

A PDS holding only a credential and encrypted grant cannot unwrap it. Once exposed to a recipient or relay, a grant cannot reliably be withdrawn by deleting its record. Archived grants do not establish current enrollment.

Acceptance rules for archived grants remain [TODO-05](TODOs.md#todo-05), separate from checks before issuing a new grant.

## Encryption envelope

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

## Encrypted records

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

## Encrypted blobs

Encrypt the original file bytes as one envelope with `blobs: []`. Upload its normalized CBOR encoding as `application/octet-stream`. Blob associated data is:

```text
["peep/blob", 1, spaceURI, keyId]
```

Omitting the blob CID and containing record location permits reuse within the same space. Following the [ATProto blob format](https://atproto.com/specs/blob), the reference uses CIDv1 with the raw codec and SHA-256 of the entire uploaded envelope; `size` counts those envelope bytes. Store the original MIME type, filename, and other metadata in the encrypted record. Record authentication binds the resulting reference. A reused blob retains its original `keyId`.

Verify the referenced CID and size before decoding, then apply envelope validation and authentication. Reject malformed or non-normalized CBOR and trailing bytes.

The authenticated configuration sets a positive, finite `maxEncryptedBlobBytes`, defaulting to 16 MiB (16,777,216 bytes), for the complete envelope. Configuration updates may change it; enforce any smaller transport limit. Check size before download/allocation and cap actual bytes received regardless of the server's reported size.

Release no plaintext before whole-file authentication. Any temporary plaintext produced internally must remain inaccessible and be discarded on failure. Format 1 does not support independently authenticated chunks or range decryption; streaming requires a separate format under [TODO-13](TODOs.md#todo-13).

## Lifecycle and recovery

### Revocation and rotation

[Enrollment withdrawals](device-enrollment.md#grant-freshness) affect future grants, not copied keys or plaintext. Future-content exclusion requires a new independent random key, grants only to eligible remaining recipients, and writers switching keys. Stale issuers can leak the replacement key; stale writers can expose new content under the old key.

Epoch metadata binds `epoch` (integer 1 through 2^53-1), a unique random `keyId`, and `SHA-256(CBOR(["peep/key", 1, spaceURI, epoch, keyId, keyBytes]))`. Creation uses epoch 1. The commitment checks key agreement but does not authenticate the metadata. Rotation authority, metadata authentication, concurrent rotations, grant coverage, and completion remain [TODO-07](TODOs.md#todo-07).

After learning an authenticated replacement write epoch, writers must use it for new records, edits, and uploads, re-encrypting unpublished queued content with fresh nonces. Historical content remains readable with retained keys; referencing an old-key blob does not exclude its former holders.

Offline reads and protected local drafts remain possible. Publication while stale, reconnect/restore, and in-progress uploads remain part of TODO-07. Publishing a withdrawal or generating a key alone does not establish completed exclusion.

### Recovery and succession

Recovery must establish a replacement binding under the approval/recovery policy before new grants, preserving its trust status. PDS account recovery alone cannot establish verified trust or silently reset an existing pin. Server backups must remain encrypted so the server cannot decrypt them or reset their protection.

Device authority, content-key recovery, and administration are separate: authorization cannot reconstruct lost keys, and key possession grants no administrative powers. Without a surviving key copy or decryptable backup, historical plaintext is lost. Recovery and succession policy remain [TODO-08](TODOs.md#todo-08).

## References

- [Device Enrollment](device-enrollment.md) and [TODOs](TODOs.md).
- [Spaces](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data) and [commit authentication](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data#commit-signature).
- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html): HPKE.
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html): Ed25519.
- [Libsodium XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction).

PEEP's configuration, grant, and storage formats are proposed extensions, not standardized Spaces features.
