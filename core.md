# PEEP: Core

Status: Discussion draft · October 20, 2026

## Scope

PEEP keeps usable content keys and plaintext on user app installations. Servers store and relay ciphertext, declarations, evidence, and encrypted grants. Any currently eligible participant's enrolled device may issue grants for keys it holds, subject to recipient authorization and freshness checks.

Each space uses a symmetric content key per epoch. Grants can include retained historical keys; revocation cannot withdraw keys already disclosed. PEEP provides neither forward secrecy, post-compromise security, nor metadata hiding. Endpoints, their software and updates, authorized recipients, and the space host remain trusted. Malicious space-host behavior is outside scope; other participants' PDSes and repo hosts may be malicious.

[Device Enrollment](device-enrollment.md) defines TOFU or independently verified device bindings and mandatory grant auditing. Prevention of PDS substitution depends on independent verification; detection depends on evidence reaching the affected client. [Protocol Details](protocol.md) defines their encodings and client procedures; integration and independent validation remain in [TODOs](TODOs.md).

## Configuration and authorization

The creator's device generates a cryptographically random 256-bit content key. Authenticated space state identifies the canonical space URI, grant profile, device verification policy, initial epoch, and attachment limit. Clients authenticate the space host and obtain this state from it; discovery, encoding, and authenticated history follow [the host-state contract](protocol.md#trusted-host-state).

The space host's membership policy determines account eligibility; each participant's declaration is a complete snapshot of their selected recipient devices for that space. A space credential permits ciphertext access but does not authenticate a device key. Issuers rely on the authenticated space host for membership decisions; no creator-device signature or separate PEEP membership approval is required. Accepted, unwithdrawn devices can approve additions and sign [account-wide device revocations](device-enrollment.md#account-wide-device-revocation) for their own account. Space administration follows the host's Spaces management rules; [the host adapter](protocol.md#trusted-host-state) supplies authenticated membership/configuration changes. Writer discovery and read credentials alone are not membership evidence; concrete Spaces transport integration remains [TODO-03](TODOs.md#todo-03).

Current members' enrolled devices are eligible for every retained epoch key in the space, including epochs before the account joined or the device enrolled. New grants of historical keys use current membership and enrollment evidence and the same trust, freshness, and audit checks as other grants. Availability still requires an eligible holder of the key.

### Device verification policy

The authenticated space configuration selects one policy for both granting and accepting keys:

- **TOFU permitted (default):** clients may use TOFU or independently verified device bindings.
- **Verified-only:** before granting a device a key or accepting a key from it, the client must have [independently verified](device-enrollment.md#independent-verification) that exact binding or validated a same-account approval path rooted in its own verified binding.

Enforcement is local to each client: the issuer checks the recipient, and the recipient checks the issuer. Missing verification blocks the affected grant or key acceptance. Existing verified bindings remain reusable across spaces. One eligible issuer can supply the key when both clients satisfy their checks; verification by every participant is unnecessary. An issuer's reported recipient trust does not verify the issuer for the recipient. All other authorization and audit requirements apply in both modes.

Apply the policy to new grants and acceptance of current or historical keys, and to authorization rechecks before publication retries or direct delivery. Enabling verified-only does not undo earlier disclosure, rewrite prior trust decisions, or retroactively invalidate accepted keys or otherwise valid archived grants. First acceptance of a key from an archived grant must still satisfy the device-verification policy. Missing or unauthenticated space configuration cannot justify TOFU fallback. Configuration updates follow the trusted host's Spaces management rules; encoding, change propagation, and rollback handling follow [Protocol Details](protocol.md#trusted-host-state).

### Authorization before grant release

Before exposing a grant to any recipient or relay, the issuer must verify:

1. The recipient account's current eligibility to participate.
2. The declaration's exact recipient keys for this space, required signatures, continuity, [bootstrap and incremental snapshot validation](device-enrollment.md#bootstrap-and-incremental-validation), and any [same-account device approval](device-enrollment.md#preventing-pds-substitution) rooted in the issuer's locally accepted [account/device/key bindings](device-enrollment.md#establishing-the-first-trusted-binding). Require the binding to meet the [device verification policy](#device-verification-policy), record whether trust rests on TOFU or independent verification, and retain the approval evidence used.
3. Its own account's current eligibility, its device's authenticated enrollment in this space, and possession of the requested key.
4. Compliance with the [grant freshness policy](device-enrollment.md#grant-freshness): approvals are reusable without automatic expiry, and known authenticated withdrawals must be enforced.
5. No known unresolved [declaration conflict](device-enrollment.md#conflicting-declarations) for either the recipient or issuer account in this space.
6. The requested epoch's [rotation context](protocol.md#rotation-context), including inherited restrictions and evidence needed to apply them to both parties. A later grant cannot disregard the events the epoch was created to address.

Missing or invalid required evidence blocks release. Independent verification is optional where policy permits TOFU; failed signatures or conflicting pins cannot be treated as first use. A space credential alone never authorizes a raw-key response or a grant to an arbitrary supplied key. Authority to approve or withdraw devices follows an accepted same-account device binding, subject to the [approver-withdrawal rules](device-enrollment.md#withdrawing-an-approving-device); device selection or key possession alone is insufficient. Issuance conveys no administrative powers. Known account removals or device withdrawals block new issuance by the affected issuer even if it retains the key. Reusing a verified binding from another space satisfies only the device-identity check; all space-specific authorization and freshness checks still apply.

The signed grant itself is the audit record and must be retained and published with its [space-specific evidence](#grant-evidence) in the issuer's own in-space repo under the [audit requirements](device-enrollment.md#detecting-inconsistent-views). Auditing records the issuance decision; it does not turn a TOFU binding into verified consent. [Later verification](device-enrollment.md#upgrading-a-tofu-binding) must not change a grant's recorded trust decision. An issuer's reported verification status does not transfer verified trust to another issuer or replace a recipient's or auditor's own trust checks.

## Grant creation

An eligible issuer encrypts to the selected recipient encryption key using `peep-hpke-v1`. Recipient keys are separate from authentication and short-lived DPoP keys.

The following encoding requires all shown fields and rejects extra fields. [Protocol Details](protocol.md#evidence-manifests) defines immutable record identities, evidence packaging, and the exact referenced values. `CID` is a CBOR link. All header fields are bound by both HPKE and the issuer signature.

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

Before accepting a grant's key, the recipient validates its fields, types, lengths, profile, space, epoch, and key ID; verifies the referenced declaration and exact recipient binding; checks [membership and enrollment evidence for both parties, including selection approvals](#authorization-before-grant-release) under the applicable trust and freshness policies, using [historical validation](#archived-grant-validation) for archived grants; and verifies the issuer signature and exact issuer binding against the [device verification policy](#device-verification-policy) before opening the grant. A valid signature alone does not satisfy verified-only; the recipient must have its own valid verification basis for that issuer. A CID authenticates bytes, not consent or freshness. The opened plaintext must be exactly 32 bytes and match the authenticated [epoch commitment](#revocation-and-rotation).

HPKE Base mode does not authenticate the sender, so the issuer signature is mandatory. Do not fall back to another suite after verification failure; profile changes require authenticated configuration updates. Interoperability vectors and independent validation remain [TODO-10](TODOs.md#todo-10).

### Grant evidence

Cryptographically bind the published grant to the exact signed declarations and resolved device-key bindings for recipient and issuer, the space membership/configuration and epoch evidence used, and the space-local approval and ancestry records needed for issuance. Include the starting snapshots and incremental history used under the [bootstrap rules](device-enrollment.md#bootstrap-and-incremental-validation). Publish and retain the actual evidence bytes; hashes alone are insufficient if the source repo withholds them. Verification and audit evidence must be readable without the granted key or a substituted recipient private key.

Validation can start from the issuer's retained device bindings and declaration starting points. Their earlier trust basis, including OOB records and approval history from other spaces, remains in [private local trust state](device-enrollment.md#private-trust-history). Reusing a binding must not publish another space's private declarations. Report the trust decision made at issuance; that statement does not establish verified trust for other readers. Readers validate using their own trust and history and may need additional evidence; the bundle does not promise universal verification from scratch, freshness, or a complete prior history.

[Evidence manifests](protocol.md#evidence-manifests) specify bindings, packaging, and validation reporting. Include the epoch's rotation context and relevant trigger evidence; archived grants retain the context under which they were issued. Private trust provenance is not required published evidence; missing signatures, exact keys, or other evidence required within this scope still blocks the grant.

## Grant delivery

The issuer publishes the signed grant together with its exact [space-specific evidence](#grant-evidence) as a record in its own permissioned repo for the space. This is the normal delivery path and produces the [audit record](device-enrollment.md#detecting-inconsistent-views) as part of releasing the grant. Retrieval uses normal Spaces credential and DPoP checks.

Before the first upload, the issuer must durably save the exact signed grant, supporting evidence, and intended record identity. Retries, including after crashes or timeouts, reuse that identity and the same bytes; they must not generate another ciphertext, signature, or audit record. Duplicate publication of that record is one grant. Changing the grant or evidence requires a new issuance under the normal checks.

Before retrying publication or directly delivering a grant, recheck the [authorization requirements](#authorization-before-grant-release) against currently known state for both issuer and recipient. Stop if authorization has been withdrawn; missing required evidence or unresolved declaration conflicts also block release. An earlier successful check or publication acknowledgment does not authorize a later retry or direct delivery. Stopping retries does not remove already published audit records or undo exposure.

Direct delivery may forward the same published record only after the issuer's repo acknowledges publication, including after an uncertain outcome. Acknowledgment does not prove durable availability to other clients; a failed or missing acknowledgment leaves exposure uncertain. [Publication state procedures](protocol.md#activation-and-publication-state) define durable preparation, evidence-first publication, retries, and reconciliation.

Issuers must retain published grants and their exact supporting evidence indefinitely and preserve them during migration. Published evidence includes the starting snapshots and incremental declaration ancestry used for issuance; earlier trust provenance stays in private local state. There is no automatic expiration or pruning on key rotation, device revocation, or membership changes. Continued availability depends on the repo remaining hosted and accessible.

Retrieval and auditing follow normal Spaces access rules. Users who leave or are removed may keep and audit what they already synced; further audit access is not guaranteed, including access to grants addressed to their own account. Indefinite retention does not extend read authorization.

A PDS holding only a credential and encrypted grant cannot unwrap it. Once exposed to a recipient or relay, a grant cannot reliably be withdrawn by deleting its record.

### Archived grant validation

Later account removal, device-selection withdrawal, or account-wide revocation does not by itself invalidate an otherwise valid archived grant for historical reading. The [mandatory grant profile](#mandatory-grant-profile) still applies: validate the exact recipient binding, issuer binding and signature, supporting declaration/approval and membership evidence, and authenticated epoch commitment. Historical decryption uses the retained [space-specific evidence](#grant-evidence) and the reader's own trust/history without requiring either party to remain currently eligible or enrolled. Absence of the issuer's private trust provenance is not itself missing required published evidence. Normal Spaces access rules still govern retrieval. First acceptance of the key also requires the issuer binding to satisfy the [device verification policy](#device-verification-policy); a grant's age or historical validity cannot bypass that check.

Distinguish cryptographic validity from authorization at issuance. If the evidence cannot establish that authorization, report it as uncertain; a claimed timestamp or old declaration cannot prove issuance preceded withdrawal. Uncertainty about historical authorization alone need not block decryption after the required cryptographic, binding, and evidence checks pass. Missing or invalid required evidence does not become acceptable because a grant is archived. [Evidence validation](protocol.md#evidence-manifests) reports cryptographic validity, historical authorization, and audit coverage separately; no trusted timestamp service is required.

An archived grant establishes neither current enrollment nor issuance authority and cannot reset pins, revive withdrawn bindings, or bypass approval/recovery rules. Successful decryption does not prove authorized issuance. New grants, publication retries, and direct delivery still require [current authorization](#authorization-before-grant-release), including for historical keys.

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

[Account-wide device revocations](device-enrollment.md#account-wide-device-revocation) and space-specific membership or device-selection withdrawals affect future grants, not copied keys or plaintext. Future-content exclusion requires a new independent random key in each affected space, grants only to eligible remaining recipients, and writers switching keys. Stale issuers can leak the replacement key; stale writers can expose new content under the old key.

A new epoch is required after an account is removed from the space, a device with access to the current key is removed or revoked, or the current key is known or suspected to be compromised. Device removal includes omission from a replacement declaration. Account-wide revocation requires rotation in each space where the device had access to the current key. Removal/revocation triggers apply when authenticated changes are learned; they do not establish a bounded revocation delay.

Adding accounts or devices alone does not require rotation, consistent with their eligibility for retained historical keys. An update that both adds and removes devices still follows the removal rule.

The trusted space host establishes the authoritative order of key epochs, including concurrent rotation proposals, and publishes the accepted epoch metadata. Clients authenticate that metadata from the host. An eligible participant's enrolled client generates each fresh, independent 256-bit content key locally and publishes grants under the normal [authorization](#authorization-before-grant-release) and [delivery/audit rules](#grant-delivery). Usable content keys remain on clients.

Epoch metadata binds `epoch` (integer 1 through 2^53-1), a unique random `keyId`, and `SHA-256(CBOR(["peep/key", 1, spaceURI, epoch, keyId, keyBytes]))`. Creation uses epoch 1. The commitment checks key agreement; metadata authority comes from the authenticated space host. [Protocol Details](protocol.md#rotation-context) specifies rotation events/context, and [activation procedures](protocol.md#activation-and-publication-state) specify authenticated requests, durable outcomes, numbering, and crash recovery.

Each accepted epoch also binds the exact events it addresses: authenticated membership removals, signed selection removals or account-wide revocations, and compromise reports naming an affected epoch/key. Successors inherit the restrictions. The generator processes those events before generating a fresh key and signs the context with the proposed commitment; it must not reuse a candidate prepared under an earlier authorization context. Every issuer enforces the relevant restrictions before granting that key, including on retries and direct delivery. Missing required evidence blocks affected grants. Later membership or selection authorization may supersede a per-space removal under the normal rules; it cannot undo an account-wide revocation.

Before requesting activation, the eligible generating client must durably save the new key with its space and epoch/key identifiers. Its authenticated request binds the proposed epoch metadata, including the exact key commitment, and the active epoch it expects to replace; creation expects no active epoch. The trusted host atomically checks that expectation and accepts one valid request, publishing the proposed metadata as active. Competing requests based on the replaced epoch are stale and must not be automatically activated afterward. A local proposal alone does not activate an epoch. This applies to the initial epoch and later rotations.

Retrying an already accepted activation request returns its original result without activating another epoch, including after a lost response or later rotations. That result must not roll back a newer epoch already known to the client. A client whose proposal is stale follows the host's accepted active epoch under the writer rule below; its losing proposal cannot authorize writes. If a known rotation trigger remains unsatisfied, it submits a fresh proposal against the accepted active epoch under the normal rotation rules. A competing activation addresses a pending event only if its context incorporates that event and its restrictions are enforced. Otherwise a fresh proposal must include it. A compromise or unauthorized grant of the replacement key creates a new trigger for that key. These requirements do not prove absence of leakage or hidden events, or that every writer has switched.

Activation requires no minimum grant count, including a grant to the generating device, and no recipient receipt or decryption acknowledgments. Issuers publish grants for eligible selected devices they can currently authorize; missing recipient evidence or unavailable recipients need not block activation of the new epoch. Every grant still requires the normal authorization and audit checks, including known withdrawals and declaration-conflict restrictions. Eligible key holders may supply remaining grants later under the then-current authorization state. Activation does not guarantee every device will obtain the key; devices without it cannot read content in that epoch. If the sole holder loses the key before another device receives it or a recoverable backup exists, that epoch's content is unrecoverable. Host acceptance and the commitment do not prove durable storage or another device's key possession.

Writers use the latest authenticated active write epoch they know, including cached state. Learning a rotation trigger initiates rotation without a separate publication pause; writers may continue using that epoch while a replacement is pending. Normal Spaces write authorization still applies, and known withdrawals take effect immediately for grant authorization under the [authorization checks](#authorization-before-grant-release).

After learning a newer authenticated active write epoch, writers must use it for new records, edits, and uploads, re-encrypting unpublished queued content with fresh nonces. If its key is unavailable, they pause publication until they obtain it; they must not fall back to an older epoch. Older metadata must not roll back a known active epoch. Historical content remains readable with retained keys; referencing an old-key blob does not exclude its former holders.

Offline reads and protected local drafts remain possible. Content published before a writer switches remains decryptable with the old key if its holder obtains the ciphertext; there is no deadline for all writers to learn the replacement. [Activation and publication state](protocol.md#activation-and-publication-state) covers epoch catch-up, queued content, and interrupted uploads; [restore](protocol.md#local-state-and-recovery) preserves known epochs and restrictions. Publishing a withdrawal, generating a key, or assigning an epoch alone does not establish recipient key availability or completed exclusion.

### Recovery and succession

A surviving device that the issuer already accepts and has not learned to be withdrawn may approve a replacement for the same account under the [approval rules](device-enrollment.md#preventing-pds-substitution), preserving TOFU/verified provenance. Without such approval, an issuer with an existing pin for that account must explicitly re-verify the exact replacement binding through an independent channel. PDS account recovery cannot replace that pin or justify a fresh TOFU decision. Restoring device keys does not clear known revocations.

Verification remains local: one currently eligible issuer, including another user helping recovery, can independently verify a fresh replacement binding and grant the content keys it holds against a valid replacement declaration. Normal membership, trust, freshness, and audit checks still apply; other issuers retain their own trust decisions. These recovery paths also apply after [device revocation cycles](device-enrollment.md#device-revocation-cycles). Optional removal/re-invitation follows the host's Spaces administration rules and must not reset pins, revocations, declaration history, or conflicts. Retain old grants as audit evidence and rotate affected space keys under the normal rotation rules. Dedicated recovery-key mechanisms are deferred. [Recovery procedures](protocol.md#local-state-and-recovery) specify replacement, notification, protected backups, and state merging; implementation validation remains [TODO-08](TODOs.md#todo-08).

Device authority, content-key recovery, and administration are separate: authorization cannot reconstruct lost keys, and key possession grants no administrative powers. Without a surviving key copy or decryptable backup, historical plaintext is lost. Server backups must remain encrypted so the server cannot decrypt them or reset their protection. Device backup/transfer must also preserve [local trust state](device-enrollment.md#device-backup-and-transfer); keys alone cannot reconstruct lost trust records about other accounts.

## References

- [Device Enrollment](device-enrollment.md) and [TODOs](TODOs.md).
- [Spaces](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data) and [commit authentication](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data#commit-signature).
- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html): HPKE.
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html): Ed25519.
- [Libsodium XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction).

PEEP's configuration, grant, and storage formats are proposed extensions, not standardized Spaces features.
