# PEEP: Device Enrollment

Status: Discussion draft

1. Users publish device public keys publicly.
2. Standard Spaces membership determines participating accounts.
3. Each participant publishes an in-space declaration selecting their exact device keys.
4. Key issuers use those declarations to select grant recipients and publish device-signed issuance evidence for auditing.

Declarations are the enrollment state. This model requires neither a separate enrollment registry service, a global chain, nor creator approval for every device addition. Independent key verification is optional; signature validation, exact-key matching, continuity checks, and grant auditing are required. Approval, bootstrap, and audit formats remain open.

## Device keys

### Publication

Each app installation generates Ed25519 signing and X25519 recipient-encryption keys under [Core's profile](core.md#mandatory-grant-profile), keeps the private keys locally, and publishes:

```typescript
// rkey = device ID
{
  $type: "com.example.device-keys"
  authPubkey: bytes    // Ed25519 public key; exact signing authority depends on policy
  encryptPubkey: bytes // X25519 public key for receiving encrypted grants
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

A declaration identifies the space, account, and selected signing/encryption key pairs, using exact bytes or verified immutable references. Device IDs alone are insufficient. Publication does not enroll a device, and a declaration cannot grant account membership.

Declaration encoding, replacement, withdrawal, and concurrent updates remain [TODO-04](TODOs.md#todo-04). Approval, grant-issuer, and administrative roles remain [TODO-03](TODOs.md#todo-03); selecting a recipient does not implicitly confer those powers.

### Preventing PDS substitution

A PDS could show the user their original declaration and an issuer a forged one. Inspecting one's own declaration cannot prevent that disclosure. Issuers support two trust modes:

- **Independently verified:** bind the intended account to exact keys through out-of-band (OOB) verification or an already verified trust path, then validate the selected recipients against that binding.
- **TOFU:** accept and pin an initial account-to-key binding without independent verification. This permits substitution at first acceptance; later continuity checks do not repair a compromised initial binding.

Optional verification concerns the account-to-key binding, not cryptographic validation. Neither mode permits skipping required signatures, exact-key matching, or continuity checks. A new binding must follow the approval or recovery policy rather than silently replacing a pin.

One approval candidate is an accepted device signing the protocol purpose/version, exact space, account, and complete selected key bindings. It could attach the approval when publishing for offline verification. The approving client must authenticate the intended keys, such as through pairing, rather than blindly sign a PDS-supplied list. Issuers validate the approval against their accepted binding and encrypt only to the exact selected key. The approval mechanism remains [TODO-01](TODOs.md#todo-01).

An independently verified, uncompromised binding and valid selection authorization prevent PDS substitution for grants made against them. They do not prove that a selection or signer remains authorized. Space-wide prevention requires every issuer of the same content key to enforce verified bindings: one TOFU grant can expose that key despite other issuers' verification.

### Establishing the first trusted binding

Self-signatures, possession challenges, PDS login, and repository publication do not independently bind a key to the intended user. Verification could reuse a verified binding or establish one through pairing or a trusted inviter; an account-only invitation is insufficient. The joining device also needs a trust decision for the space configuration.

Every issuer, including new or restored installations, must record accepted bindings and distinguish TOFU from independently verified trust. Deletion, rejoining, reinstall, or state loss must not silently reset trust or downgrade verification. Bootstrap methods, transferable evidence, verification status, and trust retention remain [TODO-02](TODOs.md#todo-02).

### Detecting inconsistent views

Auditing is part of the baseline. [Spaces applications sync each participant's repo directly from its host](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data#spaces), providing an evidence path outside the affected user's PDS:

1. Alice's PDS shows Bob a forged declaration selecting attacker-controlled keys.
2. Bob's device signs grant evidence identifying that declaration and the exact recipient keys, and publishes it in Bob's own permissioned repo for the space.
3. Alice syncs Bob's repo, validates the evidence, and compares it with her authorized selections. She can detect keys she never authorized even if her PDS keeps showing her the original declaration.

For every grant, the issuer must retain and publish device-signed issuance evidence binding the issuer, space, epoch/key ID, recipient account/device, exact declaration and keys, and grant. The existing signed grant may serve as the receipt. Retain the full declaration, resolved public keys, and approval evidence used; hashes alone are insufficient if the source PDS withholds the bytes. Publication accompanies grant release, including directly delivered grants; ordering and failure handling remain [TODO-09](TODOs.md#todo-09).

Clients must audit evidence addressed to their account against retained authorization history and alert on unauthorized keys or conflicting selections. Verify the issuer's device signature under the recorded trust policy; repository authentication alone is insufficient. Distinguish observation-only records from issuance evidence, legitimate revisions from conflicts, and stale authorized selections from keys never authorized. An issuer's signature attests to its statement; by itself it does not prove PDS misconduct or that a recipient decrypted the grant.

Detection depends on an honest issuer retaining and publishing evidence, the affected client eventually obtaining it, and sufficient authorization history to recognize the mismatch. Direct sync removes the affected PDS as the sole evidence path; it does not guarantee discovery under withholding or colluding hosts, loss of read access, or indefinite isolation. Report known gaps or lost history as an incomplete audit; matching receipts do not prove all grants were observed. Detection cannot undo disclosure and has no promised deadline.

Evidence must be readable without the key being granted or the possibly substituted recipient private key. It may remain permissioned; no public disclosure of space membership is required. Retention, discovery, access after removal, privacy, and the receipt format remain [TODO-09](TODOs.md#todo-09) and [TODO-05](TODOs.md#todo-05).

## Key issuance and content flow

Issuers apply [Core's authorization checks](core.md#authorization-before-grant-release), then create and deliver [encrypted grants](core.md#grant-creation). Issuance waits if no eligible key holder is available. Initial verification evidence must be accessible without the key being granted; packaging remains [TODO-05](TODOs.md#todo-05).

Devices encrypt and decrypt locally; plaintext caches, search, previews, and exports stay on devices. Spaces still governs ciphertext access and writes. [Core](core.md) defines content formats and authorship limits.

## Revocation and recovery

### Grant freshness

Issuers must honor authenticated withdrawals they learn about. A PDS can replay an older selection to other issuers; hiding an approver's revocation can also enable new malicious approvals if its key is compromised.

Freshness applies to membership, recipients, and approval/issuer authority in both trust modes. Neither OOB verification nor audit receipts establish freshness or a bounded revocation delay. Reusable, expiring, and fresh per-grant approvals have different availability and replay tradeoffs; choosing a policy remains [TODO-06](TODOs.md#todo-06).

A nonce proves recent participation, not current knowledge or authority. A challenge to the proposed recipient alone does not authenticate user consent.

See Core for [content-key rotation](core.md#revocation-and-rotation) and [recovery/succession](core.md#recovery-and-succession). Losing the creator's device need not block other users' device additions, but may affect administration or key availability.

## References

- [PEEP Core](core.md) and [TODOs](TODOs.md).
- [Spaces](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data): membership and ciphertext access.
- [Repository](https://atproto.com/specs/repository) and [sync](https://atproto.com/specs/sync): publication evidence and its limits.

Device publications, declarations, and enrollment evidence are proposed extensions.
