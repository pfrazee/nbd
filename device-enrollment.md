<!-- BEGIN REVIEW S3: Centralize enrollment requirements and link shared grant, rotation, and recovery rules -->
# PEEP: Device Enrollment

Status: Discussion draft

1. Users publish device public keys publicly.
2. Standard Spaces membership determines participating accounts.
3. Each participant publishes an in-space declaration selecting their exact device keys.
4. Key issuers authenticate those selections before granting keys.

Declarations are the enrollment state. This model requires neither a separate enrollment registry service, a global chain, nor creator approval for every device addition. Selection authentication and first-device bootstrap remain open; candidate mechanisms below are not settled requirements.

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

Both public keys use the profile's 32-byte encodings. The publication is reusable across spaces and contains no membership or per-space selection. Replacing either key requires a new authenticated selection; a mutable record URL cannot redirect an existing approval.

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

A PDS could show the user their original declaration and an issuer a forged one. The issuer must authenticate the selection before releasing a key; the user inspecting their own view does not prevent disclosure.

One candidate is a trusted-device approval covering the protocol purpose/version, exact space, account, and complete selected key bindings. The client could attach it when publishing, allowing verification while offline. For this to work:

- The issuer must trust the approving key through evidence independent of the declaration being verified.
- The client must authenticate the intended keys, such as through pairing, rather than blindly signing a PDS-supplied list.
- The issuer must validate approval and encrypt only to the exact authorized recipient key.

With an authenticated, uncompromised approver, this prevents a PDS from introducing a recipient the approver never selected. It does not prove that a previously approved selection or signer remains authorized. The mechanism and signing rules remain [TODO-01](TODOs.md#todo-01).

### Establishing the first trusted binding

Self-signatures, possession challenges, PDS login, repository publication, and witness receipts do not independently bind a key to the intended user. Bootstrap could reuse a verified binding or establish one through pairing or a trusted inviter.

Every issuer needs an authenticated trust path, including new or restored issuers. Verification must bind the intended account and exact keys; the joining device must authenticate the space configuration. An account-only invitation is insufficient.

TOFU permits active substitution at first acceptance. Deletion, rejoining, reinstall, or state loss must not silently reset verified trust to TOFU. Bootstrap, transferable evidence, and any TOFU policy remain [TODO-02](TODOs.md#todo-02).

### Detecting inconsistent views

Retained evidence, client comparisons, or optional witnesses may reveal inconsistent views. They cannot undo disclosure after a grant or guarantee discovery while clients are isolated. Publication evidence proves observation, not consent; different authentic selections may be legitimate revisions or concurrent edits. Audit design remains [TODO-09](TODOs.md#todo-09).

## Key issuance and content flow

Issuers apply [Core's authorization checks](core.md#authorization-before-grant-release), then create and deliver [encrypted grants](core.md#grant-creation). Issuance waits if no eligible key holder is available. Initial verification evidence must be accessible without the key being granted; packaging remains [TODO-05](TODOs.md#todo-05).

Devices encrypt and decrypt locally; plaintext caches, search, previews, and exports stay on devices. Spaces still governs ciphertext access and writes. [Core](core.md) defines content formats and authorship limits.

## Revocation and recovery

### Grant freshness

Issuers must honor authenticated withdrawals they learn about. A PDS can replay an older selection to other issuers; hiding an approver's revocation can also enable new malicious approvals if its key is compromised.

Freshness applies to membership, recipients, and approval/issuer authority. No bounded revocation delay is promised. Reusable, expiring, and fresh per-grant approvals have different availability and replay tradeoffs; choosing a policy remains [TODO-06](TODOs.md#todo-06).

A nonce proves recent participation, not current knowledge or authority. A challenge to the proposed recipient alone does not authenticate user consent.

See Core for [content-key rotation](core.md#revocation-and-rotation) and [recovery/succession](core.md#recovery-and-succession). Losing the creator's device need not block other users' device additions, but may affect administration or key availability.

## References

- [PEEP Core](core.md) and [TODOs](TODOs.md).
- [Spaces](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data): membership and ciphertext access.
- [Repository](https://atproto.com/specs/repository) and [sync](https://atproto.com/specs/sync): publication evidence and its limits.

Device publications, declarations, and enrollment evidence are proposed extensions.
<!-- END REVIEW S3 -->
