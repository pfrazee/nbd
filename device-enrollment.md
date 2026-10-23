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

PEEP uses trust on first use (TOFU) at first contact with an account, and signed [approvals](#approvals) for every later device of that account. First contact is trusted, as in a Signal-style messenger, and afterwards nothing can silently add a device for existing contacts; the [security goals](security-goals.md) list where PEEP's protection falls short of Signal's. Trust binds the account DID, device ID, and both keys, with no space identifier. Clients MUST persist pins independently of spaces; creating, leaving, deleting, or rejoining a space neither resets trust nor requires accepting an unchanged binding again. A client accepts a binding through:

- **First use.** When a client has never accepted a binding of an account, it [enumerates](#repo-observations) the account's repo at a verified commit and accepts the present device records, account-wide and at one position, only if they form one approval tree. Reach follows approvals from signer to target through any bindings. A root is a present device record with no incoming approval. If there is a root, it MUST be the only one and reach every present record. If there is none, the bindings without a present record MUST together reach every present record. Bindings without a present record, whether deleted devices or keys that never had a record, carry no authority of their own: their approvals only connect present records, and approvals among them, including cycles, never make a present record a second root or leave none to start from. Approvals left by devices the user removed, including an attacker's, therefore cannot block first use and stay in the repo as evidence; deleting their device records is enough. Otherwise the client declines first use and surfaces the account ("Bob has a device that isn't linked to his others").
- **Approval.** A binding approved by a same-account binding it accepts ([approvals](#approvals)). Acceptance is recorded with its evidence and persists even if the approval record later disappears.

Once a client has accepted any binding of an account, it MUST NOT accept a binding of that account without an approval path, except through [re-enrollment](#re-enrollment) once every accepted binding is revoked. Clients MUST NOT replace pins and MUST NOT offer users a way to accept an unapproved binding: with one shared key, a single member doing so would disclose the space to it. An unapproved binding stays unaccepted until an approval path arrives. Clients SHOULD surface unapproved bindings of other accounts that they decline, since one may indicate attempted substitution. Revoked bindings stay revoked.

A client that loses its own state MAY pin again on first use, and MUST report the loss. Pairing copies pins to a new installation; afterwards each installation pins independently, so a user's installations may hold different pins.

**First contact is not protected.** Whoever controls an account's repo when a client first meets it, a malicious PDS or someone who has taken over the account with create access, can choose the device graph that client accepts, including one rooted at its own device with an approval pointing at an honest device. A substituted device that any member accepts receives the space key and all retained history. This includes a client meeting an account for the first time just after it was taken over and reset: that client sees an ordinary first contact and gets no hold. [Auditing](audit.md#direct-sync) can detect substitution after the disclosure but cannot prevent or undo it. Independent device verification, which would prevent it, is a [deferred extension](TODOs.md#deferred-extensions).

**After first contact, takeover cannot silently add a device.** An accepted installation of the account must sign an approval, which [own-account notices](audit.md#direct-sync) surface to the account holder. Devices add; [revocation](#device-revocations) is by deleting device records, never by other devices. Whoever can delete them can revoke every device and re-enroll one, but every client that already knew the account waits out a [hold](#re-enrollment) that is surfaced to members and to the account's own installations. Self-signatures, possession challenges, PDS login/publication, and account-only invitations do not establish identity.

Each client MUST keep its own trust decisions; one user's decisions never establish trust for another user. Approval evidence, acceptance history, and revocations remain in [private state](#private-state).

## Approvals

An account's devices are defined by signed approvals and [revocations](#device-revocations), not by per-space selection. The account does not choose devices per space: every unrevoked device of an account is eligible in every space the account is a member of. Per-space selection would not contain a compromised installation: an accepted installation can approve devices and join spaces, and remote validators cannot tell whether the user confirmed. Containment of an application depends on host membership and on the PDS's permissions for repo access, not on PEEP. Devices [request keys](core.md#distribution-scheduling) only for spaces they use, which keeps honest applications from holding keys they do not need but is not a boundary.

```typescript
type Approval = {
  version: 1;
  signer: Binding;         // Accepted device of the same account.
  target: Binding;         // Device being added.
  proof: bytes;
};
```

Sign with `Ed25519.Sign(signerKey, CBOR(["peep/device-approval", 1, approvalWithoutProof]))`. Signer and target MUST name the same account. Publish in the account's public repo under [record conventions](core.md#records). Approvals only add devices; removing a device is [revocation](#device-revocations) by the PDS, which is permanent.

Before signing, the approving installation MUST authenticate the target binding through pairing and obtain the user's confirmation of adding a device to the account. The UI MUST state that the device gains access to all of the account's spaces and SHOULD warn the user to link only devices they own, because tricking users into scanning an attacker's linking code yields full access. It MAY show a name reported by the new device, which that device supplies and is not otherwise authenticated. Keys need not be displayed. Possession alone or a PDS-supplied list is insufficient user intent. The approving installation MUST persist the signed approval locally before publication. A new device MUST NOT publish its device record until its approval is in the account's repo, or both are written in one commit, so that [first-use](#local-trust) clients never see it unlinked.

After an account's first contact, approval is the only way it adds a device, apart from [re-enrollment](#re-enrollment). An accepted, unrevoked device MAY approve devices for its own account. Clients MUST validate paths outward from a locally accepted binding, checking each signature, exact binding, and same-account scope. Clients MUST preserve exact approval records for offline validation. Self-signatures or cycles among unknown keys cannot establish a root. Approval grants neither membership, cross-account authority, nor administration.

### Approval validation

Enumerate approvals alongside device records during discovery and periodic public-repo catch-up. `ObserveApproval(value, state)` MUST perform D1–D3 before accepting the target:

1. **D1 — Validate.** Check schema, CID, same-account scope, both bindings, and signature, and require both the approval record and the target's device record to be [proven present](#repo-observations) at a verified commit. Invalid input returns `INVALID` and gains no authority; an unproven record returns `INCOMPLETE`.
2. **D2 — Signer.** Require the signer to be a binding the client has accepted under [local trust](#local-trust). The signer's later revocation does not invalidate an approval whose record remains present; the PDS removes what a revoked device added by deleting those records. An approval whose signer is not yet accepted is retained and returns `INCOMPLETE`; re-evaluate it when the signer becomes accepted.
3. **D3 — Commit.** Unless the target is revoked, accept it, and persist the approval, the commit it was proven against, and the acceptance position atomically. An approval of an already accepted binding adds evidence only.

Approvals do not conflict: each one adds a device, and validation order does not change the accepted set. Withholding an approval delays a device's acceptance; it cannot remove an accepted device. Only [revocation](#device-revocations) removes one.

## Revocation and freshness

### Repo observations

Device records and their removal are read from the account's repo, so clients MUST authenticate what they read there. Each atproto repo commit is signed with the repo signing key named in the account's current DID document and carries a monotonic revision. For each account whose bindings it has accepted, a client MUST retain the highest commit revision and commit CID it has verified, and MUST:

- **Verify current state.** Check the latest commit used for a current decision against the signing key in the account's current DID document. Signing-key rotation and PDS migration do not reset the retained revision; atproto issues a new commit when the signing key rotates.
- **Verify historical commits separately.** An older commit, such as one embedded in grant evidence or retained from an earlier observation, may be signed by a key the account has since rotated away. Verify it against a signing key the account held, from the client's own retained DID document observations or a verifiable DID history such as the `did:plc` operation log. If no such key can be established, the commit is unverifiable historical evidence: report it as `incomplete` audit evidence, never as invalid, and never let it block a current decision or [grant acceptance](core.md#grant-acceptance), which rely on the client's own current observations.
- **Refuse rollback.** Reject any commit with a revision lower than the retained one, so a PDS cannot restore an older state in which a deleted record still exists. A different commit at the retained revision is a fork and raises an integrity alarm. Do not advance the retained revision to one in the future beyond a small clock allowance; otherwise a single far-future commit would make every later legitimate commit look like a rollback.
- **Prove presence.** A record is present only with an inclusion proof: a signed commit, which carries the revision, and the MST path to the record, as `com.atproto.sync.getRecord` returns.
- **Prove absence by enumeration.** A record is absent only when a complete enumeration of the repo at a verified commit, verified against that commit's MST root, does not include it; a full repo export (`com.atproto.sync.getRepo`) provides one. Clients MAY instead keep an enumerated copy current by applying verified commit events or diffs to a previous enumeration. Enumeration also yields the account's complete device set and approvals for [first use](#local-trust) and [re-enrollment](#re-enrollment).
- **Nothing else counts.** Record-level reads such as `com.atproto.repo.getRecord` and `listRecords` carry no commit or revision and prove nothing. Neither does a failed, partial, or error response, including a not-found error, or an enumeration that cannot be checked against the commit's MST root.

Device records and approvals count only when proven present in the account's own repo; copies relayed elsewhere supply bytes, not authority. Clients SHOULD follow each pinned account's authenticated commit event stream, in which deletions appear as operations in signed commits, and treat a verified deletion there as proven absence. A client that only enumerates current state can miss a deletion followed by recreation between two of its enumerations ([limits](#device-revocations)).

### Device revocations

Devices cannot revoke one another; removal happens in the account's repo. A device is revoked by deleting its device record from the account's repo. A client revokes an accepted binding when it verifies, against a commit at or above its retained revision, that the record at that binding's device ID is absent or holds a different binding. Revocation is permanent and applies in every space. It needs no device signature: revoking requires write access to the record, which PEEP limits through [session permissions](#revocation-authority).

- **No resurrection.** A record for a binding the client has revoked that appears in a later commit is ignored and raises an integrity alarm. Fresh keys always use a new device ID ([bindings](#bindings-and-publication)), so no legitimate flow recreates one.
- **Effects.** A revoked binding receives no new grants and issues none. Approvals it signed remain evidence: bindings it approved stay accepted, and its approval records still connect [first-use](#local-trust) sets. To remove devices a revoked device added, the user deletes their records too; applications that remove a device SHOULD list the devices it approved and offer to remove them.
- **Ending access.** Revocation cannot erase copied keys/plaintext, and PEEP does not [rotate](core.md#no-rotation) space keys: the revoked device keeps keys it already holds. Removing a device means ending its PDS session and deleting its record, in that order ([removal order](#revocation-authority)). A device that keeps its session can still publish approvals that clients accept, and can recreate its own record.

### Revocation authority

PEEP does not change PDS behavior. Whoever can delete or overwrite a device record can revoke that device, so PEEP limits revocation through the OAuth permissions its applications request:

- **Standing sessions are create-only.** Applications MUST request only `create` access to the device and approval collections for their ongoing sessions (for example `repo:com.example.peep.device?action=create`) and MUST NOT write device records with `putRecord`, which requires `update` as well.
- **Removal uses a separate authorization.** To remove a device, an application obtains a short-lived authorization with `delete` access to the device collection, uses it for the removal, and discards it. The authorization takes the user through the PDS's authorization interface, which [may reuse](https://atproto.com/specs/oauth#authorization-interface) an existing browser session there, so it does not by itself require the password: a stolen device with a signed-in browser session at the PDS can obtain one.
- **Removal order.** Applications MUST have the user end the device's PDS session first, then delete its record, then verify its absence by [enumeration](#repo-observations) at a commit made after both steps. Deleting first leaves a window in which the device can recreate its record; peers that miss the absence keep it accepted. If the record has reappeared, the application MUST delete it again and tell the user that something still has write access, such as another session or someone with the password. Where the user cannot identify the device's session, the application deletes the record anyway and keeps verifying its absence.

On a PDS that enforces OAuth permissions, a stolen installation's session therefore can neither delete nor overwrite the account's other device records. That does not extend to sessions PEEP does not control: app passwords and other non-OAuth credentials bypass permission checks, and any application granted `update` or `delete` access to the device collection, including through `repo:*`, can revoke devices, as can anyone with the account password or a signed-in browser session at the PDS. Clients cannot tell which kind of session wrote a commit. Such a session can revoke every device but cannot add one; the user removes it and recovers through [re-enrollment](#re-enrollment). Applications MUST NOT claim that a stolen device cannot remove the user's others without these conditions.

Account migration that drops device records revokes those devices on every client that verifies the new commits; users SHOULD check their device list after migrating. The account's PDS can revoke any device; a malicious PDS can deny service this way, as it already could by withholding its account's records.

Limits:

- **Missed deletions.** A client that last saw a record before its deletion and next sees it after recreation never observes the absence and keeps the binding accepted, while clients that observed it revoke the binding. Recreation needs `create` access to the collection, which the [removal order](#revocation-authority) takes from the device before its record is deleted; otherwise recreation requires a malicious PDS or another session with access to the collection.
- **Divergent histories.** Refusing rollback protects only each client's own sequence of observations. Repo commits do not chain (`prev` is normally null), so a malicious PDS can show different clients different histories, each with increasing revisions. Comparing commits detects only two different commits at one revision, or a binding shown present, then absent, then present again, which no honest flow produces. Grant [evidence](audit.md#evidence) records the commit each issuer relied on, supplying such commits to auditors. Other divergence is undetectable.

### Re-enrollment

When a client verifies that every binding it has accepted for an account is revoked, [first use](#local-trust) applies to that account again after a hold. A new set satisfying the first-use rule, proven present at a verified commit, becomes the account's re-enrollment candidate. The client MUST NOT grant keys to or accept keys from any binding in the candidate until it has credited `REENROLL_HOLD` (72 hours) of elapsed time to that exact candidate since first observing it ([hold timing](#hold-timing)); it then accepts the candidate as on first use. Holds bind to the candidate set: when the candidate changes, its removed members are revoked and the hold restarts for the new candidate. A hold ends when its candidate is accepted, when any of the candidate's bindings is revoked, which cancels it, or when the client accepts an unrevoked binding of the account by any other path. An ended hold stays ended: no import or restore brings it back. Every client that knew the account MUST apply the hold: with one shared key, a single client that grants early discloses the space.

During the hold:

- Clients MUST visibly surface the pending device to members, identifying the account and the earliest time this client will share with it ("Bob reset his devices. This device will share with his new device from Friday."). Each client starts its own hold when it first observes the candidate, so access arrives at different times from different members and in different spaces; no client can promise a universal unlock time.
- An installation that verifies its own binding's record absent, or learns of its own binding's revocation through import or restore, MUST alarm prominently, say the account may be compromised if the user did not remove the device, and direct them to change their password and remove unrecognized devices. Removing the candidate cancels it.
- The recovering device MAY say that people who already knew the account wait at least `REENROLL_HOLD` and show, per space, whether any member has shared with it yet. It MUST NOT present its own reset time plus the hold as the time access will return, and MUST NOT describe the hold as a minimum delay before anyone can read a space: a member whose client never knew the account can grant at once.

The hold lets a user stop an account takeover at an honest PDS, such as a phished password or email reset, if they notice within the hold. It protects only clients that knew the account before the reset; [new contacts](#local-trust) see an ordinary first contact. With one shared key, the hold delays a space's disclosure to the new device only while every member able to grant knew the account; one member that never did can grant at once, so the hold is protection enforced by existing contacts, not a space-wide delay. It does not stop a malicious PDS, which can show the deletions to members while hiding them from the user's own installations; [auditing](audit.md#direct-sync) detects that case through grants to unapproved own bindings, after disclosure.

#### Hold timing

Clients measure a hold as elapsed time in their own clock domain and never compare timestamps taken on different installations or clocks. For each hold a client persists the elapsed time credited so far and a checkpoint on its own clock. While running it credits time from a monotonic clock. Across restarts, where monotonic readings do not survive, it credits the wall-clock interval since the last persisted checkpoint only when that interval is non-negative; a clock that moved backward, or an interval the client cannot establish, credits nothing. Clients SHOULD persist checkpoints regularly so that a restart loses little credit. Holds assume honest clocks: a forward clock change while a client is not running shortens that client's hold, which is equivalent to running modified application code and outside PEEP's [goals](security-goals.md#non-goals).

Transfers and backups carry each hold as its candidate and the elapsed time credited up to export, never as a start time. Time a backup spends in storage is not credited. An importer that holds the identical candidate keeps the larger credited time; an importer with no hold for the account adopts the imported one unless it would have ended, because the importer has accepted an unrevoked binding of the account or has revoked one of the candidate's bindings; an importer holding a different candidate keeps its own. Imported credit counts from the importer's own clock at import. A hold whose credited time the importer cannot establish, such as one recorded only as a timestamp, starts at zero on import.

### Bounded validation

Validators MUST use visited references, resumable progress, and finite byte/node/depth/work budgets; they MAY cache validated signatures and proofs. Validators MUST authenticate approval paths before using them and reject cross-account approvals; cycles among unaccepted keys establish nothing.

Implementations MUST publish supported limits and check each block before allocation. Resource exhaustion or unavailable required paths means incomplete validation, not permission to skip required checks, ignore proven revocations, or weaken trust checks. Large histories may require more work or a more capable client.

### Freshness

For client decisions, "current" means the latest authenticated state known locally under the relevant monotonic-revision rules. Clients MUST include every learned revocation. Receipt alone does not establish authority; missing required evidence still blocks the affected operation.

Clients MUST enforce each authenticated change as soon as learned:

| Change | Required effect |
| --- | --- |
| Account becomes ineligible | Block new grants to and from that account in the space until a later eligible host decision permits them. |
| Device revocation | Permanently block grants to/from the exact binding in every space. |
| Every accepted binding revoked | Hold any candidate set under [re-enrollment](#re-enrollment). |

Cached approvals MUST NOT override these effects. Approvals MAY be reused without expiry or fresh per-grant approval, including while the approver is offline. Neither a host read, an audit record, nor a repo read without a newer verified commit establishes freshness. A PDS that withholds newer commits leaves stale authorization usable indefinitely. No bounded propagation delay is promised; stricter profiles are [deferred](TODOs.md#todo-06).

## Recovery

### Private state

Clients MUST durably retain keys and exact binding pins, with the evidence each acceptance relied on; observed DID documents and repo signing keys, for verifying historical commits; first-observed host configuration values; first-use acceptance sets; approval evidence, retained even when approval records disappear; for each pinned account, the highest verified repo revision and commit CID; revoked bindings with the commit proving each absence; re-enrollment candidates with their exact membership, credited hold time, and local clock checkpoint; authenticated host observations; key acceptance decisions; pending operations; and audit checkpoints/gaps.

Clients MUST keep this state confidential and authenticated and use an append-only local journal with unique installation/history identity and monotonic sequence. Clients MUST preserve imported histories' identities/order and record the import as a local event. Local trust survives space lifecycles under [binding rules](#local-trust).

### Backup and transfer

Use the application's protected backup or pairing container for keys and state together. Transfers MUST be authenticated and encrypted between the user's own trusted installations. Bind format/version, owner account, source installation/history, and the full payload; authenticate before import. Protect encryption with independent high-entropy key material that PDS login/reset cannot reveal or replace. Document key wrapping/KDF, integrity, rollback-detection limits, and atomic restore. [Platform support](#platform-notes) must be validated; a new interoperable backup protocol is not required.

Before atomic import, clients MUST validate ownership, key/public-binding consistency, references, provenance, and journal integrity. Importers MUST union approvals and revoked bindings, keep the higher verified repo revision for each account, and merge host state by monotonic revisions. Importers MUST resolve conflicting pins explicitly and MUST NOT clear revocations or roll back newer known state. Re-enrollment holds transfer as credited elapsed time under [hold timing](#hold-timing). Importing a revocation of the importer's own binding raises the [re-enrollment](#re-enrollment) alarm. Transfer may carry a user's decisions to their own installations, never to another user.

An old backup cannot detect wholly lost newer state without a surviving reference. Report missing coverage/freshness, reconcile available sources, and never invent prior acceptance or revocation. A key-only restore recovers no trust/approval/audit history; report the loss and require explicit recovery.

### Replacement

A surviving, accepted, unrevoked device approves fresh same-account keys, and the user removes the lost devices through a [delete authorization](#revocation-authority). Each peer validates the approval locally; one eligible helper holding keys can then restore access to those spaces. Without a surviving device, the user recovers through [re-enrollment](#re-enrollment). PDS recovery cannot revive revoked bindings.

Removal/re-invitation follows host administration but cannot reset pins, revocations, or approval/audit history. Keep old grants; removal does not [rotate](core.md#no-rotation) space keys. Administration, device authority, and key recovery are separate: losing all key copies and decryptable backups [loses the space](core.md#key-loss). Cross-application backup portability is outside the baseline.

### Total device loss

A user who loses every installation and decryptable backup installs a fresh one, signs in at their PDS to [remove](#revocation-authority) every lost device, and waits out the [re-enrollment](#re-enrollment) hold; members are told when the new device will get access. Members then re-grant keys they hold. Keys held only by the lost installations are gone. Applications SHOULD explain the hold to the user and SHOULD prompt single-device users to add a device or enable backup so that recovery needs neither. A hold-free mechanism that a PDS cannot exercise alone, such as a recovery key, is an open design question ([TODO-08](TODOs.md#todo-08)).

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
