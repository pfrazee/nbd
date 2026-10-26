# NBD: No Big Deal Encryption Proposal

End-to-end encryption for atproto spaces. **Discussion draft:** baseline decisions are specified; implementation and independent validation remain outstanding.

"NBD" means two things:

1. Convenient: No big deal to implement
2. Relaxed: No big deal data should be kept in it

This scheme is for casual computing needs. It gives people who already know you time to stop a remote account takeover, alerts you to changes in your own devices, and lets members detect a malicious PDS after the fact. A stricter scheme would replace the trust-on-first-use (TOFU) scheme, add forward secrecy, and/or ensure regular key rotation. NBD is for people who trust the members of their space, semi-trust their PDS, and do not want to hide historic space activity from new members. It aims to minimize security tasks by users. If NBD does not fit your use-case, do not use it.

Usage looks like:

```typescript
const content = { $type: "app.example.message#content", text: "Hello!" };
const plaintext = CBOR([CBOR(content), padding]); // Zero bytes chosen under the padding rules.
// Encrypt plaintext with the record associated data (see core.md#content-encryption).
{
  $type: "app.example.message",
  envelope: {
    $type: "com.example.nbd.envelope",
    format: 1,
    keyId: "71329bda9cf34bf7a8f68f475e166981",
    nonce: Uint8(...),
    ciphertext: Uint8(...),
    blobs: []
  }
}
```

## User experience

To get a quick understanding of these specs, see the user experience documentation:

- **[Relaxed](ux-flows/relaxed.md)** - How applications work when they're not overly paranoid.
- **[Paranoid](ux-flows/paranoid.md)** - A more security-minded user experience.

## Specs

The spec documents use [normative conventions](core.md#conformance-and-validation-results).

| Document | Defines |
| --- | --- |
| [Core](core.md) | Trust boundaries, [protocol conventions](core.md#protocol-conventions), [key grants](core.md#key-grants), [content encryption](core.md#content-encryption), and the [space key lifecycle](core.md#space-key-lifecycle). |
| [Device enrollment](device-enrollment.md) | Bindings, [trust on first use](device-enrollment.md#local-trust), [approvals](device-enrollment.md#approvals), [revocation](device-enrollment.md#revocation-and-freshness), [recovery](device-enrollment.md#recovery), and [platform notes](device-enrollment.md#platform-notes). |
| [Auditing](audit.md) | Evidence, publication, retention, historical validation, and sync. |
| [Rationale](rationale.md) | Design choices and comparison with MLS, Megolm, Signal sender keys, and Keybase team keys (informative). |
| [Remaining work](TODOs.md) | Implementation, [validation cases](TODOs.md#validation-cases), and deferred extensions. |
| [Executable model](model/README.md) | Local trust in Python, with adversarial cases, random walks, and mutation testing (informative). |
| [Tamarin model](formal/README.md) | Symbolic proofs of secrecy and authentication under compromise and a malicious PDS (informative). |
| [Prototype](prototype/README.md) | Multi-device simulation with a playable UI; start with its [reviewer guide](prototype/README.md#for-reviewers) (informative). |

## Description

Users publish device keys publicly and add devices to their account through signed approvals. First contact is trusted, and afterwards devices change only through visible, user-controlled steps. Only the member who invited someone may share keys with their devices right away; everyone else waits out a 72-hour first-contact hold. Eligible devices exchange encrypted space keys through signed grants, which also serve as audit records. Content encryption and decryption happen on clients. 

NBD has no forward secrecy, no post-compromise recovery, and no cryptographic exclusion after removal ([non-goals](#non-goals)).

### Goals

NBD aims to guarantee, against the stated adversaries:

1. **Confidentiality from outsiders.** Content is readable only by holders of the space key. The space host, PDSes, relays, and network observers learn metadata but not content ([content encryption](core.md#content-encryption)).
2. **No silent device addition after first contact.** Once a client has pinned an account, a new device of that account is accepted only through an approval signed by a device the client already accepted, or after a [re-enrollment hold](device-enrollment.md#re-enrollment). A PDS, or someone who takes over the account, cannot add a device for existing contacts without one of those ([local trust](device-enrollment.md#local-trust)). A device the client accepted and the account later removed still counts while the account keeps another device: whoever holds its key and can write to the repo can add devices, which goal 6 surfaces to the account holder ([revoked signers](device-enrollment.md#approval-validation)).
3. **Time to stop a takeover, from every member.** If an account at an honest PDS is taken over and its devices replaced, every client waits at least 72 hours, counted from when it first observes the new device, before sharing a space's key with it, even if the attacker holds a removed device's key, and the account's surviving installations alarm. Clients that knew the account wait out the [re-enrollment hold](device-enrollment.md#re-enrollment); clients that never did, including members admitted after the takeover, wait out the [first-contact hold](device-enrollment.md#grant-standing). The one exception is a member whose account first meets the new device through its own [invite](core.md#invites) of the account into a space, which can grant that space's key at once (non-goal 1).
4. **Removed devices stop receiving keys.** Deleting a device record stops new grants to it in every space once clients observe the deletion; ending its PDS session ends its access to ciphertext within one credential lifetime ([revocation](device-enrollment.md#device-revocations), [ending access](core.md#ending-access)).
5. **A stolen device cannot remove the user's other devices,** on a PDS that enforces OAuth permissions, unless the thief also has the account password, a signed-in browser session at the PDS, which the separate delete authorization may reuse, or another broad session ([revocation authority](device-enrollment.md#revocation-authority)).
6. **The account holder learns of every device change.** Each installation notifies its user of new and removed devices of the account, and alarms on grants to devices none of its installations generated, transferred, or approved ([own-account notices](audit.md#direct-sync)).
7. **Detection after the fact.** Grants are published with evidence, so members can audit who received keys, and substitution that does occur is detectable ([auditing](audit.md)).

### Non-goals

NBD explicitly does not protect against the following. Each is a deliberate trade-off, not an oversight.

1. **The inviter's first contact.** Whoever controls an account's repo when a client first meets it, a malicious PDS or a takeover, can choose the devices that client accepts. Every client then holds those devices before granting to them, except the inviter: a member whose account first meets an account through its own invite may grant to those devices at once in the spaces it invited the account to. So an inviter meeting an account just after it was hijacked, or capturing the first device of an account invited before it installed ([pending invites](core.md#invites)), shares those spaces' keys with the attacker. Signal has the same exposure for a new contact of a hijacked number. Independent device verification is deferred ([TODO](TODOs.md#deferred-extensions)).
2. **A malicious PDS hiding a reset from its own user.** The hold protects only if the account holder can learn of the reset; a PDS that hides the deletions from the user's installations is detected only by auditing, after disclosure.
3. **Malicious host decisions.** The space host decides membership; an admitted account receives the key and retained history ([trusted host state](core.md#trusted-host-state)).
4. **Members.** Any member can leak content or the key. Removed members keep the key and anything they already read; NBD never [rotates](core.md#no-rotation) a space's key and relies on Spaces access control to deny them later ciphertext.
5. **Forward secrecy and post-compromise security.** A copied device key or space key reads the whole space for as long as its holder can obtain ciphertext ([rationale](rationale.md#what-nbd-gives-up)).
6. **Malicious application code.** Applications, browser origins, and updates are trusted with installation keys ([platform notes](device-enrollment.md#platform-notes)).
7. **Bounded freshness.** Revocations take effect when learned; withheld updates can leave stale state usable ([freshness](device-enrollment.md#freshness)).
8. **Total key loss.** Losing every copy of a space key loses the space ([key loss](core.md#key-loss)).

### Evidence

A [Tamarin model](formal/README.md) proves, for unbounded sessions against an adversary that controls the network and every PDS and can compromise any device, that space keys stay secret except through the paths these goals permit, that grants and approvals are authentic, that accepted keys match the space's commitment, that a device the adversary created is accepted after first contact only through a completed hold or a compromised signer, that a space's key reaches an adversary's device early only through a vouch and invite into that same space, a completed hold, or a compromised signer, with that scope preserved through approval chains, and that removing the live-binding rule, or any of the invite rules, reintroduces the attack each prevents. It abstracts time and repo mechanics. Two executable artifacts test the trust rules in more detail but over bounded runs. The [Python model](model/README.md) checks local trust in a shared view of every repo with adversarial cases, random walks, and mutation testing. The [prototype](prototype/README.md) runs several installations against emulated PDSes and host, with network lag, malicious-PDS views, and write faults; a goal-level check judges every key disclosure against ground truth, and its [reviewer guide](prototype/README.md#for-reviewers) maps each goal and non-goal above to a playable scenario or test. The two cross-check each other on shared-view traces.