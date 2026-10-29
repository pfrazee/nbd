# NBD: No Big Deal Encryption Proposal

End-to-end encryption for atproto spaces. **Discussion draft:** baseline decisions are specified; implementation and independent validation remain outstanding.

"NBD" means two things:

1. Convenient: No big deal to implement
2. Relaxed: No big deal data should be kept in it

This scheme is for casual computing needs. It gives your space 72 hours to stop a remote account takeover, except from the member who invites the compromised account, and alerts you to changes in your own devices. If a PDS impersonates you to anyone, your devices alarm within a day, or warn you that they can't check. A stricter scheme would replace the trust-on-first-use (TOFU) scheme, add forward secrecy, and/or ensure regular key rotation. NBD is for people who trust the members of their space, semi-trust their PDS, and do not want to hide historic space activity from new members. It aims to minimize security tasks by users. If NBD does not fit your use-case, do not use it.

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
| [Device enrollment](device-enrollment.md) | Bindings, [trust on first use](device-enrollment.md#local-trust), [approvals](device-enrollment.md#approvals), [witnessed history](device-enrollment.md#witnessed-history), [revocation](device-enrollment.md#revocation-and-freshness), [recovery](device-enrollment.md#recovery), and [platform notes](device-enrollment.md#platform-notes). |
| [Auditing](audit.md) | Evidence, publication, retention, historical validation, sync, and [own-account history](audit.md#own-account-history). |
| [Rationale](rationale.md) | Design choices and comparison with MLS, Megolm, Signal sender keys, and Keybase team keys (informative). |
| [Remaining work](TODOs.md) | Implementation, [validation cases](TODOs.md#validation-cases), and deferred extensions. |
| [Executable model](model/README.md) | Local trust in Python, with adversarial cases, random walks, and mutation testing (informative). |
| [Tamarin model](formal/README.md) | Symbolic proofs of secrecy and authentication under compromise and a malicious PDS (informative). |
| [Prototype](prototype/README.md) | Multi-device simulation with a playable UI; start with its [reviewer guide](prototype/README.md#for-reviewers) (informative). |

## Description

Users publish device keys publicly and add devices to their account through signed approvals. First contact is trusted, and afterwards devices change only through visible, user-controlled steps. Only the member who invited someone may share keys with their devices right away; everyone else waits out a 72-hour first-contact hold. Clients accept devices only from the history a common atproto relay published, as their application's witness reconstructs it, and each account's own installations watch that history for devices they did not add. Eligible devices exchange encrypted space keys through signed grants, which also serve as audit records. Content encryption and decryption happen on clients.

NBD has no forward secrecy, no post-compromise recovery, and no cryptographic exclusion after removal ([non-goals](#non-goals)).

### Goals

NBD aims to guarantee, against the stated adversaries:

1. **Confidentiality from outsiders.** Content is readable only by holders of the space key. The space host, PDSes, relays, and network observers learn metadata but not content ([content encryption](core.md#content-encryption)).
2. **No silent device addition after first contact.** Once a client has pinned an account, a new device of that account is accepted only through an approval signed by a device the client already accepted, or after a [re-enrollment hold](device-enrollment.md#re-enrollment). A PDS, or someone who takes over the account, cannot add a device for existing contacts without one of those ([local trust](device-enrollment.md#local-trust)). A device the client accepted and the account later removed still counts while the account keeps another device: whoever holds its key and can write to the repo can add devices, which the account holder's installations alarm on (goal 7, [revoked signers](device-enrollment.md#approval-validation)).
3. **Time to stop a takeover, from every member.** If an account at an honest PDS is taken over and its devices replaced, every client waits at least 72 hours, counted from when it first observes the new device, before sharing a space's key with it, even if the attacker holds a removed device's key, and the account's surviving installations alarm. Clients that knew the account wait out the [re-enrollment hold](device-enrollment.md#re-enrollment); clients that never did, including members admitted after the takeover, wait out the [first-contact hold](device-enrollment.md#grant-standing). The one exception is a member that never knew the account, met the new device on first use, and then [invites](core.md#invites) the account into a space it was not yet a member of: it can grant that space's key at once (non-goal 1).
4. **Removed devices stop receiving keys.** Deleting a device record stops new grants to it in every space once clients observe the deletion; ending its PDS session ends its access to ciphertext within one credential lifetime ([revocation](device-enrollment.md#device-revocations), [ending access](core.md#ending-access)).
5. **A stolen device cannot remove the user's other devices,** on a PDS that enforces OAuth permissions, unless the thief also has the account password, a signed-in browser session at the PDS, which the separate delete authorization may reuse, or another broad session ([revocation authority](device-enrollment.md#revocation-authority)).
6. **The account holder learns of every device change.** Each installation notifies its user of new and removed devices of the account, and alarms on grants to devices none of its installations generated, transferred, or approved ([own-account notices](audit.md#direct-sync)).
7. **Impersonation is detected within a day.** If any honest client accepts a device as yours that none of your installations generated, transferred, or approved, a running installation of yours alarms within 24 hours, or warns that it cannot check, and one that was not running does so when it next runs. This holds against a malicious PDS, including your own, and whichever spaces were involved, as long as the reference relay, your application's witness, and the accepting client's witness are honest and clocks are honest ([own-account history](audit.md#own-account-history), [witnessed history](device-enrollment.md#witnessed-history)). It is detection after the fact: for the member who invites the impostor, the key has already been shared; every other member is normally still holding. Grants are published with evidence, so members can also audit who received keys ([auditing](audit.md)).

### Non-goals

NBD explicitly does not protect against the following. Each is a deliberate trade-off, not an oversight.

1. **The inviter's first contact.** Whoever controls an account's repo when a client first meets it, a malicious PDS or a takeover, can choose the devices that client accepts. Every client then holds those devices before granting to them, except in a space its own account invites the account into: there it may grant at once to devices it met on first use, whenever it met them. So a member that first met an account just after it was hijacked, and then invites it into a space, or that captures the first device of an account invited before it installed ([pending invites](core.md#invites)), shares that space's key with the attacker. A member that knew the account before it was reset does not: the reset's new devices wait out the re-enrollment hold even in spaces it invites the account into. Signal has the same exposure for a new contact of a hijacked number. Independent device verification is deferred ([TODO](TODOs.md#deferred-extensions)).
2. **A colluding relay or witness, and warnings that are not proof.** Detection rests on the reference relay and the witnesses involved being honest. A relay that colludes with a PDS, or a dishonest witness, can again show different clients different histories, so a reset hidden from the user, or an impostor, is detected only by auditing, after disclosure. Even with honest ones, a PDS can turn some alarms into gap warnings, which say only that the user cannot check, and can create harmless gaps that train users to acknowledge them ([own-account history](audit.md#own-account-history)).
3. **Malicious host decisions.** The space host decides membership; an admitted account receives the key and retained history ([trusted host state](core.md#trusted-host-state)).
4. **Members.** Any member can leak content or the key. Removed members keep the key and anything they already read; NBD never [rotates](core.md#no-rotation) a space's key and relies on Spaces access control to deny them later ciphertext.
5. **Forward secrecy and post-compromise security.** A copied device key or space key reads the whole space for as long as its holder can obtain ciphertext ([rationale](rationale.md#what-nbd-gives-up)).
6. **Malicious application code.** Applications, browser origins, and updates are trusted with installation keys ([platform notes](device-enrollment.md#platform-notes)).
7. **Bounded freshness.** Revocations take effect when learned; withheld updates can leave stale state usable ([freshness](device-enrollment.md#freshness)).
8. **Total key loss.** Losing every copy of a space key loses the space ([key loss](core.md#key-loss)).

### Evidence

A [Tamarin model](formal/README.md) proves, for unbounded sessions against an adversary that controls the network and every PDS and can compromise any device, that space keys stay secret except through the paths these goals permit, that grants and approvals are authentic, that accepted keys match the space's commitment, that a device the adversary created is accepted after first contact only through a completed hold or a compromised signer, that a space's key reaches an adversary's device early only through the issuer's first use of it followed by an invite of its account into that same space, a completed hold, or a compromised signer, with that scope preserved through approval chains, and that removing the live-binding rule, or any of the invite rules, reintroduces the attack each prevents. Its relay-witness variant proves that every binding an honest client accepts was published by the reference relay first, and that every installation of the account that reaches its position sees it or a gap there; removing any of the witness rules reintroduces the attack it prevents. It abstracts time, liveness, and cursors. Two executable artifacts test the trust rules in more detail but over bounded runs. The [Python model](model/README.md) checks local trust in a shared view of every repo with adversarial cases, random walks, and mutation testing, and its witness variant adds a relay, witnesses, and a PDS that forks what it shows clients, with the 24-hour deadline checked after every step. The [prototype](prototype/README.md) runs several installations against emulated PDSes and host, with network lag, malicious-PDS views, write faults, and a relay with witnesses; a goal-level check judges every key disclosure against ground truth, and its [reviewer guide](prototype/README.md#for-reviewers) maps each goal and non-goal above to a playable scenario or test. The two cross-check each other on shared-view traces.