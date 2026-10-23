# PEEP: Security Goals and Non-Goals

Informative. This page states the bar the rest of the specification is meant to meet, so that review can check the design against it. PEEP provides TOFU enrollment with signed device approvals for retained shared spaces: first contact is trusted, and afterwards devices change only through visible, user-controlled steps. That matches a Signal-style messenger at first contact only. PEEP has no forward secrecy, no post-compromise recovery, and no cryptographic exclusion after removal ([non-goals](#non-goals)), so a compromised key costs far more than it would in Signal. Where the specification and this page disagree, one of them is wrong.

## Goals

PEEP aims to guarantee, against the stated adversaries:

1. **Confidentiality from outsiders.** Content is readable only by holders of the space key. The space host, PDSes, relays, and network observers learn metadata but not content ([content encryption](core.md#content-encryption)).
2. **No silent device addition after first contact.** Once a client has pinned an account, a new device of that account is accepted only through an approval signed by a device the client already accepted, or after a [re-enrollment hold](device-enrollment.md#re-enrollment). A PDS, or someone who takes over the account, cannot add a device for existing contacts without one of those ([local trust](device-enrollment.md#local-trust)). A device the client accepted and the account later removed still counts while the account keeps another device: whoever holds its key and can write to the repo can add devices, which goal 6 surfaces to the account holder ([revoked signers](device-enrollment.md#approval-validation)).
3. **Time to stop a takeover, from existing contacts.** If an account at an honest PDS is taken over and its devices replaced, every client that already knew the account waits at least 72 hours before sharing with the new device, even if the attacker holds a removed device's key, and the account's surviving installations alarm ([re-enrollment](device-enrollment.md#re-enrollment)). This is not a delay for the space: a member whose client never knew the account treats the new device as a first contact and can grant it the space key at once (non-goal 1).
4. **Removed devices stop receiving keys.** Deleting a device record stops new grants to it in every space once clients observe the deletion; ending its PDS session ends its access to ciphertext within one credential lifetime ([revocation](device-enrollment.md#device-revocations), [ending access](core.md#ending-access)).
5. **A stolen device cannot remove the user's other devices,** on a PDS that enforces OAuth permissions, unless the thief also has the account password, a signed-in browser session at the PDS, which the separate delete authorization may reuse, or another broad session ([revocation authority](device-enrollment.md#revocation-authority)).
6. **The account holder learns of every device change.** Each installation notifies its user of new and removed devices of the account, and alarms on grants to devices none of its installations generated, transferred, or approved ([own-account notices](audit.md#direct-sync)).
7. **Detection after the fact.** Grants are published with evidence, so members can audit who received keys, and substitution that does occur is detectable ([auditing](audit.md)).

## Non-goals

PEEP explicitly does not protect against the following. Each is a deliberate trade-off, not an oversight.

1. **First contact.** Whoever controls an account's repo when a client first meets it, a malicious PDS or a takeover, can choose the devices that client accepts. This includes a new contact meeting an account just after it was hijacked: that contact gets no hold, and if it is a member of a space, it can grant that space's key to the new device while existing contacts are still holding. Signal has the same exposure for a new contact of a hijacked number. Independent device verification is deferred ([TODO](TODOs.md#deferred-extensions)).
2. **A malicious PDS hiding a reset from its own user.** The hold protects only if the account holder can learn of the reset; a PDS that hides the deletions from the user's installations is detected only by auditing, after disclosure.
3. **Malicious host decisions.** The space host decides membership; an admitted account receives the key and retained history ([trusted host state](core.md#trusted-host-state)).
4. **Members.** Any member can leak content or the key. Removed members keep the key and anything they already read; PEEP never [rotates](core.md#no-rotation) a space's key and relies on Spaces access control to deny them later ciphertext.
5. **Forward secrecy and post-compromise security.** A copied device key or space key reads the whole space for as long as its holder can obtain ciphertext ([rationale](rationale.md#what-peep-gives-up)).
6. **Malicious application code.** Applications, browser origins, and updates are trusted with installation keys ([platform notes](device-enrollment.md#platform-notes)).
7. **Bounded freshness.** Revocations take effect when learned; withheld updates can leave stale state usable ([freshness](device-enrollment.md#freshness)).
8. **Total key loss.** Losing every copy of a space key loses the space ([key loss](core.md#key-loss)).

## Review question

If the specification meets exactly the goals above and documents the non-goals, is it acceptable? Findings that show a goal failing are defects. Findings that fall under a non-goal should be raised as proposals to change this page, not as defects in the mechanisms.
