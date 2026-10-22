# PEEP: Rationale and Alternatives

This document is informative. Requirements are in [Core](core.md), [Device Enrollment](device-enrollment.md), and [Auditing](audit.md).

## Why this design

PEEP targets retained shared data in atproto Spaces. Current members may read pre-join history; applications create spaces frequently and reuse account/device verification across them. The host already controls account membership. Signed approvals make an app installation one of an account's devices in all its spaces, while any eligible holder can distribute keys through its own repo without an appointed issuer.

Independent device verification prevents PDS key substitution under the endpoint trust assumptions. TOFU instead accepts initial-substitution risk and relies on conditional later discovery through published grants and direct repo sync. Verification is a per-space policy rather than a per-relationship option: with one shared key, the weakest exchange sets the whole space's protection, so a verified pair inside a TOFU space would gain nothing. Local verification avoids transferable-attestation infrastructure. Grant evidence records the actual recipient selection and decision, while normal Spaces access governs who can audit it.

One key for the life of a space makes all retained history available through one grant per device. PEEP does not [rotate](core.md#no-rotation) that key. Spaces already give the host access control over who can fetch ciphertext, so removal relies on it: a removed participant keeps the key, and keeping later content from them depends on the host. That requires a read policy that authenticates users, and for a removed device it also requires the user to cut the device off at their PDS, since the host grants access to accounts rather than devices ([ending access](core.md#ending-access)). Rotation would add protection only against a host that misbehaves, at the cost of epochs, history wrapping, carried-forward exclusion state, host activation, and writer pauses. Removal therefore needs no new space. Spaces are cheap to create, so users who credibly believe the host or PDSes are compromised in a way access control cannot stop can [replace the space](core.md#replacing-a-space). These choices trade stronger secrecy and freshness guarantees for history access, asynchronous operation, and simplicity. Key compromise exposes the whole space, revocation takes effect only when learned, and a lost key loses the space. Trust in the host and application software remains essential.

Devices are enrolled account-wide rather than per space. Per-space selection could not contain a compromised installation, which can approve devices and join spaces without remote validators seeing whether the user confirmed, and it cost per-space declaration histories and conflicts. Containing applications is left to host membership and the PDS's repo permissions; request-driven delivery keeps honest applications from holding keys they do not use.

Per-target local revocation cutoffs replace cycle detection, trading simpler validation for the possibility that a withdrawn device forces replacement of the entire older device set.

## Comparison

The comparison concerns key mechanisms and their integration, rather than every feature of the products using them.

| Mechanism | Relevant properties | Relationship to PEEP |
| --- | --- | --- |
| [MLS, RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) | Group epochs, authenticated updates, and tree-based key establishment provide forward secrecy and post-compromise security under the protocol's assumptions. Joining bootstraps the new epoch; its Welcome is not an archive of prior epochs. | A strong candidate when those guarantees are required. Spaces would still need membership/identity integration and a history-sharing layer; PEEP currently chooses one retained space key and host authority instead of MLS group state. |
| [Megolm](https://spec.matrix.org/latest/olm-megolm/megolm/) | Each sender has an outbound ratchet and signing key. Retaining/exporting an earlier ratchet point permits reading from that point onward. Retained history limits forward secrecy; compromise exposes later messages in that session until a new session replaces it. Session-key exchange depends on a secure channel. | Closer to retained-history messaging, but adds per-sender session distribution and ratchet state. PEEP uses one content key per space epoch without adding [message-authorship proofs](core.md#encrypted-records). |
| [Signal sender keys](https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/group_cipher.rs) | libsignal derives message keys from per-sender chain state, signs messages, and supplies distribution-message operations. Membership authorization, delivery of distribution messages, and archive policy require surrounding application logic. | Sender-key mechanics alone do not supply PEEP's enrollment or grant audit contract. Adopting them would change content/state handling; this comparison does not equate sender keys with every security property of the Signal application or its pairwise protocol. |
| [Keybase team keys](https://book.keybase.io/docs/teams/crypto) | Team generations distribute a seed through per-user keys; team signing chains record public keys. Rotation wraps the previous seed under material derived from the next generation, making history accessible to new members. | The closest history-distribution precedent. PEEP drops generations entirely, keeping one key per space, with direct grants to selected installation keys, host membership decisions, and per-space declarations instead of importing Keybase's per-user key and team-signing-chain architecture. |

## Why not MLS now?

### The requirements diverge where MLS is strongest

MLS is designed so that compromise of a member's state exposes as little past and future traffic as possible. PEEP's central requirement runs the other way: current members, including newly joined devices, read the space's retained history. Any device able to read that history exposes it if compromised, whatever key-agreement protocol delivered its keys. For retained Spaces content, MLS's forward secrecy therefore protects little beyond the key-agreement state itself.

History access does not rule out MLS. The RFC defines [exporters](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.5) for application secrets. An application could keep separately retained archive keys and send them to new members over MLS; that is an architectural option inferred from these facilities, not an archive feature promised by the RFC. Doing so means rebuilding most of PEEP on top of MLS:

| PEEP component | Still required with MLS? |
| --- | --- |
| A retained [space key](core.md#key-generation) | Yes. MLS epoch secrets are deleted as the group advances, and a Welcome bootstraps only the current epoch. Pre-join history needs a separate retained key with its own compromise semantics. |
| Host [membership](core.md#trusted-host-state) | Yes. Spaces already gives the host membership authority, and MLS needs a delivery service to order commits. Clients could refuse additions no member committed, but that would contradict Spaces administration rather than reduce host trust in practice. |
| [Approvals](device-enrollment.md#approvals), [local trust](device-enrollment.md#local-trust), and [revocation](device-enrollment.md#device-revocations) | Yes. MLS authenticates leaves through credentials whose validation the application defines. Mapping atproto accounts to app installations, verifying bindings, and making revocation permanent across spaces stay application work. |
| [Grant evidence](audit.md#evidence) and [auditing](audit.md) | Yes, or a replacement. The MLS transcript authenticates group operations to members, but it is not repo-published evidence of who released which keys under which authorization. |
| [Content encryption](core.md#content-encryption) | Mostly. Retained records and blobs need keys that outlive MLS epochs, so content would be encrypted under the archive keys rather than MLS application messages. |

What MLS would replace is the narrowest part of PEEP: [delivering the space key to members' devices](core.md#key-grants). PEEP does that with one HPKE grant per device.

### Costs MLS adds for Spaces

- **Per-space group state.** Applications create spaces frequently. Each would be an MLS group whose ratchet tree every device stores and updates. A PEEP device needs only its keys and the grants addressed to it.
- **Ordered processing.** MLS members process commits in epoch order. An offline device must replay every missed commit, or rejoin, before it can follow the group, and lost state is hard to recover. PEEP grants can be read independently and in any order; one grant recovers the whole space.
- **Epoch churn from device changes.** Adding or removing a device in MLS requires a commit that advances the epoch for every member, in every space the device joins. In PEEP, neither additions nor removals change the key; a new device simply receives grants.
- **Key package supply.** Joining via Welcome consumes a key package that is generally single-use. Devices would publish and replenish key packages in their repos, adding availability and exhaustion cases that PEEP's long-lived published device keys avoid.

### What PEEP gives up

MLS brings standardized security analysis and stronger guarantees that PEEP explicitly does not provide. The most relevant loss is post-compromise security for device keys. In PEEP, an attacker who silently copies a device's encryption key can decrypt every later grant to that device until the binding is revoked, and anyone who copies a space key can read that space for as long as they can obtain its ciphertext. MLS heals this once the device sends an update; PEEP's only remedy is a new space. MLS removal also excludes a removed member cryptographically, where PEEP relies on the host.

Simplicity is an objective, not a demonstrated advantage: PEEP avoids group-ratchet state but introduces enrollment, revocation, recovery, and audit machinery that requires independent review. A comparison implementation, very large spaces, or a requirement for post-compromise security would justify revisiting this choice. A middle option would use MLS only to deliver PEEP's epoch keys while keeping history wrapping and host authority. Periodic device encryption-key rotation could narrow the post-compromise gap without MLS.
