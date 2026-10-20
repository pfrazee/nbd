# PEEP: Rationale and Alternatives

This document is informative. Requirements are in [Core](core.md), [Device Enrollment](device-enrollment.md), and [Auditing](audit.md).

## Why this design

PEEP targets retained shared data in atproto Spaces. Current members may read pre-join history; applications create spaces frequently and reuse account/device verification across them. The host already controls account membership and epoch order. Signed per-space selections authorize particular app installations, while any eligible holder can distribute keys through its own repo without an appointed issuer.

Independent device verification prevents PDS key substitution under the endpoint trust assumptions. TOFU instead accepts initial-substitution risk and relies on conditional later discovery through published grants and direct repo sync. Local verification avoids transferable-attestation infrastructure. Grant evidence records the actual recipient selection and decision, while normal Spaces access governs who can audit it.

A fresh key per epoch and immutable backward wraps make retained history available through a small number of device grants. Missing wraps have direct-grant fallback; unavailable active keys have fresh-epoch recovery. These choices trade stronger secrecy and freshness guarantees for history access and asynchronous operation. Current-key compromise exposes connected history, revocation takes effect only when learned, and availability is conditional. Trust in the host and application software remains essential.

## Comparison

The comparison concerns key mechanisms and their integration, rather than every feature of the products using them.

| Mechanism | Relevant properties | Relationship to PEEP |
| --- | --- | --- |
| [MLS, RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) | Group epochs, authenticated updates, and tree-based key establishment provide forward secrecy and post-compromise security under the protocol's assumptions. Joining bootstraps the new epoch; its Welcome is not an archive of prior epochs. | A strong candidate when those guarantees are required. Spaces would still need membership/identity integration and a history-sharing layer; PEEP currently chooses retained epoch keys and host authority instead of MLS group state. |
| [Megolm](https://spec.matrix.org/latest/olm-megolm/megolm/) | Each sender has an outbound ratchet and signing key. Retaining/exporting an earlier ratchet point permits reading from that point onward. Retained history limits forward secrecy; compromise exposes later messages in that session until a new session replaces it. Session-key exchange depends on a secure channel. | Closer to retained-history messaging, but adds per-sender session distribution and ratchet state. PEEP uses one content key per space epoch and defers independent device authentication of content. |
| [Signal sender keys](https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/group_cipher.rs) | libsignal derives message keys from per-sender chain state, signs messages, and supplies distribution-message operations. Membership authorization, delivery of distribution messages, and archive policy require surrounding application logic. | Sender-key mechanics alone do not supply PEEP's enrollment or grant audit contract. Adopting them would change content/state handling; this comparison does not equate sender keys with every security property of the Signal application or its pairwise protocol. |
| [Keybase team keys](https://book.keybase.io/docs/teams/crypto) | Team generations distribute a seed through per-user keys; team signing chains record public keys. Rotation wraps the previous seed under material derived from the next generation, making history accessible to new members. | The closest history-distribution precedent. PEEP uses the backward-wrapping idea with direct grants to selected installation keys, host membership decisions, and per-space declarations instead of importing Keybase's per-user key and team-signing-chain architecture. |

## Why not MLS now?

History access does not rule out MLS. The RFC defines [exporters](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.5) for application secrets. An application could use separately retained archive keys and share them with new members over MLS; that is an architectural option inferred from these facilities, not an archive feature promised by the RFC. The archive would have its own retention and compromise semantics.

PEEP's present choice is a narrow fit to Spaces' trusted membership host, retained data, reusable local device trust, and repo-published audit evidence. Simplicity is an objective, not a demonstrated advantage: PEEP avoids group-ratchet state but introduces enrollment, revocation, recovery, and audit machinery that requires independent review. MLS brings standardized security analysis and stronger guarantees that PEEP explicitly does not provide. A comparison implementation or a requirement for forward secrecy/post-compromise security would justify revisiting this choice.
