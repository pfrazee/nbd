# PEEP: Paul's End-to-end Encryption Proposal

Paul's End-to-end Encryption Proposal (PEEP) for atproto spaces. **Incomplete.**

Users publish device public keys publicly. Spaces establish which accounts may participate. Each participant declares their exact device keys. Issuers accept bindings through trust on first use (TOFU) or independent verification, and publish device-signed grant evidence in their own in-space repos for participants to audit through direct sync.

Selected devices encrypt and decrypt locally. Servers store ciphertext, encrypted grants, public key publications, and permissioned declarations/evidence. Independent verification can prevent PDS key substitution; TOFU allows initial substitution, with detection conditional on the affected client receiving evidence and checking its authorization history. Revocation freshness is a separate guarantee.

| Document | Contents |
| --- | --- |
| [Core](core.md) | Grants, encryption formats, rotation, and recovery. |
| [Device Enrollment](device-enrollment.md) | Public keys, declarations, trust, and auditing. |
| [TODOs](TODOs.md) | Open decisions, validation, and deferred extensions. |

This is a discussion draft, not yet an interoperable protocol. Approval, bootstrap, and audit formats remain unresolved.

Future work could support AppView enrollment when the backend is a trusted member.
