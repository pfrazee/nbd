# PEEP: Paul's End-to-end Encryption Proposal

Paul's End-to-end Encryption Proposal (PEEP) for atproto spaces. **Incomplete.**

Users publish device public keys publicly. The space host is trusted to establish which accounts may participate and to order key epochs. Each participant declares the complete set of exact device keys selected for each space; an already accepted device signs the declaration to approve that same-account selection. Any currently eligible participant's enrolled device may issue grants for keys it holds. Spaces permit trust on first use (TOFU) by default or require each client to verify a device before granting it a key or accepting a key from it. Clients reuse private local trust records across spaces and publish device-signed grants with space-specific evidence in their own in-space repos. Each grant is also its audit record, retained indefinitely and available through direct sync under normal Spaces access rules.

Clients can bootstrap from an authenticated complete declaration, then validate updates against their remembered state; full historical replay is not required before operation. Current members' selected devices encrypt and decrypt locally and may receive all retained historical keys, including keys for pre-join content. Servers store ciphertext, encrypted grants, public key publications, and permissioned declarations/evidence. Independent verification can prevent PDS key substitution; TOFU allows initial substitution, with detection conditional on the affected client receiving evidence and checking its authorization history. Approvals are reusable without automatic expiry. Device revocation applies across spaces when learned; removal from one space does not revoke the device's binding elsewhere. No bounded revocation delay is promised.

| Document | Contents |
| --- | --- |
| [Core](core.md) | Grants, encryption formats, rotation, and recovery. |
| [Device Enrollment](device-enrollment.md) | Public keys, declarations, trust, and auditing. |
| [Protocol Details](protocol.md) | Encodings, evidence, host integration, and client state procedures. |
| [TODOs](TODOs.md) | Integration and validation work, plus deferred extensions. |

This is a discussion draft with baseline formats specified, pending transport integration, byte-exact interoperability vectors, and independent security validation. Each epoch binds the rotation events it addresses; later grants must enforce those restrictions. This does not prove that a key was never leaked or that every writer has switched.

Future work could support AppView enrollment when the backend is a trusted member.
