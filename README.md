<!-- BEGIN REVIEW S3: Shorten the overview and document map -->
# PEEP: Paul's End-to-end Encryption Proposal

Paul's End-to-end Encryption Proposal (PEEP) for atproto spaces. **Incomplete.**

Users publish device public keys publicly. Spaces establish which accounts may participate. Each participating user publishes an in-space declaration selecting the exact device keys they want to use, and key issuers authenticate those selections before releasing grants.

Approved devices encrypt and decrypt locally. Servers store ciphertext, encrypted grants, public key publications, and permissioned declarations/evidence. The draft is not yet a complete interoperable enrollment protocol; candidate mechanisms in the TODOs are not selected requirements.

| Document | Contents |
| --- | --- |
| [Core](core.md) | Grants, encryption formats, rotation, and recovery. |
| [Device Enrollment](device-enrollment.md) | Public keys, declarations, and trust requirements. |
| [TODOs](TODOs.md) | Open decisions, validation, and deferred extensions. |

This is a discussion draft; enrollment authentication and bootstrap are unresolved.

Future work could support AppView enrollment when the backend is a trusted member.
<!-- END REVIEW S3 -->
