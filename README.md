# PEEP: Paul's End-to-end Encryption Proposal

End-to-end encryption for atproto Spaces. **Discussion draft:** baseline decisions are specified; implementation and independent validation remain outstanding.

Users publish device keys publicly and add devices to their account through signed approvals. Eligible devices exchange encrypted space keys through signed grants, which also serve as audit records. Content encryption and decryption happen on clients. The protocol documents use [normative conventions](core.md#conformance-and-validation-results).

## User experience

To get a quick understanding of these specs, see the user experience documentation:

- **[Relaxed](ux-flows/relaxed-tofu.md)** - How applications work when they're not overly paranoid.
- **[Trust on First Use](ux-flows/tofu.md)** - A more security-minded experience.

## Specs

Read the specifications below:

| Document | Defines |
| --- | --- |
| [Security goals](security-goals.md) | What PEEP guarantees, what it deliberately does not, and the bar for review. |
| [Core](core.md) | Trust boundaries, [protocol conventions](core.md#protocol-conventions), [key grants](core.md#key-grants), [content encryption](core.md#content-encryption), and the [space key lifecycle](core.md#space-key-lifecycle). |
| [Device enrollment](device-enrollment.md) | Bindings, [trust on first use](device-enrollment.md#local-trust), [approvals](device-enrollment.md#approvals), [revocation](device-enrollment.md#revocation-and-freshness), [recovery](device-enrollment.md#recovery), and [platform notes](device-enrollment.md#platform-notes). |
| [Auditing](audit.md) | Evidence, publication, retention, historical validation, and sync. |
| [Rationale](rationale.md) | Design choices and comparison with MLS, Megolm, Signal sender keys, and Keybase team keys (informative). |
| [Remaining work](TODOs.md) | Implementation, [validation cases](TODOs.md#validation-cases), and deferred extensions. |
| [Executable model](model/README.md) | Local trust in Python, with adversarial cases, random walks, and mutation testing (informative). |
| [Tamarin model](formal/README.md) | Symbolic proofs of secrecy and authentication under compromise and a malicious PDS (informative). |
| [Prototype](prototype/README.md) | Multi-device simulation with a playable UI; start with its [reviewer guide](prototype/README.md#for-reviewers) (informative). |
