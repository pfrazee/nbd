# PEEP: Paul's End-to-end Encryption Proposal

End-to-end encryption for atproto Spaces. **Discussion draft:** baseline decisions are specified; implementation and independent validation remain outstanding.

Users publish device keys publicly and select them through signed in-space declarations. Eligible devices exchange encrypted space keys through signed grants, which also serve as audit records. Content encryption and decryption happen on clients. The protocol documents use [normative conventions](core.md#conformance-and-validation-results).

## User experience

To get a quick understanding of these specs, see the user experience documentation:

- **[Relaxed](ux-flows/relaxed-tofu.md)** - How applications work when they're not overly paranoid.
- **[Trust on First Use](ux-flows/tofu.md)** - A more security-minded experience.
- **[Verified-only](ux-flows/verified-only.md)** - A very careful security experience.

## Specs

Read the specifications below:

| Document | Defines |
| --- | --- |
| [Core](core.md) | Trust boundaries, [protocol conventions](core.md#protocol-conventions), [key grants](core.md#key-grants), [content encryption](core.md#content-encryption), and [rotation](core.md#rotation). |
| [Device enrollment](device-enrollment.md) | Bindings, verification, declarations, [history and revocation](device-enrollment.md#enrollment-history), [recovery](device-enrollment.md#recovery), and [platform notes](device-enrollment.md#platform-notes). |
| [Auditing](audit.md) | Evidence, publication, retention, historical validation, and sync. |
| [Rationale](rationale.md) | Design choices and comparison with MLS, Megolm, Signal sender keys, and Keybase team keys (informative). |
| [Remaining work](TODOs.md) | Implementation, [validation cases](TODOs.md#validation-cases), and deferred extensions. |
