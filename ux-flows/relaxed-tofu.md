# PEEP UX Flows: Relaxed TOFU

Informative. A presentation of [TOFU](tofu.md) spaces (`tofu-permitted` [policy](../core.md#device-verification-policy)) with the minimum user-facing security process the specification allows. The protocol is unchanged: relaxed and full TOFU clients interoperate in the same spaces. See also [Verified-only](verified-only.md). A "device" is an app installation.

## What protects these spaces

The same as [TOFU](tofu.md#what-protects-these-spaces): devices are trusted on first use, unapproved changes are accepted as visible [TOFU key changes](../device-enrollment.md#local-trust), and the defense against a malicious PDS is detection through [auditing](../audit.md#direct-sync) and notices. Relaxed presentation keeps every required notice but makes routine ones quiet, so detection depends more on users noticing timeline lines and on the account holder's own alarms.

## What stays and what goes

| Still required | Omitted or hidden |
| --- | --- |
| Admission explains that new members see retained history ([host state](../core.md#trusted-host-state)). | Policy choice at creation: every space is TOFU. |
| Member additions, removals, readmissions, and accepted TOFU key changes are visibly surfaced ([host state](../core.md#trusted-host-state)). | Trust badges and the Verify action. |
| Joining shows the resulting device set and allows changes ([enrollment preferences](../device-enrollment.md#enrollment-preferences)). | Recovery kit prompts: users without verified relationships are never prompted. |
| Linking a device shows the exact device and spaces ([batch enrollment](../device-enrollment.md#declarations)). | The future-spaces question while linking: new devices default to *Automatically*, changeable in settings. |
| Own-account device notices with removal, and alarms for devices the account never approved ([auditing](../audit.md#direct-sync)). | The sole-holder indicator and device-list detail. |
| A way to inspect observed grants to any member ([auditing](../audit.md#direct-sync)), which can live deep in settings. | |
| Reporting known loss of local state ([recovery](../device-enrollment.md#recovery)). | |

## Creating a space

1. **"New space" form:** name and optional members. No security choices.
2. **"Creating on 2 devices · Change."** Creating the space is the confirmation.
3. **"Securing space…"** until the host accepts epoch 1; drafts persist and retry quietly.
4. **Space opens.**

## Adding a member

Alice adds Bob.

1. **Invite Bob:** "Bob will be able to read everything already posted here." One line in the invite sheet satisfies the history requirement.
2. **Timeline:** "Alice added Bob."
3. **Bob taps "Join Book club" · "Joining on 2 devices · Change."**
4. **Bob waits briefly:** "Getting access…" while members' devices grant [in the background](tofu.md#keeping-spaces-available). If nothing arrives, members get "Bob is waiting to join Book club."
5. **Unlock.** Devices pin each other on first sight. No badges, no verification prompts.
6. **Key changes appear as a timeline line:** "Bob's devices changed." No modal, no action required. This is the one routine security notice other members see.

## Adding a device

1. **Laptop:** "Link this device" with a QR code.
2. **Phone:** scan, then "Enable *Alice's Laptop* in: ☑ Book club ☑ Work ☑ Family", all checked by default. The phone grants immediately.
3. **Alice's other devices:** "New device: *Alice's Laptop*, added from *iPhone*. Not you? Remove it." This notice and its removal action are required; they are how Alice catches a compromised device adding an attacker's.
4. **Other members:** nothing.

## Losing every device

1. **"Restore from backup"** or **"Start fresh"**. Starting fresh is the expected path.
2. **Members see "Alice's devices changed"** and keep sharing with her. Alice's new device pins everyone again.
3. **History mostly returns** as members re-grant keys. Copy: "Messages only you had may not come back."
4. **If someone had verified Alice** in another app, their client blocks until she is re-verified. A relaxed app without verification shows nothing to Alice; other members still share with her.

## Creating a space from an existing space

"New space from Book club…" copies the members, not the messages. Each member taps Join once, and existing pins carry over.

## Alarms

Relaxed presentation does not soften these. They are integrity alarms, not routine notices:

- **A device you don't recognise:** a grant to, or a record for, a device of the user's account that no device of theirs approved ([auditing](../audit.md#direct-sync)). Copy: "A device you don't recognise may have access to your spaces. Review devices."
- **Host integrity:** a space reporting a different verification policy than first observed ([policy](../core.md#device-verification-policy)).

## Verified-only spaces

A relaxed app cannot exchange keys in a [verified-only](verified-only.md) space without verification UI. It either supports verification for those spaces only, or lists them as unavailable: "This space requires verified devices. Open it in an app that supports verification."
