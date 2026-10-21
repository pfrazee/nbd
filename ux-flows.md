# PEEP: UX Flows

Informative. This document sketches user-facing flows implied by [Core](core.md) and [Device Enrollment](device-enrollment.md), and records rough edges for discussion. A "device" is an app installation.

## UI vocabulary

- **Space policy** (host): *Allow unverified devices* (`tofu-permitted`, default) or *Require verified devices* (`verified-only`). Chosen at creation and [fixed for the life of the space](core.md#device-verification-policy).
- **Trust badge** per device: *Unverified* (TOFU), *Verified*, or *Verified via \<their other device\>* (approval-derived).

## 1. Creating a new space

1. **"New space" form**: name, optional members, and *Allow unverified devices* / *Require verified devices*. The form says the choice is permanent: "You can't change this later. To change it, create a new space."
2. **"Creating on 3 devices · Change."** The device set comes from each device's [enrollment preference](device-enrollment.md#enrollment-preferences): *Automatically* devices are included, *Ask* devices appear unchecked, *Never* devices are omitted. This device is always included. Creating the space is the confirmation.
   - *Under the hood:* the host stores configuration revision 1 and the creator's eligible membership decision. On the app's first PEEP use, it generates keypairs and publishes its [device record](device-enrollment.md#bindings-and-publication). It signs the initial [declaration](device-enrollment.md#declarations) with `previous: []`.
3. **"Securing space…"**: the epoch 1 key is generated and the [activation request](core.md#client-activation-states) submitted. Posting waits for acceptance. On network loss, the draft persists and the exact request is retried; the UI should not report failure while the outcome is unknown.
4. **Space opens.** Other devices receive grants in the background when they come online.

**TOFU vs verified:** nearly identical. Only the creator's account is involved and its devices trust each other through pairing; policy matters once someone else joins.

**Sole-holder indicator:** whenever this device is the only known holder of the active key (it has seen no grant of that key to any other binding), show a quiet, informational note: "Only this device can currently read this space." It disappears once another device or member receives the key, usually within minutes of creation. It links to "Add a device", and to a [recovery kit](#recovery-kits) only where kits are already suggested. The same rule covers spaces whose other holders have all left. A recovery kit selected at creation receives epoch 1 in the first grant pass, so the note never appears.

## 2. Adding a member

Admin Alice adds Bob.

**Alice:**

1. **Invite Bob.** The confirmation MUST explain that admission includes retained history, e.g. "Bob will be able to read everything already posted here." There is no "only from now on" option; [history wrapping](core.md#backward-history-wrapping) makes past content part of membership.
2. **Every member sees "Alice added Bob"** in the timeline (required by [host state rules](core.md#trusted-host-state)).

**Bob:**

3. **Notification, then "Join Book club" with "Joining on 3 devices · Change."** One tap. The device set comes from his [enrollment preferences](device-enrollment.md#enrollment-preferences), and this device signs one declaration for all of them.
4. **Locked state: "Waiting for a member's device…"** The space name and member list (host data) are visible; content is not. His app publishes a [key request](core.md#key-requests). Bob can write drafts locally; they send when the space unlocks.
   - **Background issuing:** members' devices are woken by a push notification and grant [in the background](core.md#distribution-scheduling). On iOS, the visible "Bob joined Book club" notification is the wake-up: its notification extension issues the grant. Usually Bob unlocks within seconds without anyone opening the app.
   - **Visible prompt:** if nothing arrives within a short window, members get "Bob is waiting to join Book club. Open to share access." Opening the app grants immediately.
   - **Always-on devices:** a member's desktop, home server, or hosted agent grants whenever it is running.
   - Any eligible member's device can fulfil the request, not only Alice's. Bob is notified when the space unlocks.

**TOFU path:**

5. Carol's device sees Bob's declaration, pins his device on first sight, and issues a grant. Bob's device pins Carol's device on first sight and accepts. One grant unlocks all reachable history.
6. Each shows the other as *Unverified* with an optional, non-blocking Verify action. Verifying later upgrades future decisions only.
7. **Key changes:** if Bob's keys later change without approval from a Bob device already pinned, clients that only pinned him by TOFU accept the change as a [TOFU key change](device-enrollment.md#local-trust) and show a notice: "Bob's devices changed." Nothing blocks. Clients that verified Bob block until he is re-verified: "Bob's device changed. Verify to continue." Pins are never silently replaced.
8. **What protects TOFU spaces:** detection, not prevention. Bob's client alarms if it finds grants to a device he never selected, or records in his repo for devices he doesn't recognise ([auditing](audit.md#direct-sync)). Members see every unapproved device change. Copy for space info: "Devices in this space aren't verified. Changes are shown, but not blocked."

**Verified-only path:**

5. **Verify with any one member.** The issuer checks the recipient and the recipient checks the issuer, but every [verification session](device-enrollment.md#independent-verification) establishes both directions at once.
   - Bob sees "Verify with any member to unlock," with the member list.
   - Members see "Bob is waiting. Verify Bob."
6. **"Verify" offers three channels:**
   - **Scan in person:** one device shows a QR code, the other scans it. One scan; the shower's screen then reads "Bob's phone verified with you."
   - **Share a code:** "Verify Bob" shows a 6-digit PIN, valid for 15 minutes. Read it on a call or send it through another app. Bob's app shows "Alice wants to verify with you. Enter the code she gave you."
   - **Send a link:** the same session as a link, for sending through another app without a call.
7. **Failure is neutral and final.** A wrong PIN, a used link, or expiry ends that session: "Verification failed. This can happen if the code was mistyped or someone is interfering. Start a new verification." After repeated failures, the app recommends meeting to scan.
8. With the session complete, X's device issues the grant automatically.
9. **Payoff:** verification belongs to a device pair, not a space, so it is reused everywhere. It extends through approvals: Bob's laptop, approved by his verified phone, shows as *Verified via Bob's phone*. It also reaches the verifier's own devices through [trust sync](device-enrollment.md#own-device-trust-sync): after Alice verifies Bob on her phone, her desktop and always-on devices can grant to him too. In practice each pair of people verifies once.

**Copy rule:** PINs and links must not be sent through Bluesky DMs or posts. Whoever sees the secret first can complete the session in Bob's place, and DMs pass through the PDS this protects against.

**Verified invites:** in a verified-only space, Alice's invitation can open a verification session addressed to Bob and offer the PIN or link to share through another app. Bob enters it when he joins, so the invite and the verification are one step.

The admin has no special key authority; adding Bob does not make Alice the verifier or issuer.

## 3. Adding a device as an existing member

Alice gets a new laptop.

**Old device available:**

1. **Laptop:** install, log in, show "Link this device" with a QR code. Generating keys and publishing the device record grants nothing on its own.
2. **Phone:** Devices → Link → scan. Then "Enable *Alice's Laptop* in: ☑ Book club ☑ Work ☐ Family." Selection is per space, so this is a real choice; [batch enrollment](device-enrollment.md#declarations) MUST show exact spaces and changes. The phone signs one declaration per space. The same screen asks once about the future: "Include *Alice's Laptop* in spaces you join later?" (*Automatically* / *Ask each time* / *Never*). The answer becomes the laptop's [enrollment preference](device-enrollment.md#enrollment-preferences) and syncs to Alice's other devices.
3. **Pairing transfers [private state](device-enrollment.md#backup-and-transfer):** pins and verification status move to the laptop so it does not TOFU everyone afresh. Afterwards, [trust sync](device-enrollment.md#own-device-trust-sync) keeps the devices current as Alice verifies people on either one. Provenance is preserved.
4. **The phone grants immediately** for each space's current epoch; the laptop reads full history. The laptop accepts because it paired directly with the phone.
5. **Partial progress:** "3 of 4 spaces enabled. Retrying Work…"
6. **Alice's other devices notify her:** "New device: *Alice's Laptop*, added from *iPhone*, 2 minutes ago. Not you? Remove it." One notice per device, not per space, and none on the approving phone. Removing it revokes the laptop and rotates affected spaces. This catches a compromised device approving an attacker's device, which only Alice can recognise ([own-account notices](audit.md#direct-sync)).

**TOFU vs verified:** no difference for Alice. For other members:

- If they verified Alice's phone, the laptop is automatically *Verified via approval* and works in verified-only spaces without a new ceremony.
- If they pinned the phone by TOFU, the laptop is trusted on that TOFU basis.
- Other members get no timeline notice for approved additions. Alice's device list shows it: "Alice · 3 devices", with *Laptop* added 2 days ago and *Verified via Alice's iPhone*. Apps may add a subtle indicator in verified-only spaces, never a gate.

**No surviving device (phone lost):**

- **Restore from backup** (same keys and state), **use a recovery kit**, or **start fresh**.
- **With a [recovery kit](#recovery-kits):** "Enter your recovery code." The new phone restores Alice's verifications of others, recovers every key granted to the kit, and approves itself. Members who verified Alice accept the new phone as *Verified via approval*; nobody re-verifies. Finish with "Your old devices have been removed" and "Save a new recovery kit?"
- **Starting fresh in TOFU spaces is cheap.** Members who only pinned Alice by TOFU accept her new device as a key change and see "Alice's devices changed." Alice's new device pins everyone again. She loses no protection she had at first contact.
- **Starting fresh is expensive where Alice is verified.** Anyone who verified Alice, and everyone in verified-only spaces, must [re-verify](device-enrollment.md#replacement) her with one verification session each. Copy: "Alice has a new device that isn't linked to her old ones. Verify to share with her." Alice's new device lists those contacts and opens one verification session per contact from a single screen.
- **History mostly returns:** members re-grant keys they hold. Content is lost only where Alice's devices held the only copies.
- Copy must be honest: "Resetting your account password can't restore encrypted access."

## 4. Creating a space from an existing space

PEEP has no parent/child relationship; each space is cryptographically independent.

| Carries over | Doesn't carry over |
| --- | --- |
| [Device trust](device-enrollment.md#local-trust) (TOFU pins, verified status): no re-verification. | Membership: each admission is a separate host decision (the app can prefill it). |
| Public device records. | Declarations: each member enables each device again, per space. |
| | Keys and history: the new space starts at epoch 1 with empty history; parent content is not readable through it. |
| | Policy: the app can copy the parent's policy, and a derived space is how a group changes policy. |

1. **"New space from Book club…"** prefills the parent's members and policy. Copy: "Members are copied; messages aren't."
2. **Creator:** as in [flow 1](#1-creating-a-new-space); enrollment preferences choose the devices.
3. **Each member:** "Alice added you to *Book club – spoilers*." Each taps **Join** once; [enrollment preferences](device-enrollment.md#enrollment-preferences) choose their devices, and their other devices unlock through background issuing. Being added alone enrolls nothing, so members who never tap Join stay locked.
4. **Key exchange is fast.** Pairs verified in the parent are already verified; even in a verified-only space, grants arrive as soon as a member's declaration lands.


**Live mirroring** (true sub-spaces) would be host-side; PEEP consumes the resulting membership decisions. A parent removal would remove the account from every child, each of which must [rotate](core.md#triggers).

## Recovery kits

A [recovery binding](device-enrollment.md#recovery-bindings) is optional and is suggested only where losing every device would be costly. Users in TOFU-only situations never see a prompt: a [TOFU key change](device-enrollment.md#local-trust) already makes starting fresh cheap.

- **When to suggest:** after the user's first successful verification, when joining or creating a verified-only space, or on learning someone verified them. Copy: "You've verified people. Save a recovery kit so you won't need to verify them again if you lose all your devices." Dismissing it is permanent until the situation changes. Settings always offers it.
- **Setup:** show the code once, ask the user to write it down or save it in a password manager, and confirm a few words. Then "Use the kit in: ☑ Work (verified) ☑ Family (verified) ☐ Book club", defaulting to verified-only spaces. The app keeps no copy of the code.
- **Other members** see one more device for the user, approved by an existing one. It needs no attention.
- **If the code may be exposed:** "Replace recovery kit" revokes the old one and creates a new one, which rotates the affected spaces.

## Keeping spaces available

Delivery needs a running key holder. Applications layer three mechanisms:

1. **Background issuing.** Key requests and new declarations trigger push notifications to members' devices, which run grant authorization and publish grants without the app being opened. iOS uses a notification service extension behind a visible notification; this requires installation keys to be readable after first unlock ([platform notes](device-enrollment.md#platform-notes)).
2. **Visible prompts.** If no grant arrives within a short window, the requester's app asks members to open the space.
3. **Always-on devices.** A desktop, home server, or hosted agent selected as an ordinary device. Communities can run one under an admin account. In verified-only spaces it relies on [own-device trust sync](device-enrollment.md#own-device-trust-sync) to learn its owner's verifications. Settings copy: "Keep your spaces available from this computer." Hosted agents should say who operates them, because they hold keys.

## Rough edges

| # | Issue | Where | Status |
| --- | --- | --- | --- |
| UX-1 | **Locked until another member is online.** No server can hand out keys; a new member or device waits for an eligible holder. | Flows 2, 4 | Mitigated: [background issuing](core.md#distribution-scheduling) on push, visible member prompts as fallback, and always-on devices made viable in verified-only spaces by [own-device trust sync](device-enrollment.md#own-device-trust-sync). A space whose holders are all offline and unreachable by push still waits. |
| UX-2 | **Verified-only verification is mutual and heavy.** Each direction needed its own check, both with the same member, and remote checks meant comparing 64 characters. | Flow 2 | Addressed: single-use mutual [verification sessions](device-enrollment.md#independent-verification) over QR, link, or 6-digit PIN; the static code is removed. |
| UX-3 | **Every space needs a separate opt-in from each member**, including spaces derived from an existing one. | Flows 2, 4 | Addressed: per-device [enrollment preferences](device-enrollment.md#enrollment-preferences) reduce joining to one Join tap with no device questions. Joining itself stays explicit; auto-join rules are [deferred](TODOs.md#deferred-extensions). |
| UX-4 | **Losing every device forces re-verification**, and content where the user held the only key copies is lost. | Flow 3 | Addressed: in TOFU spaces, members accept the new device as a surfaced [TOFU key change](device-enrollment.md#local-trust). Where verification matters, an optional [recovery kit](#recovery-kits) restores trust decisions and keys and approves the new device; without one, re-verification starts from a single screen. |
| UX-5 | **Joining always includes full history.** "From now on" requires a new space. | Flow 2 | Accepted by design: history cuts would need join-time rotations in only some spaces, a likely source of failed implementations. Spaces wanting joiners without history start a new space. |
| UX-6 | **Other members aren't told about device additions.** | Flow 3 | Addressed: the account holder's own devices [notify them](audit.md#direct-sync) of every device change they didn't approve, with removal; unapproved TOFU key changes are shown to everyone; approved additions appear passively in device lists. Users with no honest device online get no notice. |
| UX-7 | **Sole key copy at creation.** Until a second device or backup holds epoch 1, losing the creating device loses that content. | Flow 1 | Accepted by design: the window closes when any other device or member receives the key, only content posted while alone is at risk, and writes resume through availability recovery. Closing it fully would need server escrow. A sole-holder indicator makes it visible; a second device, backup, or optional recovery kit covers it. |
| UX-8 | **Floors don't follow derived spaces.** Clients cannot tell spaces are related without application metadata. | Flow 4 | Resolved by removing local floors: policy is fixed per space, verified relationships already bind in TOFU spaces, and a group wanting verification creates a verified-only space. |
