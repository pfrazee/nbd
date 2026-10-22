# PEEP UX Flows: TOFU

Informative. User-facing flows for PEEP spaces, which all use [trust on first use](../core.md#device-trust). See also [Relaxed TOFU](relaxed-tofu.md), which presents the same protocol with minimal security UI. A "device" is an app installation.

## What protects these spaces

A person's devices are trusted on first contact; after that, a new device is accepted only if one of that person's existing devices linked it ([local trust](../device-enrollment.md#local-trust)). A malicious PDS can substitute keys at first contact, and a substituted device that any member accepts can read the whole space; the defense there is detection after the fact, through [auditing](../audit.md#direct-sync) of grants to your own account. Later, a PDS cannot add a device on its own. The cost is that losing every device can't be recovered from.

There is no device verification. Members share one key, so one member verifying another would not protect the space: anyone who accepted a substituted device could pass it the key ([why](../core.md#device-trust)). Verified-only spaces are a [deferred extension](../TODOs.md#deferred-extensions). Space info says: "Devices in this space aren't verified. Changes are shown, but not blocked."

## UI vocabulary

- **Device list** per member: each device and when it was added. No trust badges and no Verify action.

## Creating a space

1. **"New space" form:** name and optional members. No security choices.
2. **No device choice.** Every device on the account can read every space the account belongs to ([approvals](../device-enrollment.md#approvals)), so creating asks nothing about devices.
   - *Under the hood:* the host stores configuration revision 1 and the creator's eligible membership decision. On the app's first PEEP use, it generates keypairs and publishes its [device record](../device-enrollment.md#bindings-and-publication).
3. **No extra wait.** The space key is generated on this device before the space is created, and its [commitment](../core.md#key-generation) is part of the creating configuration, so posting can start as soon as creation succeeds.
4. **Space opens.** The creator's other devices get the key when they open it; installations of the same app get it right away.

**Sole-holder indicator:** whenever this device is the only known holder of the space key (it has seen no grant of that key to any other binding), show a quiet note: "Only this device can currently read this space." It disappears once another device or member receives the key and links to "Add a device".

![Creating a space in TOFU: the new space form, "Securing space…", the sole-holder note, and space info](images/tofu-creating-a-space.png)

## Adding a member

Admin Alice adds Bob.

**Alice:**

1. **Invite Bob.** The confirmation explains that admission includes retained history: "Bob will be able to read everything already posted here." This is [recommended](../core.md#trusted-host-state), and space info also states it; a space has [one key](../core.md#key-generation), so past content is part of membership.
2. **Every member sees "Alice added Bob"** in the timeline.

**Bob:**

3. **Notification, then "Join Book club."** One tap, no device list. His other devices request the key when he opens the space on them.
4. **Brief locked state: "Waiting for a member's device…"** His app publishes a [key request](../core.md#key-requests). Bob can write drafts locally. Members' devices grant [in the background](#keeping-spaces-available), usually within seconds.
5. **Unlock.** Carol's device pins Bob's device on first sight and grants; Bob's device pins Carol's device and accepts. One grant unlocks all reachable history.

**Afterwards:**

6. **Device lists:** each sees the other's devices, with no badges or Verify action.
7. **Unlinked devices:** if a new Bob device appears without a link from a Bob device already pinned, members' apps don't share keys with it, and there is no override. Device lists show "Bob has a device that isn't linked to his others," which can mean Bob skipped linking or someone is impersonating him.
8. **Alarms:** Bob's client alarms if it finds a grant to a device he never approved, or records in his repo for devices he doesn't recognise ([auditing](../audit.md#direct-sync)): "A device you don't recognise may have access to *Book club*." These are the main defense against substitution, so they are prominent.

![Adding a member in TOFU: invite with the history warning, the timeline line, Bob joining, the brief locked state, a key change notice, and the own-account alarm](images/tofu-adding-a-member.png)

## Adding a device

Alice gets a new laptop.

1. **Laptop:** install, log in, show "Link this device" with a QR code. Until it is linked, members' apps that already know Alice won't share keys with it ([local trust](../device-enrollment.md#local-trust)); the screen says so.
2. **Phone:** Devices → Link → scan, then one confirmation: "Link *Alice's Laptop*? It will be able to read all your spaces. Only link devices you own." The phone signs an [approval](../device-enrollment.md#approvals); there is no list of spaces.
3. **Pairing transfers [private state](../device-enrollment.md#backup-and-transfer):** pins move to the laptop so it does not pin everyone afresh. Afterwards each device pins on its own.
4. **Spaces open on demand.** When Alice opens a space on the laptop, it requests the key and her phone grants it in the background; the laptop reads full history. Installations of the same app may get keys right away.
5. **Other members:** the laptop is approved by Alice's phone, so they accept it. No timeline notice; device lists show "Alice · 3 devices".
6. **Alice's other devices notify her:** "New device: *Alice's Laptop*, added from *iPhone*, 2 minutes ago. Not you? Remove it." One notice per device, none on the approving phone. Removing it revokes the laptop, which then gets no new keys but keeps those it already received; the notice tells Alice to sign it out at her provider and change her password, which ends its access to spaces. A device Alice never approved means her account or PDS may be compromised, so this notice, unlike an ordinary device removal, also offers to move affected spaces ([own-account notices](../audit.md#direct-sync), [no rotation](../core.md#no-rotation)).

![Adding a device in TOFU: the laptop code, the link confirmation, pins transferring, the device list other members see, and the new-device notice on Alice's iPad](images/tofu-adding-a-device.png)

## Losing every device

1. **"Restore from backup"** (same keys and state) is the only way back. There is no [recovery process](../device-enrollment.md#total-device-loss) without a backup or a surviving device.
2. **Without one, encrypted spaces are gone for this account.** A fresh install can't be linked, so members' apps that already know Alice won't share keys with it. Copy is honest: "Without a backup or one of your other devices, this account can't get back into its encrypted spaces. Resetting your password won't help."
3. **Members see why Alice is stuck:** "Alice has a device that isn't linked to her others." The app offers no way to accept it.
4. **Prevention is the product.** The app prompts users with one device to add a second device or turn on backup, and settings show how many devices and backups the account has.

## Creating a space from an existing space

PEEP has no parent/child relationship; each space is cryptographically independent. This is also how a group leaves a space it credibly believes is compromised beyond what the host can stop ([replacing a space](../core.md#replacing-a-space)); it is not a response to [removing a member](#removing-a-member-or-device).

| Carries over | Doesn't carry over |
| --- | --- |
| [Device trust](../device-enrollment.md#local-trust): TOFU pins. | Membership: each admission is a separate host decision (the app can prefill it). |
| Public device records and approvals. | |
| | Keys and history: the new space has its own key; parent content is not readable through it. |

1. **"New space from Book club…"** prefills the parent's members. Copy: "Members are copied; messages aren't."
2. **Creator:** as in [creating a space](#creating-a-space).
3. **Each member taps Join once;** existing pins carry over, so grants arrive as soon as their devices request them.

![Creating a space from an existing space in TOFU: the prefilled form, and Bob joining with one tap](images/tofu-creating-from-existing.png)

## Removing a member or device

1. **Removal stops new keys at once.** Removing Carol from Book club takes effect as soon as members' apps and the host learn of it: no new grants to her devices, and the host stops issuing her access. Access she already has expires within minutes, an hour at most ([ending access](../core.md#ending-access)). Nothing is held back; posting continues.
2. **Removing a device takes one more step.** Removing a lost device stops new keys, but the device can keep reading until its access is removed at the account's PDS, which the app can't do yet. The removal confirmation says: "To stop *Alice's Laptop* reading new messages, also sign it out in your account settings at your provider. If someone may know your password, change it." Once it is signed out, its access ends within minutes ([ending access](../core.md#ending-access)).
3. **Copy is honest.** The timeline says "Carol was removed," never that new messages are protected from her. Space info explains: "Carol's devices still hold this space's key. If she got new messages some other way, she could read them" ([no rotation](../core.md#no-rotation)).
4. **No move offered.** Removing, plus signing a device out, is the whole response; the notice does not suggest a new space. Moving lives in space settings for groups that credibly believe the space is compromised beyond what the host can stop ([replacing a space](../core.md#replacing-a-space)).

## Keeping spaces available

1. **Background issuing.** Key requests trigger push notifications to members' devices, which grant without the app being opened ([distribution](../core.md#distribution-scheduling)). On iOS, the visible "Bob joined Book club" notification's service extension does the work, which requires installation keys readable after first unlock ([platform notes](../device-enrollment.md#platform-notes)).
2. **Visible prompts.** If no grant arrives within a short window, the requester's app asks members to open the space: "Bob is waiting to join Book club. Open to share access."
3. **Always-on devices.** A desktop, home server, or hosted agent linked as an ordinary device grants whenever it is running. Settings copy: "Keep your spaces available from this computer." Hosted agents say who operates them, because they hold keys.

![Keeping spaces available in TOFU: background issuing behind a lock-screen notification, the visible prompt to open the space, and always-on device settings](images/tofu-keeping-spaces-available.png)
