# PEEP UX Flows: Verified-only

Informative. User-facing flows for spaces whose [verification policy](../core.md#device-verification-policy) is `verified-only`. See also [TOFU](tofu.md) and [Relaxed TOFU](relaxed-tofu.md). A "device" is an app installation.

## What protects these spaces

Keys pass only between devices that have verified each other, directly or through same-account approval rooted in a verified device. A malicious PDS cannot substitute keys between verified devices. The cost is that every member verifies at least one other member once; verification is then reused across all spaces.

The policy is chosen at creation and [fixed for the life of the space](../core.md#device-verification-policy). Space info says: "Only verified devices can read this space."

## UI vocabulary

- **Space policy:** *Require verified devices*. A space that allows unverified devices is a different space; a group switching policy creates a new one.
- **Trust badge** per device: *Verified* or *Verified via \<their other device\>* (approval-derived). Unverified devices appear only as "Waiting for verification".
- **Verify:** one action with three channels: scan in person, share a 6-digit code, or send a link.

## Creating a space

1. **"New space" form:** name, optional members, and *Require verified devices*. The form says the choice is permanent: "You can't change this later. To change it, create a new space."
2. **"Creating on 3 devices · Change."** The device set comes from each device's [enrollment preference](../device-enrollment.md#enrollment-preferences): *Automatically* devices are included, *Ask* devices appear unchecked, *Never* devices are omitted. This device is always included. Creating the space is the confirmation.
   - *Under the hood:* the host stores configuration revision 1 and the creator's eligible membership decision. On the app's first PEEP use, it generates keypairs and publishes its [device record](../device-enrollment.md#bindings-and-publication). It signs the initial [declaration](../device-enrollment.md#declarations) with `previous: []`.
3. **"Securing space…":** the epoch 1 key is generated and the [activation request](../core.md#client-activation-states) submitted. Posting waits for acceptance. On network loss, the draft persists and the exact request is retried; the UI does not report failure while the outcome is unknown.
4. **Space opens.** The creator's other devices receive grants in the background; they are verified through pairing.

**Sole-holder indicator:** whenever this device is the only known holder of the active key (it has seen no grant of that key to any other binding), show a quiet note: "Only this device can currently read this space." It disappears once another device or member receives the key and links to "Add a device".

## Adding a member

Admin Alice adds Bob.

**Alice:**

1. **Invite Bob.** The confirmation explains that admission includes retained history: "Bob will be able to read everything already posted here." This is [recommended](../core.md#trusted-host-state), and space info also states it; [history wrapping](../core.md#backward-history-wrapping) makes past content part of membership.
2. **Verified invite (optional):** the invitation can open a [verification session](../device-enrollment.md#independent-verification) addressed to Bob and offer its 6-digit code or link to share through another app. Bob enters it when he joins, so inviting and verifying are one step.
3. **Every member sees "Alice added Bob"** in the timeline.

**Bob:**

4. **Notification, then "Join Book club" with "Joining on 3 devices · Change."** One tap. His [enrollment preferences](../device-enrollment.md#enrollment-preferences) choose the devices, and this device signs one declaration for all of them.
5. **Locked until verified: "Verify with any member to unlock,"** with the member list. The space name and members (host data) are visible; content is not. Bob can write drafts locally. If Bob already verified any member's device in another space, there is nothing to do: verification is reused.
6. **Members see "Bob is waiting. Verify Bob."** Any one member suffices, because every session verifies both directions. The admin has no special role.

**Verifying:**

7. **"Verify" offers three channels:**
   - **Scan in person:** one device shows a QR code, the other scans it. One scan; the shower's screen then reads "Bob's phone verified with you."
   - **Share a code:** "Verify Bob" shows a 6-digit PIN, valid for 15 minutes. Read it on a call or send it through another app. Bob's app shows "Alice wants to verify with you. Enter the code she gave you."
   - **Send a link:** the same session as a link, for sending through another app without a call.
8. **Copy rule:** "Don't send this code through Bluesky messages." Whoever sees the secret first can complete the session in Bob's place, and messages pass through the PDS this protects against.
9. **Failure is neutral and final.** A wrong PIN, a used link, or expiry ends that session: "Verification failed. This can happen if the code was mistyped or someone is interfering. Start a new verification." After repeated failures, the app recommends meeting to scan.
10. **Unlock.** With the session complete, the verifying member's device grants Bob the current key, which unlocks all reachable history. Other members' devices that verified Bob, directly or through [trust sync](../device-enrollment.md#own-device-trust-sync) from their owner's other devices, can also grant.

**Reuse:** verification belongs to a device pair, not a space. It extends through approvals: Bob's laptop, approved by his verified phone, shows as *Verified via Bob's phone*. In practice each pair of people verifies once.

**Key changes:** if Bob's keys change without approval from a verified Bob device, every member's client blocks: "Bob's device changed. Verify to continue." Grants to and from that device stop until Bob is re-verified or an approval resolves the [dispute](../device-enrollment.md#independent-verification).

![Adding a member in verified-only: invite with the history warning and a verification code, the timeline line, Bob locked until he verifies with any member, the three channels, the 6-digit code on both sides, a neutral failure, unlocking, and a key change that blocks everyone](images/verified-only-adding-a-member.png)

## Adding a device

Alice gets a new laptop.

1. **Laptop:** install, log in, show "Link this device" with a QR code. Generating keys and publishing the device record grants nothing on its own.
2. **Phone:** Devices → Link → scan. Then "Enable *Alice's Laptop* in: ☑ Book club ☑ Work ☐ Family" ([batch enrollment](../device-enrollment.md#declarations) shows exact spaces and changes). The same screen asks once: "Include *Alice's Laptop* in spaces you join later?" (*Automatically* / *Ask each time* / *Never*).
3. **Pairing transfers [private state](../device-enrollment.md#backup-and-transfer):** Alice's verifications move to the laptop, and [trust sync](../device-enrollment.md#own-device-trust-sync) keeps them current afterwards. The laptop can grant to everyone Alice verified.
4. **The phone grants immediately**; the laptop reads full history. "3 of 4 spaces enabled. Retrying Work…" covers partial progress.
5. **Other members need no ceremony.** Anyone who verified Alice's phone sees the laptop as *Verified via Alice's iPhone*. Device lists show "Alice · 3 devices"; apps may add a subtle indicator for a recent addition, never a gate.
6. **Alice's other devices notify her:** "New device: *Alice's Laptop*, added from *iPhone*, 2 minutes ago. Not you? Remove it." One notice per device, none on the approving phone. Removing it revokes the laptop and rotates affected spaces ([own-account notices](../audit.md#direct-sync)).

![Adding a device in verified-only: the laptop code, batch enrollment, other members seeing the laptop as Verified via Alice's iPhone with no ceremony, and the new-device notice on Alice's iPad](images/verified-only-adding-a-device.png)

## Losing every device

1. **"Restore from backup"** (same keys and state) or **"Start fresh"**. There is currently no other [recovery process](../device-enrollment.md#total-device-loss).
2. **Starting fresh** means [re-verification](../device-enrollment.md#replacement): Alice and each member she exchanges keys with must verify again; one session per contact covers both directions. The new device lists those contacts and opens the sessions from a single screen. Contacts see "Alice has a new device that isn't linked to her old ones. Verify to share with her."
3. **History mostly returns:** members re-grant keys they hold. Content is lost only where Alice's devices held the only copies.
4. Copy is honest: "Resetting your account password can't restore encrypted access."

## Creating a space from an existing space

PEEP has no parent/child relationship; each space is cryptographically independent.

| Carries over | Doesn't carry over |
| --- | --- |
| [Device trust](../device-enrollment.md#local-trust): pairs verified anywhere stay verified. | Membership: each admission is a separate host decision (the app can prefill it). |
| Public device records. | Declarations: each member joins and selects devices again. |
| | Keys and history: the new space starts at epoch 1; parent content is not readable through it. |

1. **"New space from Book club…"** prefills the parent's members. Copy: "Members are copied; messages aren't." This is also how a TOFU group moves to verification: "Create a verified-only space from this one."
2. **Creator:** as in [creating a space](#creating-a-space).
3. **Each member taps Join once.** Pairs verified in the parent or any other space unlock immediately. Members who were only TOFU-pinned in a TOFU parent must verify with one member, as for a new member.

![Creating a space from an existing space in verified-only: creating a verified-only space from a TOFU one, verified pairs joining immediately, and TOFU-only members asked to verify with any member](images/verified-only-creating-from-existing.png)

## Keeping spaces available

Delivery needs a running key holder that has verified the recipient.

1. **Background issuing.** Key requests and new declarations trigger push notifications to members' devices, which grant without the app being opened ([distribution](../core.md#distribution-scheduling)). On iOS, a visible notification's service extension does the work, which requires installation keys readable after first unlock ([platform notes](../device-enrollment.md#platform-notes)).
2. **Visible prompts.** If no grant arrives within a short window, the requester's app asks members to open the space: "Bob is waiting to join Book club. Open to share access."
3. **Always-on devices.** A desktop, home server, or hosted agent selected as an ordinary device. It learns its owner's verifications through [trust sync](../device-enrollment.md#own-device-trust-sync), so it can grant to anyone its owner verified. Settings copy: "Keep your spaces available from this computer." Hosted agents say who operates them, because they hold keys.

![Keeping spaces available in verified-only: background issuing by a device that already verified the recipient, the visible prompt, and always-on device settings](images/verified-only-keeping-spaces-available.png)
