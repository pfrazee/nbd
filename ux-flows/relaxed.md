# NBD UX Flows: Relaxed

Informative. A presentation of the same NBD spaces as the [Paranoid](paranoid.md) flows, with the minimum user-facing security process the specification allows. The protocol is unchanged: relaxed and paranoid clients interoperate in the same spaces. A "device" is an app installation.

## What protects these spaces

The same as [Paranoid](paranoid.md#what-protects-these-spaces): devices are trusted on first contact, later devices must be [linked](../device-enrollment.md#local-trust), removing a device takes a separate approval at the provider, and the defense against first-contact substitution by a malicious PDS is detection through [auditing](../audit.md#direct-sync). Only the member who [invited](../core.md#invites) someone shares with their devices before a 3-day wait, and only devices their app met as a first contact, not a reset; every other member's app waits 3 days first ([grant standing](../device-enrollment.md#grant-standing)), so a newcomer who first meets a taken-over account holds like everyone else. Relaxed presentation keeps every required notice but makes routine ones quiet, so detection depends more on the account holder's own alarms.

## Flows

### Creating a space

1. **"New space" form:** name and optional members. No security choices.
2. **Space opens** as soon as it is created; the key is generated on this device first. Space info includes "Everyone in this space can read its full history."
3. **Members get the key at once** from the creator's devices, whether the creator first met them through an invite or as fellow members of another space.

![Creating a space: the new space form with no security choices, the space open at once with "You added Bob" and "You added Carol" timeline lines, and space info stating that everyone can read the full history](images/relaxed-creating-a-space.png)

### Adding a member

Alice adds Bob.

1. **Invite Bob.** No history explanation; space info carries it. If Alice's app has never met Bob, it meets his devices now, at the invite ([invites](../core.md#invites)).
2. **Timeline:** "Alice added Bob."
3. **Bob taps "Join Book club".** No device list is shown.
4. **Bob waits briefly:** "Getting access…" while Alice's devices grant [in the background](paranoid.md#keeping-spaces-available). If nothing arrives, members get "Bob is waiting to join Book club." If Alice's devices stay offline, other members' apps share only once their own 3-day waits for Bob end, so Bob's app shows no unlock time. There is no "let him in now" button.
5. **Unlock.** Alice's device, which met Bob's as a first contact, at the invite or before, grants. Other members' devices pin Bob's on first sight and quietly wait ([grant standing](../device-enrollment.md#grant-standing)); they rarely need to grant, since Alice already did. No badges, no verification prompts.
6. **Unlinked devices get nothing.** A new Bob device that no Bob device linked receives no keys, with no override; his device list quietly notes "1 device isn't linked."

![Adding a member, steps 1–3: Alice invites Bob with one tap, Carol sees the "Alice added Bob" timeline line, and Bob taps Join on the invited space](images/relaxed-adding-a-member-1.png)

![Adding a member, steps 4–6: Bob sees "Getting access…" with a draft, members get "Bob is waiting to join Book club" if nothing arrives, Bob reads the history once a grant lands, and Alice's list of Bob's devices quietly notes the device that isn't linked](images/relaxed-adding-a-member-2.png)


### Inviting someone who hasn't installed the app

1. **Invite Bob.** Alice's app finds no devices for him and sends a pending invite, which admits him at once.
2. **Bob installs and joins.** The next time Alice's app syncs, it meets Bob's new device for the first time and grants at once, as if he had been installed when she invited him.
3. **After a week,** the pending invite lapses: Bob is still a member, but Alice's app waits for his device like everyone else's.

![Inviting someone who hasn't installed the app: Alice adds Bob, Carol sees "Alice added Bob", Bob installs and gets the key from Alice at once, and Carol's member list says her device will share with Bob from Friday](images/relaxed-inviting-before-install.png)

### When an invite fails to send

If Alice invites Bob while offline or while her provider is failing writes, her app has already met Bob and saved the invite. It shows "Invite pending, will send when you're back online" and resends the same invite until it lands. Bob is admitted, and Alice's devices share with him, only once it does.

### Adding a device

1. **Laptop:** "Link this device" with a QR code.
2. **Phone:** scan, then one confirmation: "Link *Windows PC* to your account? It will be able to read all your spaces. Only link devices you own." The name is reported by the laptop and is not proof of anything; the warning is what counters tricks to scan an attacker's code. The laptop can read every space; it requests keys as Alice opens them, and the phone grants in the background.
3. **Alice's other devices:** "New device: *Windows PC*. Added from iPhone. Not you?" with **Remove it** and **It was me**. This notice and its removal action are required; they are how Alice catches a compromised device adding an attacker's. **Remove it** sends her to sign the device out at her provider, then asks her to approve removal there and deletes the device, which revokes it, checks that it stays deleted, and suggests changing her password.
4. **Other members:** nothing.
5. **Replacing a phone:** the app doesn't suggest removing the old device afterwards; wiping it is enough. Removing it right away would show a reset to members whose apps haven't caught up ([replacement](../device-enrollment.md#replacement)).

![Adding a device: the laptop shows a linking code, the phone scans it and confirms once with an ownership warning, Alice's iPad gets a new-device notice with Remove it, and other members see nothing](images/relaxed-adding-a-device.png)

![Replacing a phone: the old phone links the new one, the new phone gets every space's key from Alice's devices, the old phone's device list offers no removal prompt, and Bob sees nothing](images/relaxed-replacing-a-phone.png)

### Losing every device

1. **"Restore from backup"** or **"Start over"** ([total device loss](../device-enrollment.md#total-device-loss)).
2. **Starting over:** the app asks the user to approve removal at their provider and deletes the old devices, then shows "People who already know you will wait at least 3 days before sharing with this device," with each space's status as members' apps catch up. Members who never knew the user wait too; only someone whose app first meets the user's new device after the reset can share sooner, by inviting them into a space. Members see a quiet line: "Alice reset her devices. This device will share with her new device from Friday." The removal list is where the user checks their old devices; the app doesn't raise unrecognised-device alarms for them, but still does for any device that remains or appears afterwards.
3. **The hold is not softened.** Relaxed apps can't skip or shorten their own [72-hour wait](../device-enrollment.md#re-enrollment), and an old device that sees itself removed still alarms.

![Losing every device: "Welcome back" offers restore or start over, the new phone lists her old iPhone and iPad and asks whether she recognises them before removing them, it shows each space waiting for members, and Bob sees "Alice reset their devices. This device will share with their new device from Friday."](images/relaxed-losing-every-device.png)

### A new space after someone resets

If someone the creator already knew reset their devices less than 3 days ago, the creator's app is still holding their new device, and a new space doesn't change that. The space waits for the rest of the hold, with a quiet note: "Your device will share with Carol from Friday." Someone else in the space who already shares with Carol's new device can grant instead.

![A new space that waits: Alice starts Garden with Carol, who reset her devices yesterday, the space notes "Your device will share with Carol from Friday," Carol's new phone sees "Getting access…" with no unlock time, and on Friday Alice's app grants](images/relaxed-new-space-after-reset.png)

### Creating a space from an existing space

"New space from Book club…" copies the members, not the messages. Each member taps Join once, and existing pins carry over.

![Creating a space from an existing space: "New space from Book club…" in the space menu, a pre-filled form noting messages aren't copied, and Bob joining the new space with one tap](images/relaxed-creating-from-existing.png)

### Removing a member or device

Removal and **I lost a device** stop new keys at once, with nothing held back, and existing access expires within minutes ([ending access](../core.md#ending-access)). **I lost a device** sends the user to sign the device out at their provider, then asks them to approve removal there and deletes the device, which revokes it, checks that it stays deleted, and suggests changing their password: until they do, whoever kept the lost device's keys can add more devices. The timeline says "Carol was removed," and space info adds that her devices still hold the space's key ([no rotation](../core.md#no-rotation)). The notice does not suggest moving to a new space.

![Removing a member or device: Bob's timeline says "Carol was removed", space info says Carol's devices still hold the key, the provider signs the lost iPad out first, and Alice's device list confirms its removal and suggests changing her password](images/relaxed-removing.png)

### Alarms

Relaxed presentation does not soften these. They are integrity alarms, not routine notices:

- **A device you don't recognise:** a device of the user's account that no device of theirs approved, in the account's history as their app's witness reads it, even briefly ([own-account history](../audit.md#own-account-history)), or in a grant ([auditing](../audit.md#direct-sync)). Copy: "A device you don't recognise may have access to your spaces. Review devices."
- **A different history:** the provider showed this app a version of the account that the relay never published ([witnessed history](../device-enrollment.md#witnessed-history)), with the same copy and review flow.
- **Host integrity:** a space reporting a different key commitment than first observed ([host state](../core.md#trusted-host-state)).

Two warnings say when the app couldn't check, and are not softened either, though they are not alarms:

- **Couldn't check recently:** a banner that can't be dismissed while the app's view of the account is more than a day behind, naming what isn't responding ([liveness](../audit.md#liveness-and-deadline)). Copy: "Your app couldn't check your account for unrecognised devices in the last day."
- **Couldn't check part of the history:** one notice per stretch, which the user can acknowledge ([gaps](../audit.md#monitoring-and-history)). Copy: "Your app couldn't check part of your account's history. A device you didn't add could have been there."

![Alarms: a full-screen "A device you don't recognise may have access to your spaces" alarm, the device list with the never-approved device and a Remove action, and a persistent red banner when a space's security settings change unexpectedly](images/relaxed-alarms.png)

### Settings

Surfaces the specification requires to exist but allows to be buried:

- **Devices & security:** the user's devices, **Link a new device**, and **I lost a device**, which sends the user to sign a lost device out at their provider so it stops reading, then deletes it after they approve removal there so it gets no new keys.
- **Member access**, deep in space settings: the devices each member has been granted keys to, as observed by this user's devices, with who granted them and when, and devices declined as unlinked ([auditing](../audit.md#direct-sync)).
- **Lost local state** is reported by the app itself when it detects it, not from settings: for example, after a reinstall without restore, "This device couldn't restore its saved security state and trusted everyone again" ([recovery](../device-enrollment.md#recovery)).

![Settings: Devices & security with Link a new device and I lost a device, member access listing which devices got the key from whom and a declined unlinked device, and the lost-state banner on Carol's phone](images/relaxed-settings.png)


## What stays and what goes

| Still required | Omitted or hidden |
| --- | --- |
| Member additions, removals, and readmissions are visibly surfaced ([host state](../core.md#trusted-host-state)). | |
| Retained-history access is discoverable, here in space info ([host state](../core.md#trusted-host-state)). | The history explanation when inviting. |
| Linking confirms adding a device, with an access warning ([approvals](../device-enrollment.md#approvals)). | |
| Own-account device notices with removal, and alarms for devices the account never approved, including ones seen only briefly in its history ([own-account history](../audit.md#own-account-history)). | |
| The liveness warning and one warning per unchecked stretch of history ([liveness](../audit.md#liveness-and-deadline)). | |
| Signing devices out at the provider, then removing them through a provider approval ([ending access](../core.md#ending-access)). | |
| The re-enrollment hold, its member notice, and the alarm on a removed device ([re-enrollment](../device-enrollment.md#re-enrollment)). | |
| A way to inspect observed grants to any member ([auditing](../audit.md#direct-sync)), which can live deep in settings. | The sole-holder indicator and device-list detail. |
| Reporting known loss of local state ([recovery](../device-enrollment.md#recovery)). | |
| Only the inviter shares on first contact; other members wait 3 days ([grant standing](../device-enrollment.md#grant-standing)). | Per-member wait times, which live in member info. |
| No "let them in now" button, and no promised unlock time for the person waiting. | |
| Invites that fail to send are saved and resent unchanged, and admit only once sent ([invites](../core.md#invites)). | The pending-invite window, beyond the invite still admitting late joiners. |
| | "Invited by" for each member, shown only in space info. |
| Never claiming a removal locks the removed party out of new messages ([no rotation](../core.md#no-rotation)). | |

