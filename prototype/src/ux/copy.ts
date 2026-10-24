// User-facing strings, quoted from ux-flows/relaxed-tofu.md and
// ux-flows/tofu.md. Screens take every string from here, so the figures say
// what the docs say. Keyed by presentation where the two differ.

export type Mode = "relaxed" | "tofu";

export const APP = "Lantern";

type Strings = {
  linkThisDevice: string;
  linkThisDeviceBody: string;
  linkConfirmTitle: (device: string) => string;
  linkConfirmBody: string;
  linkConfirmWarning: string;
  linkButton: string;
  cancel: string;
  newDeviceTitle: (device: string) => string;
  newDeviceBody: (from: string) => string;
  removeIt: string;
  itWasMe: string;
  message: string;
};

const shared: Strings = {
  linkThisDevice: "Link this device",
  linkThisDeviceBody: `On the phone you already use, open ${APP} and scan this code.`,
  linkConfirmTitle: (d) => `Link “${d}” to your account?`,
  linkConfirmBody: "It will be able to read all your spaces.",
  linkConfirmWarning: "Only link devices you own.",
  linkButton: "Link device",
  cancel: "Cancel",
  newDeviceTitle: (d) => `New device: ${d}`,
  newDeviceBody: (from) => `Added from ${from}. Not you?`,
  removeIt: "Remove it",
  itWasMe: "It was me",
  message: "Message",
};

export const COPY: Record<Mode, Strings> = {
  relaxed: shared,
  tofu: {
    ...shared,
    linkConfirmTitle: (d) => `Link ${d}?`,
    linkThisDeviceBody: `${shared.linkThisDeviceBody} Until then, people in your spaces won't share keys with it.`,
    newDeviceBody: (from) => `Added from ${from}. Not you? Remove it.`,
  },
};

/** Strings only the TOFU flows use (ux-flows/tofu.md). */
export const TOFU = {
  soleHolder: "Only this device can currently read this space.",
  addADevice: "Add a device",
  unverified: "Devices in this space aren't verified. Changes are shown, but not blocked.",
  inviteHistory: (who: string) => `${who} will be able to read everything already posted here.`,
  waitingForDevice: "Waiting for a member's device…",
  unlinkedNote: (who: string) => `${who} has a device that isn't linked to their others.`,
  unrecognised: (space: string) => `A device you don't recognise may have access to ${space}.`,
  startOver: "Start over on this device",
  holdBody: "People who already know you will wait at least 3 days before sharing with this device. This gives you time to stop someone who got into your account.",
  removedAlarm: "This device was removed from your account.",
  removedAlarmBody: "If this wasn't you, change your password at your provider and remove devices you don't recognise.",
  replaceWait: "People whose apps haven't caught up will wait 3 days before sharing with your new phone. Wait a few days first.",
  waitingToJoin: (who: string, space: string) => `${who} is waiting to join ${space}`,
  openToShare: "Open to share access.",
  keepAvailable: "Keep your spaces available from this computer",
  keepAvailableBody: "While it's running, it shares access with members and your other devices.",
  passwordHint: "If someone may know your password, change it.",
};

/** Starting over after total device loss, in both presentations
 * (device-enrollment.md#total-device-loss). */
export const START_OVER = {
  title: "Your old devices",
  body: `${APP} will remove these devices from your account. Do you recognise all of them?`,
  confirm: "Yes, remove them",
  stillHave: "I still have one of these",
  unrecognised: "I don't recognise one",
};
