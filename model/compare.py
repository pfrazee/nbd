"""Run the same attack and availability scenarios against each trust variant.

Run: python3 -I model/compare.py          (prints a markdown table)
Outcomes, from the viewing client's side:
  compromised  the attacker's device is accepted in the target space
  hold         acceptance waits out the re-enrollment hold
  declined     an honest device is refused (availability loss, no exposure)
  safe         honest devices accepted, attacker devices refused
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peep_trust import (AccountWideAnchorClient, Binding,  # noqa: E402
                        ScopedWitnessClient, TofuClient, WarnOnlyClient, World)

VARIANTS = [("TOFU only", TofuClient), ("Warnings only", WarnOnlyClient),
            ("Account-wide anchors (spec)", AccountWideAnchorClient),
            ("Scoped witnesses", ScopedWitnessClient)]
COMMUNITY, PRIVATE = "community", "private"


def B(a, d):
    return Binding(a, d)


class Scene:
    def __init__(self, cls):
        self.w = World()
        self.alice = self.w.add_device(B("alice", "a0"))
        self.c = cls(self.w, self.alice)

    def dev(self, account, device):
        return self.w.add_device(B(account, device))

    def meet(self, b, space=COMMUNITY):
        return self.c.accepted(b, space)

    def outcome(self, honest, attacker, space=COMMUNITY):
        if attacker is not None and self.meet(attacker, space):
            return "compromised"
        account = (honest or attacker).account
        if self.c.hold_pending(account, space):
            return "hold"
        if honest is not None and not self.meet(honest, space):
            return "declined"
        return "safe"


def witness(s, name="dave", spaces=(COMMUNITY,)):
    d = s.dev(name, "d0")
    for sp in spaces:
        s.w.admit(sp, "alice", name)
        s.meet(d, sp)
    return d


# ---- scenarios --------------------------------------------------------------
# Each takes a client class and returns an outcome string.

def root_theft_with_honest_witness(cls):
    """Takeover with create access adds M and an approval M -> Bob's root;
    a member the viewer accepted has granted to Bob's honest device."""
    s = Scene(cls)
    d = witness(s)
    bob = s.dev("bob", "b0")
    s.w.admit(COMMUNITY, "bob")
    s.w.grant("g", COMMUNITY, d, bob)
    m = s.dev("bob", "m")
    s.w.approve(m, bob)
    return s.outcome(bob, m)


def unlinked_device_beside_live(cls):
    """Takeover publishes M with no approvals beside Bob's live device."""
    s = Scene(cls)
    d = witness(s)
    bob = s.dev("bob", "b0")
    s.w.admit(COMMUNITY, "bob")
    s.w.grant("g", COMMUNITY, d, bob)
    m = s.dev("bob", "m")
    return s.outcome(bob, m)


def reset_seen_by_newcomer(cls):
    """Takeover deletes Carol's devices and publishes M; the viewer never
    pinned Carol but accepted Bob, who granted to Carol's old device."""
    s = Scene(cls)
    bob = witness(s, "bob")
    carol = s.dev("carol", "c0")
    s.w.admit(COMMUNITY, "carol")
    s.w.grant("g", COMMUNITY, bob, carol)
    s.w.delete_device(carol)
    m = s.dev("carol", "m")
    return s.outcome(None, m)


def creator_reset_seen_by_newcomer(cls):
    """As above, but Carol created the space and only issued grants."""
    s = Scene(cls)
    bob = witness(s, "bob")
    carol = s.dev("carol", "c0")
    s.w.admit(COMMUNITY, "carol")
    s.w.grant("g1", COMMUNITY, carol, bob)
    s.w.grant("g2", COMMUNITY, bob, B("zed", "z0"), provenance="g1")
    s.w.delete_device(carol)
    m = s.dev("carol", "m")
    return s.outcome(None, m)


def reset_seen_by_pinned_client(cls):
    s = Scene(cls)
    bob = s.dev("bob", "b0")
    s.w.admit(COMMUNITY, "alice", "bob")
    s.meet(bob)
    s.w.delete_device(bob)
    m = s.dev("bob", "m")
    return s.outcome(None, m)


def colluding_accounts_same_pds(cls):
    """One malicious PDS hosts X and Y; YM grants garbage to XM. The viewer
    has not accepted YM; an accepted member granted to X's honest device."""
    s = Scene(cls)
    d = witness(s)
    xa, ya = s.dev("x", "xa"), s.dev("y", "ya")
    s.w.admit(COMMUNITY, "x", "y")
    s.w.grant("g", COMMUNITY, d, xa)
    xm, ym = s.dev("x", "xm"), s.dev("y", "ym")
    s.w.approve(xm, xa)
    s.w.grant("g-ym", COMMUNITY, ym, xm)
    return s.outcome(xa, xm)


def _cross_space(cls, private_witness):
    s = Scene(cls)
    charlie = witness(s, "charlie")
    dave = witness(s, "dave")
    bob = s.dev("bob", "b0")
    s.w.admit(COMMUNITY, "bob")
    s.w.admit(PRIVATE, "alice", "bob")
    s.w.grant("g-dave", COMMUNITY, dave, bob)
    if private_witness:
        eve = witness(s, "eve", spaces=(PRIVATE,))
        s.w.grant("g-eve", PRIVATE, eve, bob)
    bm = s.dev("bob", "bm")
    s.w.approve(bm, bob)  # Bob's malicious PDS steals the root
    s.w.grant("g-charlie", COMMUNITY, charlie, bm)  # Charlie colludes
    return s.outcome(bob, bm, PRIVATE)


def colluding_witness_cross_space(cls):
    """Charlie (community only) colludes with Bob's malicious PDS; the
    private space has its own honest witness for Bob."""
    return _cross_space(cls, private_witness=True)


def colluding_witness_cross_space_no_private_witness(cls):
    """As above, but no member of the private space has granted to Bob."""
    return _cross_space(cls, private_witness=False)


def witness_chain(cls):
    """Charlie vouches for BM; BM then vouches for Dana's attacker device DM
    in the private space, which has honest witnesses for both."""
    s = Scene(cls)
    charlie = witness(s, "charlie")
    eve = witness(s, "eve", spaces=(COMMUNITY, PRIVATE))
    bob, dana = s.dev("bob", "b0"), s.dev("dana", "n0")
    for a in ("bob", "dana"):
        s.w.admit(COMMUNITY, a)
        s.w.admit(PRIVATE, a)
    for sp in (COMMUNITY, PRIVATE):
        s.w.grant(f"g-eve-bob-{sp}", sp, eve, bob)
        s.w.grant(f"g-eve-dana-{sp}", sp, eve, dana)
    bm, dm = s.dev("bob", "bm"), s.dev("dana", "dm")
    s.w.approve(bm, bob)
    s.w.approve(dm, dana)
    s.w.grant("g-charlie", COMMUNITY, charlie, bm)
    s.meet(bm, COMMUNITY)
    s.w.grant("g-bm", PRIVATE, bm, dm)
    return s.outcome(dana, dm, PRIVATE)


def retire_only_anchored_branch(cls):
    """Honest: phone approved tablet; only the tablet was granted keys by
    others; the tablet is retired."""
    s = Scene(cls)
    bob = witness(s, "bob")
    phone, tablet = s.dev("carol", "phone"), s.dev("carol", "tablet")
    s.w.approve(phone, tablet)
    s.w.admit(COMMUNITY, "carol")
    s.w.grant("g", COMMUNITY, bob, tablet)
    s.w.delete_device(tablet)
    return s.outcome(phone, None)


def forged_witness_missing_binding(cls):
    """An accepted member grants to a binding Carol never had."""
    s = Scene(cls)
    d = witness(s)
    carol = s.dev("carol", "c0")
    s.w.admit(COMMUNITY, "carol")
    s.w.grant("g", COMMUNITY, d, B("carol", "fake"))
    return s.outcome(carol, None)


SCENARIOS = [
    ("Root theft (M approves the root), honest witness", root_theft_with_honest_witness),
    ("Unlinked device beside live devices", unlinked_device_beside_live),
    ("Reset at honest PDS, newcomer with recipient anchor", reset_seen_by_newcomer),
    ("Reset of a creator who only issued, newcomer", creator_reset_seen_by_newcomer),
    ("Reset, client already pinned the account", reset_seen_by_pinned_client),
    ("Two accounts on one malicious PDS witness each other", colluding_accounts_same_pds),
    ("Colluding witness + malicious PDS, other space has a witness", colluding_witness_cross_space),
    ("Colluding witness + malicious PDS, other space has none", colluding_witness_cross_space_no_private_witness),
    ("Witness chain into a private space", witness_chain),
    ("Retire the only anchored branch (availability)", retire_only_anchored_branch),
    ("Forged witness naming a missing binding (availability)", forged_witness_missing_binding),
]


def table():
    head = "| Scenario | " + " | ".join(n for n, _ in VARIANTS) + " |"
    rows = [head, "| --- |" + " --- |" * len(VARIANTS)]
    for label, fn in SCENARIOS:
        rows.append(f"| {label} | " + " | ".join(fn(cls) for _, cls in VARIANTS) + " |")
    return "\n".join(rows)


if __name__ == "__main__":
    print(table())
