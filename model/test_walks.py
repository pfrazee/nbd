"""Random adversarial walks over SpecClient, checking invariants after every
step. A stdlib stand-in for property-based stateful testing: each walk is a
seeded sequence of repo writes (any write, as a malicious PDS could make),
elapsed time, queries, and backup exports and imports between two of
Alice's installations with different clocks. A failing walk is shrunk to a
minimal trace before it is reported.

Invariants:

- Acceptance and revocation are monotone.
- First use follows the single-root rule, restated here: two present roots,
  or a present root that misses a present record, decline; otherwise every
  present record is accepted at once, or none is.
- After a query, the accepted set is closed under present approvals of
  accounts with a live accepted binding, and a
  known account with no live accepted binding whose present records satisfy
  the rule has exactly that candidate on hold.
- A binding of an account the client already knew is accepted only through
  an approval path from bindings it had accepted while the account has a
  live accepted binding (never during re-enrollment), through an import of
  another installation's acceptance, or after the candidate's hold has run
  for REENROLL_HOLD of real time since any installation first saw it.
- After a sync, every accepted binding whose record is absent is revoked,
  and a revoked own binding has raised the takeover alarm.
- Hold credit never exceeds real time since the candidate was first seen,
  never decreases for the same candidate, and starts at zero when a client
  observes a candidate itself. A hold ends only when its candidate is accepted, one of its bindings
  is revoked, or the account has an accepted binding whose record is
  present. While a hold is pending, its candidate has no revoked binding and
  the account has no live accepted binding; a replaced candidate's dropped
  bindings are revoked.
- Approval order does not change the accepted set.

Run: python3 -I -m unittest discover -s model
More walks: NBD_WALKS=5000 NBD_STEPS=80 python3 -I -m unittest discover -s model -p test_walks.py
"""

import os
import random
import unittest
from typing import Dict, List, Optional, Set

from nbd_trust import (PENDING_INVITE_TTL, REENROLL_HOLD, Approval, Binding, InviterClient,
                       SpecClient, World)

ACCOUNTS = ("alice", "bob", "carol")
WALKS = int(os.environ.get("NBD_WALKS", "1500"))
STEPS = int(os.environ.get("NBD_STEPS", "60"))
WAITS = (0.5, 1.0, 24.0, 48.0, 71.0, 72.0, 100.0)
SLOTS = 3
EPS = 1e-9


class Walk:
    """One world, two installations of Alice, and the checker's own record
    of what has happened, independent of client state."""

    CLIENT = SpecClient

    def __init__(self, offset: float):
        w = self.world = World()
        a0, a1 = B("alice", "a0"), B("alice", "a1")
        self.made: Dict[str, List[Binding]] = {x: [] for x in ACCOUNTS}
        for b in (a0, a1, B("bob", "b0"), B("carol", "c0")):
            self._add(b)
        w.approve(a0, a1)
        self.clients = [self.CLIENT(w, a0), self.CLIENT(w, a1, clock_offset=offset)]
        self.clients[0].pair(a1)
        self.clients[1].pair(a0)
        self.slots: Dict[int, object] = {}
        self.first_seen: Dict[frozenset, float] = {}

    def _add(self, b: Binding) -> None:
        self.world.add_device(b)
        if b not in self.made[b.account]:
            self.made[b.account].append(b)

    # ---- actions ---------------------------------------------------------

    def gen(self, rng: random.Random) -> tuple:
        w = self.world
        kind = rng.choices(
            ("add", "link", "reset", "approve", "delete", "unapprove", "wait", "query",
             "export", "import"),
            (2, 4, 2, 2, 3, 1, 3, 10, 2, 3))[0]
        x = rng.choice(ACCOUNTS)
        made = self.made[x]
        fresh = lambda k=0: B(x, f"{x[0]}{len(made) + k}")
        if kind == "link" and w.present_devices(x):
            # An honest link: the record and its approval in one commit.
            return ("link", rng.choice(sorted(w.present_devices(x), key=repr)), fresh())
        if kind == "reset":
            # Delete every device and enroll a new set, as recovery or a takeover would.
            new = [fresh(k) for k in range(rng.choice((1, 1, 2)))]
            return ("reset", x, tuple(new))
        if kind == "add":
            gone = [b for b in made if not w.present(b)]
            if gone and rng.random() < 0.2:
                return ("add", rng.choice(gone))  # recreate a deleted record
            return ("add", fresh())
        if kind == "approve" and len(made) >= 2:
            signer, target = rng.sample(made, 2)
            return ("approve", signer, target)
        if kind == "delete" and w.present_devices(x):
            return ("delete", rng.choice(sorted(w.present_devices(x), key=repr)))
        if kind == "unapprove" and w.account_approvals(x):
            ap = rng.choice(sorted(w.account_approvals(x), key=repr))
            return ("unapprove", ap.signer, ap.target)
        if kind == "wait":
            return ("wait", rng.choice(WAITS))
        if kind == "export":
            return ("export", rng.randrange(2), rng.randrange(SLOTS))
        if kind == "import":
            return ("import", rng.randrange(2), rng.randrange(SLOTS))
        all_made = [b for bs in self.made.values() for b in bs]
        return ("query", rng.randrange(2), rng.choice(all_made))

    def step(self, act: tuple) -> Optional[str]:
        """Apply one action and return the first invariant it breaks."""
        w = self.world
        before = [(set(c.state.accepted), set(c.state.revoked), dict(c.state.holds))
                  for c in self.clients]
        extra_before = [self.snapshot(c) for c in self.clients]
        synced: Optional[int] = None
        imported = None
        kind = act[0]
        if kind == "add":
            self._add(act[1])
        elif kind == "link":
            self._add(act[2])
            w.approve(act[1], act[2])
        elif kind == "reset":
            for b in w.present_devices(act[1]):
                w.delete_device(b)
            for b in act[2]:
                self._add(b)
            for b in act[2][1:]:
                w.approve(act[2][0], b)
        elif kind == "approve":
            w.approve(act[1], act[2])
        elif kind == "delete":
            w.delete_device(act[1])
        elif kind == "unapprove":
            w.approvals.get(act[1].account, set()).discard(Approval(act[1], act[2]))
        elif kind == "wait":
            w.now += act[1]
        elif kind == "query":
            synced = act[1]
            self.clients[synced].accepted(act[2])
        elif kind == "export":
            self.slots[act[2]] = self.clients[act[1]].export_state()
        elif kind == "import":
            imported = self.slots.get(act[2])
            if imported is not None:
                synced = act[1]
                self.clients[synced].import_state(imported.copy())
        else:
            synced = self.extra(act)
        for i, c in enumerate(self.clients):
            for _x, (cand, _cr, _ck) in c.state.holds.items():
                self.first_seen.setdefault(cand, w.now)
            err = self._check(i, c, before[i], synced == i,
                              imported if synced == i else None,
                              act[2] if kind == "query" and synced == i else None)
            err = err or self.extra_check(i, c, before[i], extra_before[i], act, synced == i,
                                          imported if synced == i else None)
            if err:
                return f"client {i}: {err}"
        return None

    def extra(self, act: tuple) -> Optional[int]:
        """Hook: apply an action this walk adds; return the client it synced."""
        return None

    def snapshot(self, c) -> object:
        return None

    def extra_check(self, i, c, before, extra_before, act, synced, imported) -> Optional[str]:
        return None

    # ---- invariants ------------------------------------------------------

    def _check(self, i, c, before, synced, imported, queried) -> Optional[str]:
        w, st = self.world, c.state
        acc0, rev0, holds0 = before
        acc1, rev1, holds1 = set(st.accepted), set(st.revoked), st.holds
        if not acc0 <= acc1:
            return f"acceptance lost: {sorted(acc0 - acc1, key=repr)}"
        if not rev0 <= rev1:
            return f"revocation lost: {sorted(rev0 - rev1, key=repr)}"

        knew = {b.account for b in acc0}
        # What this step may legitimately accept: approval paths from what the
        # client had accepted, what it imported, and candidates whose hold has
        # run for REENROLL_HOLD of real time.
        base = set(acc0) | (set(imported.accepted) if imported is not None else set())
        for cand, _cr, _ck in holds0.values():
            if w.now - self.first_seen[cand] >= REENROLL_HOLD - EPS:
                base |= cand
        reach = _closure(base, w, _live_accounts(base - rev1, w))
        for b in sorted(acc1 - acc0 - rev1, key=repr):
            if b.account in knew and b not in reach:
                return f"accepted {b} for a known account without approval path or elapsed hold"

        if queried is not None:
            x = queried.account
            if x not in knew and x != c.own.account:
                expect = _single_root(x, w, rev1)
                # Approvals may also accept deleted bindings, already revoked.
                got = {b for b in acc1 - acc0 - rev1 if b.account == x}
                if expect is None and got:
                    return f"first use of {x} accepted {sorted(got, key=repr)}; rule declines"
                if expect is not None and got != expect:
                    return (f"first use of {x} accepted {sorted(got, key=repr)}; "
                            f"rule accepts {sorted(expect, key=repr)}")
            if x in knew and x != c.own.account and not any(
                    b.account == x and w.present(b) for b in acc1 - rev1):
                expect = _single_root(x, w, rev1)
                held = holds1.get(x)
                if expect is not None and (held is None or held[0] != frozenset(expect)):
                    return f"re-enrollment of {x} not holding candidate {sorted(expect, key=repr)}"
            missing = _closure(acc1, w, _live_accounts(acc1 - rev1, w)) - acc1
            if missing:
                return f"approved by accepted bindings but not accepted: {sorted(missing, key=repr)}"

        if synced:
            for b in sorted(acc1, key=repr):
                if not w.present(b) and b not in rev1:
                    return f"{b} absent after sync but not revoked"
            for x, (cand, _cr, _ck) in holds1.items():
                if cand & rev1:
                    return f"hold for {x} pending with revoked {sorted(cand & rev1, key=repr)}"
                if any(b.account == x and w.present(b) for b in acc1 - rev1):
                    return f"hold for {x} pending while the account has a live binding"
                old = holds0.get(x)
                if old and old[0] != cand and not (old[0] - cand) <= rev1:
                    return f"replaced candidate for {x} left {sorted(old[0] - cand - rev1, key=repr)} unrevoked"
        if c.own in rev1 and f"removed {c.own}" not in st.alarms:
            return "own binding revoked without takeover alarm"

        live = {b for b in acc1 - rev1 if w.present(b)}
        for x, (cand, credited, _ck) in holds1.items():
            if credited > w.now - self.first_seen[cand] + EPS:
                return f"hold for {x} credited {credited}h, more than real time since first seen"
            old = holds0.get(x)
            if old and old[0] == cand:
                if credited < old[1] - EPS:
                    return f"hold credit for {x} fell from {old[1]} to {credited}"
            elif imported is None and credited > EPS:
                return f"new hold for {x} started with {credited}h credit"
        for x, (cand, _cr, _ck) in holds0.items():
            new = holds1.get(x)
            if new and new[0] == cand:
                continue
            if new is None and not (cand <= acc1 - rev1 or cand & rev1
                                    or any(b.account == x for b in live)):
                return f"hold for {x} ended with no accepted candidate, revocation, or live binding"
        return None


def B(account: str, device: str) -> Binding:
    return Binding(account, device)


def _live_accounts(bindings: Set[Binding], w: World) -> Set[str]:
    return {b.account for b in bindings if w.present(b)}


def _closure(start: Set[Binding], w: World, accounts: Optional[Set[str]] = None) -> Set[Binding]:
    """Bindings reachable by approvals from start, following only approvals
    of the given accounts (all accounts if None)."""
    seen = set(start)
    while True:
        new = {ap.target for x in (w.accounts() if accounts is None else accounts)
               for ap in w.account_approvals(x) if ap.signer in seen} - seen
        if not new:
            return seen
        seen |= new


def _single_root(x: str, w: World, revoked: Set[Binding]) -> Optional[Set[Binding]]:
    """The first-use rule, restated: the present records the client accepts
    on first contact, or None if it declines."""
    present = {b for b in w.present_devices(x) if b not in revoked}
    aps = w.account_approvals(x)
    if not present:
        return None
    roots = present - {a.target for a in aps}
    if len(roots) > 1:
        return None
    if roots:
        starts = roots
    else:
        starts = ({a.signer for a in aps} | {a.target for a in aps}) - present
    reached = set(starts)
    while True:
        new = {a.target for a in aps if a.signer in reached} - reached
        if not new:
            break
        reached |= new
    return present if present <= reached else None


def replay(offset: float, actions: List[tuple], cls=None) -> Optional[str]:
    walk = (cls or Walk)(offset)
    for n, act in enumerate(actions):
        err = walk.step(act)
        if err:
            return f"step {n}: {err}"
    return None


def shrink(offset: float, actions: List[tuple], cls=None) -> List[tuple]:
    """Drop actions one at a time while the walk still fails."""
    changed = True
    while changed:
        changed = False
        for n in range(len(actions)):
            trial = actions[:n] + actions[n + 1:]
            if replay(offset, trial, cls):
                actions, changed = trial, True
                break
    return actions


def run_walks(case: unittest.TestCase, cls) -> None:
    for seed in range(WALKS):
        rng = random.Random(seed)
        offset = rng.uniform(-100.0, 100.0)
        walk = cls(offset)
        actions = []
        for _ in range(STEPS):
            act = walk.gen(rng)
            actions.append(act)
            if walk.step(act):
                small = shrink(offset, actions, cls)
                trace = "\n".join(f"  {a}" for a in small)
                case.fail(f"seed {seed}, offset {offset:.1f}: "
                          f"{replay(offset, small, cls)}\n{trace}")


class Walks(unittest.TestCase):
    def test_random_walks_keep_invariants(self):
        run_walks(self, Walk)

    def test_approval_order_does_not_change_accepted_set(self):
        for seed in range(WALKS):
            rng = random.Random(seed)
            devices = [B("bob", f"d{n}") for n in range(1, 5)]
            nodes = [B("bob", "b0")] + devices
            aps = {(s, t) for s in nodes for t in nodes if s != t and rng.random() < 0.3}
            results = []
            for _ in range(2):
                order = sorted(aps, key=repr)
                rng.shuffle(order)
                w = World()
                client = SpecClient(w, w.add_device(B("alice", "a0")))
                self.assertTrue(client.accepted(w.add_device(nodes[0])))
                for d in devices:
                    w.add_device(d)
                for s, t in order:
                    w.approve(s, t)
                    client.accepted(rng.choice(nodes))
                results.append(client.account_wide_set())
            self.assertEqual(results[0], results[1], f"seed {seed}")
            self.assertEqual(results[0] - {B("alice", "a0")}, _closure({nodes[0]}, w),
                             f"seed {seed}")


SPACES = ("s1", "s2")


class InviterWalk(Walk):
    """The same walk over InviterClient (proposal-inviters.md), adding
    invites into two spaces, an account (erin) that starts with no devices
    and later installs, failing writes and retries, and standing queries.
    Extra invariants, checked against the walk's own record of each client's
    first contacts rather than client state:

    - A published invite record authorizes only bindings some own client
      accepted on first use in the step it first met the account, and that
      step was its invite of the account, or its first contact within
      PENDING_INVITE_TTL of its pending invite of a device-less account.
    - A client's vouched bindings come only from its own first contact
      through an invite or capture, or from a published own record that
      authorizes them, adopted while it had never pinned the account.
    - A binding is authorized in a space only if a published own record for
      that space authorizes it, and only if the client holds it as vouched:
      a later vouch never extends an earlier record (Astra's third review).
    - Vouches and authorizations are never lost. No invite record is
      published for an account already a member of the space.
    - First-contact credit never exceeds real time since any installation
      first accepted the binding, never decreases, and starts at zero unless
      imported.
    - Standing matches a restatement of its five sources over the client's
      persisted bases.
    """

    CLIENT = InviterClient

    def __init__(self, offset: float):
        super().__init__(offset)
        self.made["erin"] = []
        self.first_accepted: Dict[Binding, float] = {}
        self.first: List[Dict[str, tuple]] = [{}, {}]  # client -> account -> (kind, bindings)
        self.pending: List[Dict[str, float]] = [{}, {}]  # client -> account -> invite time
        self.seen_invites = 0

    def gen(self, rng: random.Random) -> tuple:
        r = rng.random()
        if r < 0.08:
            return ("invite", rng.randrange(2), rng.choice(("bob", "carol", "erin")), rng.choice(SPACES))
        if r < 0.18:
            all_made = [b for bs in self.made.values() for b in bs]
            return ("standing", rng.randrange(2), rng.choice(all_made), rng.choice(SPACES))
        if r < 0.21:
            return ("writes", rng.random() < 0.5)
        if r < 0.24 and not self.world.present_devices("erin"):
            return ("install", B("erin", f"e{len(self.made['erin'])}"))
        if r < 0.26:
            return ("admit", rng.choice(("bob", "carol", "erin")), rng.choice(SPACES))
        return super().gen(rng)

    def extra(self, act: tuple) -> Optional[int]:
        w = self.world
        if act[0] == "writes":
            w.fail_writes = act[1]
            return None
        if act[0] == "install":
            self._add(act[1])
            return None
        if act[0] == "admit":
            w.admit(act[2], act[1])
            return None
        i, c = act[1], self.clients[act[1]]
        if act[0] == "invite":
            account = act[2]
            if (not w.eligible(account, act[3]) and not c._knew(account)
                    and not w.present_devices(account)):
                since = self.pending[i].get(account)
                if since is None or w.now - since >= PENDING_INVITE_TTL - EPS:
                    self.pending[i][account] = w.now  # a new pending window
            self.invite_rejected = w.eligible(account, act[3])
            c.invite(act[3], account)
        elif act[0] == "standing":
            self.answer = c.standing(act[2], act[3])
        return i

    def snapshot(self, c) -> object:
        st = c.state
        return (set(st.vouched), {sp: set(v) for sp, v in st.authorized.items()}, dict(st.fc_holds),
                len(self.world.invites))

    def _check(self, i, c, before, synced, imported, queried) -> Optional[str]:
        # An installation may adopt an account from its own account's invite
        # record, like a paired pin, instead of running first use.
        if queried is not None and any(
                ev == "invited" for b, ev in c.state.accepted.items()
                if b.account == queried.account and b not in before[0]):
            queried = None
        return super()._check(i, c, before, synced, imported, queried)

    def extra_check(self, i, c, before, extra_before, act, synced, imported) -> Optional[str]:
        w, st = self.world, c.state
        vouched0, authorized0, fc0, n_invites = extra_before
        knew = {b.account for b in before[0]}
        for b in st.accepted:
            self.first_accepted.setdefault(b, w.now)
        # The walk's own record of how this client first met each account.
        for x in {b.account for b in st.accepted} - knew - {c.own.account}:
            got = frozenset(b for b, ev in st.accepted.items() if b.account == x and ev == "first use")
            if synced and act[0] == "invite" and act[2] == x:
                kind = "invite"
            elif x in self.pending[i] and w.now - self.pending[i][x] < PENDING_INVITE_TTL - EPS:
                kind = "capture"
            else:
                kind = "other"
            self.first[i][x] = (kind, got)
        if i == 1:  # once per step, after both clients are recorded
            for rec in w.invites[self.seen_invites:]:
                if rec.inviter == "alice" and rec.authorizes and not any(
                        f.get(rec.account, ("", frozenset()))[0] in ("invite", "capture")
                        and rec.authorizes <= f[rec.account][1] for f in self.first):
                    return f"invite record {rec} authorizes devices not first met through an invite"
            if (act[0] == "invite" and self.invite_rejected
                    and any(r.space == act[3] and r.account == act[2] and not r.captures
                            for r in w.invites[self.seen_invites:])):
                return f"published an invite for {act[2]}, already a member of {act[3]}"
            self.seen_invites = len(w.invites)
        own = [r for r in w.invites if r.inviter == c.own.account]
        if not vouched0 <= st.vouched:
            return "vouches lost"
        for b in st.vouched - vouched0:
            kind, firsts = self.first[i].get(b.account, ("", frozenset()))
            mine = b.account not in knew and kind in ("invite", "capture") and b in firsts
            adopted = b.account not in knew and (
                any(b in r.authorizes for r in own)
                or (imported is not None and b in imported.vouched))
            if not (mine or adopted):
                return f"vouched {b} neither first met through an invite nor adopted unpinned"
        for sp, bs in st.authorized.items():
            if not authorized0.get(sp, set()) <= bs:
                return f"authorizations lost in {sp}"
            for b in bs - authorized0.get(sp, set()):
                if not any(r.space == sp and b in r.authorizes for r in own):
                    return f"authorized {b} in {sp} with no own record for {sp} authorizing it"
                if b not in st.vouched:
                    return f"authorized {b} in {sp} though it is not vouched here"
        for b, (credited, _ck) in st.fc_holds.items():
            if credited > w.now - self.first_accepted[b] + EPS:
                return f"first-contact credit for {b} is {credited}h, more than real time"
            old = fc0.get(b)
            if old is not None and credited < old[0] - EPS:
                return f"first-contact credit for {b} fell from {old[0]} to {credited}"
            if old is None and imported is None and credited > EPS:
                return f"new first-contact hold for {b} started with {credited}h"
        if synced and act[0] == "standing":
            b, s = act[2], act[3]
            want = (b in st.accepted and b not in st.revoked and w.present(b)
                    and _standing_ref(c, b, s, set()))
            if self.answer != want:
                return f"standing({b}, {s}) is {self.answer}; its sources say {want}"
        return None


def _standing_ref(c, b: Binding, s: str, seen: Set[Binding]) -> bool:
    """Standing's sources, restated over the client's persisted bases."""
    st = c.state
    if b in seen or b not in st.accepted:
        return False
    seen.add(b)
    if b.account == c.own.account or st.accepted[b] == "re-enrolled":
        return True
    if st.fc_holds.get(b, (0.0, 0.0))[0] >= REENROLL_HOLD:
        return True
    if b in st.authorized.get(s, set()):
        return True
    signer = st.approvers.get(b)
    return signer is not None and _standing_ref(c, signer, s, seen)

class InviterWalks(unittest.TestCase):
    def test_random_inviter_walks_keep_invariants(self):
        run_walks(self, InviterWalk)


if __name__ == "__main__":
    unittest.main()
