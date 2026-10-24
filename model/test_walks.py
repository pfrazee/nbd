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

from nbd_trust import REENROLL_HOLD, Approval, Binding, SpecClient, World

ACCOUNTS = ("alice", "bob", "carol")
WALKS = int(os.environ.get("NBD_WALKS", "1500"))
STEPS = int(os.environ.get("NBD_STEPS", "60"))
WAITS = (0.5, 1.0, 24.0, 48.0, 71.0, 72.0, 100.0)
SLOTS = 3
EPS = 1e-9


class Walk:
    """One world, two installations of Alice, and the checker's own record
    of what has happened, independent of client state."""

    def __init__(self, offset: float):
        w = self.world = World()
        a0, a1 = B("alice", "a0"), B("alice", "a1")
        self.made: Dict[str, List[Binding]] = {x: [] for x in ACCOUNTS}
        for b in (a0, a1, B("bob", "b0"), B("carol", "c0")):
            self._add(b)
        w.approve(a0, a1)
        self.clients = [SpecClient(w, a0), SpecClient(w, a1, clock_offset=offset)]
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
        for i, c in enumerate(self.clients):
            for _x, (cand, _cr, _ck) in c.state.holds.items():
                self.first_seen.setdefault(cand, w.now)
            err = self._check(i, c, before[i], synced == i,
                              imported if synced == i else None,
                              act[2] if kind == "query" and synced == i else None)
            if err:
                return f"client {i}: {err}"
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


def replay(offset: float, actions: List[tuple]) -> Optional[str]:
    walk = Walk(offset)
    for n, act in enumerate(actions):
        err = walk.step(act)
        if err:
            return f"step {n}: {err}"
    return None


def shrink(offset: float, actions: List[tuple]) -> List[tuple]:
    """Drop actions one at a time while the walk still fails."""
    changed = True
    while changed:
        changed = False
        for n in range(len(actions)):
            trial = actions[:n] + actions[n + 1:]
            if replay(offset, trial):
                actions, changed = trial, True
                break
    return actions


class Walks(unittest.TestCase):
    def test_random_walks_keep_invariants(self):
        for seed in range(WALKS):
            rng = random.Random(seed)
            offset = rng.uniform(-100.0, 100.0)
            walk = Walk(offset)
            actions = []
            for _ in range(STEPS):
                act = walk.gen(rng)
                actions.append(act)
                if walk.step(act):
                    small = shrink(offset, actions)
                    trace = "\n".join(f"  {a}" for a in small)
                    self.fail(f"seed {seed}, offset {offset:.1f}: "
                              f"{replay(offset, small)}\n{trace}")

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


if __name__ == "__main__":
    unittest.main()
