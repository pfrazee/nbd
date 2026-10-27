"""Random adversarial walks over WitnessClient (relay-witnessed repos),
checking the proposal's goal after every step. Alice is the account under
attack, with two installations on different applications (app1 and app2,
whose witnesses have different clocks); Bob (app2) and Carol (app1) meet
and invite her. Each walk is a seeded sequence of:

- honest links and removals of Alice's devices, and honest writes to
  other collections, which change the repo root; honest writes the relay
  drops (a rate limit), and honest writes whose revision is far ahead of
  the relay's time (a PDS clock wrong once);
- a malicious PDS adding and deleting impostor devices (rooted over her
  devices, approved by a removed device's key, or bare), through `#commit`,
  `#sync` served to some witnesses, or never relayed; resetting her
  account; recreating removed records; replacing `#sync` roots; forking
  what it serves one client, at a new or a witnessed revision; serving one
  client a commit it never relayed (or one the relay dropped) after a later
  commit inverts to the last relayed one or not; publishing an impostor at
  a revision not above the last; withholding and stalling fetches per
  witness;
- witness outages (longer than the relay's replay window too), relay
  outages, unreachable witnesses, witness clocks slow or fast against the
  relay within `CLOCK_SKEW` (and fast beyond it), elapsed time, and
  installation wall-clock jumps;
- installations stopping and starting, exporting backups, being wiped and
  restored from a stale backup onto either application's witness,
  acknowledging gap warnings, and ticking;
- Bob and Carol querying Alice's devices and inviting her.

Invariants after every step:

- The goal (`goal_violations`): every impostor an honest client accepted is
  in, or leaves a gap in, the history each of Alice's installations read,
  and every running installation has alarmed, noticed, presented, recorded
  a covering gap, or shows the liveness warning 24 hours after acceptance.
- Every acceptance rests on a commit the client's own witness reconstructed
  at that revision, whose commit is the one the relay published there.
- Acceptance, revocation, own alarms, and gaps never shrink; acknowledging
  marks a gap, never removes it.
- A fork alarm names two different commits at one revision, one of them
  relayed.
- No false integrity alarm from honest behavior: an unrelayed-commit alarm
  names a commit the relay never published, between two relayed commits
  with no event of the account between them, and never a commit an honest
  relay dropped (unless the PDS then concealed it); a non-increasing
  alarm names a relayed commit whose revision is not above an earlier one
  within the allowance; and no witness's latest revision is more than
  `REV_ALLOWANCE` ahead of the relay's time.

The goal is checked with `CLOCK_SKEW` of slack on its deadline (finding
10: a witness clock slow by less than the allowance understates frontier
age by that much).

The main walks run the proposal's rules. The lag walks add the conditions
behind findings 1 and 2 (a witness hours behind the relay, fresh enrollment
after history the witness lacks, 90-day waits), which the event-time
frontier and the before-history gap now handle, so they must keep the goal.
The finding walks also add the clock conditions behind findings 3 and 4 (a
suspending clock, a clock set back while stopped) and must find a violation.

Run: python3 -I -m unittest discover -s model
More walks: NBD_WITNESS_WALKS=2000 NBD_WITNESS_STEPS=60 python3 -I -m unittest discover -s model -p test_witness_walks.py
"""

import os
import random
import unittest
from typing import Dict, List, Optional

from nbd_trust import Binding
from nbd_witness import (CLOCK_SKEW, RELAY_REPLAY_WINDOW, REV_ALLOWANCE, WITNESS_RETENTION, RelayWorld,
                         Witness, WitnessClient, goal_violations, rev_at)

WALKS = int(os.environ.get("NBD_WITNESS_WALKS", "300"))
STEPS = int(os.environ.get("NBD_WITNESS_STEPS", "60"))
WAITS = (0.25, 1.0, 5.0, 12.0, 23.0, 25.0, 48.0, RELAY_REPLAY_WINDOW + 8)
SLOTS = 2
TICK = 4.0  # hours between a running installation's frontier advances during waits
SPACES = ("s1", "s2")
# Witness clock offsets against the relay: slow and fast within the allowance,
# and fast beyond it (safe: it overstates age). A clock slow beyond the
# allowance breaks the goal's honest-clock assumption whenever it goes slow
# while the witness is behind (finding 11), so only the tests cover it.
WOFFS = (0.0, -0.9 * CLOCK_SKEW, 0.9 * CLOCK_SKEW, 1.0)


def B(account: str, device: str) -> Binding:
    return Binding(account, device)


class WitnessWalk:
    LAG = False  # add the conditions behind findings 1 and 2
    CLOCKS = False  # add the conditions behind findings 3 and 4

    def __init__(self, offset: float):
        w = self.w = RelayWorld()
        woff = WOFFS[int(abs(offset) * 7) % len(WOFFS)]
        self.wit = {"app1": Witness(w, "app1"), "app2": Witness(w, "app2", clock_offset=woff)}
        cls = self.client_cls()
        a0 = w.add_device(B("alice", "a0"))
        a1 = w.link(a0, B("alice", "a1"))
        self.made: List[Binding] = [a0, a1]
        self.legit = {a0, a1}
        self.imps: List[Binding] = []
        b0, c0 = w.add_device(B("bob", "b0")), w.add_device(B("carol", "c0"))
        self.inst = [cls(w, a0, self.wit["app1"]), cls(w, a1, self.wit["app2"], clock_offset=offset)]
        self.inst[0].pair(a1)
        self.inst[1].pair(a0)
        self.others = [cls(w, b0, self.wit["app2"]), cls(w, c0, self.wit["app1"])]
        for c in self.inst + self.others:
            c.sync()
        self.slots: Dict[int, tuple] = {}
        self.fresh = 0
        self.hidden: List = []  # commits the PDS made and never relayed, on purpose
        self.concealed: set = set()  # dropped commits a later commit then concealed

    def client_cls(self):
        suspending = self.CLOCKS

        class C(WitnessClient):
            MONO_COUNTS_SUSPEND = not suspending  # finding 3's condition
        return C

    # ---- actions -------------------------------------------------------------

    def gen(self, rng: random.Random) -> tuple:
        w = self.w
        kinds = ["link", "remove", "imp", "imp_del", "resurrect", "reset", "replace_sync",
                 "withhold", "stall", "fork", "unfork", "wdown", "wup", "relay", "unreach",
                 "wait", "jump", "stop", "start", "export", "restore", "ack", "tick", "query", "invite"]
        kinds += ["post", "wclock", "drop", "futurerev", "oldrev", "conceal", "serve"]
        weights = [3, 2, 4, 3, 1, 1, 1, 2, 1, 2, 1, 1, 2, 1, 1, 6, 1, 1, 2, 2, 1, 1, 6, 8, 2, 3, 1,
                   2, 1, 1, 1, 2]
        if self.LAG:
            kinds += ["lag", "fresh", "longwait"]
            weights += [2, 1, 1]
        if self.CLOCKS:
            kinds += ["suspend", "backjump"]
            weights += [3, 2]
        kind = rng.choices(kinds, weights)[0]
        present = sorted(w.present_devices("alice"), key=repr)
        legit_present = [b for b in present if b in self.legit]
        removed = [b for b in self.made if b in self.legit and not w.present(b)]
        wname = rng.choice(("app1", "app2"))
        i = rng.randrange(2)
        if kind == "post":
            return ("post", rng.choice(("alice", "bob")))
        if kind == "wclock":
            return ("wclock", wname, rng.choice(WOFFS))
        if kind in ("drop", "futurerev"):
            nb = B("alice", f"a{len(self.made)}")
            what = ("link", rng.choice(legit_present), nb) if legit_present and rng.random() < 0.5 else ("post",)
            if kind == "drop":
                return ("drop", what)
            return ("futurerev", rng.choice((0.5, 6.0, 30.0)), what)
        if kind == "oldrev":
            return ("oldrev", B("alice", f"m{len(self.imps)}"), rng.choice((0, 1, 1000)))
        if kind == "conceal":
            return ("conceal",)
        if kind == "serve":
            pool = self.hidden + [d for d in w.dropped if d.account == "alice"]
            if pool:
                viewer = rng.choice([c.name for c in self.others + self.inst])
                return ("serve", viewer, rng.choice(pool))
        if kind == "link" and legit_present:
            return ("link", rng.choice(legit_present), B("alice", f"a{len(self.made)}"))
        if kind == "remove" and len(legit_present) > 1:
            return ("remove", rng.choice(legit_present))
        if kind == "imp":
            how = rng.choice(("root", "root", "stolen", "bare"))
            if how == "stolen" and not removed:
                how = "root"
            signer = rng.choice(removed) if how == "stolen" else None
            via = rng.choice(("commit", "commit", "sync", "sync-app1", "sync-app2", "hidden"))
            return ("imp", B("alice", f"m{len(self.imps)}"), how, signer, via)
        if kind == "imp_del":
            live = [b for b in present if b not in self.legit]
            if live:
                return ("imp_del", rng.choice(live), rng.choice(("commit", "commit", "sync", "hidden")))
        if kind == "resurrect" and removed:
            return ("resurrect", rng.choice(removed))
        if kind == "reset" and legit_present:
            return ("reset", B("alice", f"m{len(self.imps)}"))
        if kind in ("replace_sync",):
            return ("replace_sync",)
        if kind in ("withhold", "stall"):
            return (kind, wname, rng.random() < 0.6)
        if kind == "fork":
            viewer = rng.choice([c.name for c in self.others + self.inst])
            same = rng.random() < 0.4
            if rng.random() < 0.5 or not legit_present:
                return ("fork", viewer, "add", B("alice", f"m{len(self.imps)}"), same)
            return ("fork", viewer, "delete", rng.choice(legit_present), same)
        if kind == "unfork":
            return ("unfork",)
        if kind in ("wdown", "wup"):
            return (kind, wname)
        if kind == "relay":
            return ("relay", rng.random() < 0.6)
        if kind == "unreach":
            return ("unreach", wname, rng.random() < 0.5)
        if kind == "wait":
            return ("wait", rng.choice(WAITS))
        if kind == "jump":
            h = rng.choice((-30.0, -2.0, 3.0, 40.0))
            return ("jump", i, h)
        if kind in ("stop", "start", "ack", "tick"):
            return (kind, i)
        if kind == "export":
            return ("export", i, rng.randrange(SLOTS))
        if kind == "restore":
            return ("restore", i, rng.randrange(SLOTS), wname)
        if kind == "query":
            return ("query", rng.randrange(2), rng.choice(self.made + self.imps))
        if kind == "invite":
            return ("invite", rng.randrange(2), rng.choice(SPACES))
        if kind == "lag":
            return ("lag", wname, rng.choice((0.0, 0.0, 6.0, 30.0)))
        if kind == "fresh":
            return ("fresh", i)
        if kind == "longwait":
            return ("wait", WITNESS_RETENTION + 1)
        if kind == "suspend":
            return ("suspend", i, rng.choice((10.0, 30.0)))
        if kind == "backjump":
            return ("backjump", i, rng.choice((5.0, 20.0)))
        return ("tick", i)

    def step(self, act: tuple) -> Optional[str]:
        w = self.w
        clients = self.inst + self.others
        before = [(c, set(c.state.accepted), set(c.state.revoked), set(c.state.own_alarms),
                   [(g.lo, g.hi, g.kind) for g in c.state.gaps]) for c in clients]
        k = act[0]
        if k == "link":
            w.link(act[1], act[2])
            self.made.append(act[2])
            self.legit.add(act[2])
        elif k == "remove":
            w.delete_device(act[1])
        elif k == "post":
            w.post(act[1])
        elif k == "wclock":
            self.wit[act[1]].clock_offset = act[2]
        elif k == "drop":
            w.drop_next.add("alice")
            self._honest(act[1])
            w.drop_next.discard("alice")
        elif k == "futurerev":
            self._honest(act[2], rev=rev_at(w.now + act[1]))
        elif k == "oldrev":
            m, back = act[1:]
            self.imps.append(m)
            last = w.relay_head("alice")
            rev = max(1, (last.commit.rev if last else 1) - back)
            w.pds_write("alice", add=[m], approve=[(m, b) for b in sorted(w.present_devices("alice"), key=repr)[:1]],
                        rev=rev)
        elif k == "conceal":
            last = w.relay_head("alice")
            self.concealed |= {d for d in w.dropped if last is None or d.rev > last.commit.rev}
            w.pds_write("alice", prev="relayed")
        elif k == "serve":
            w.serve(act[1], act[2])
        elif k == "imp":
            m, how, signer, via = act[1:]
            self.imps.append(m)
            if how == "root":
                roots = [b for b in w.present_devices("alice")
                         if not any(a.target == b for a in w.account_approvals("alice"))]
                approve = [(m, r) for r in roots]
            elif how == "stolen":
                approve = [(signer, m)]
            else:
                approve = []
            self._write(via, add=[m], approve=approve)
        elif k == "imp_del":
            m, via = act[1:]
            self._write(via, delete=[m], unapprove=[(a.signer, a.target) for a in w.account_approvals("alice")
                                                  if a.signer == m])
        elif k == "resurrect":
            w.pds_write("alice", add=[act[1]])
        elif k == "reset":
            self.imps.append(act[1])
            w.pds_write("alice", add=[act[1]], delete=list(w.present_devices("alice")))
        elif k == "replace_sync":
            w.replace_sync("alice")
        elif k == "withhold":
            w.withhold(act[1], "alice", act[2])
        elif k == "stall":
            w.stall(act[1], "alice", act[2])
        elif k == "fork":
            viewer, what, b, same = act[1:]
            rev = w.head["alice"].rev if same else None
            if what == "add":
                self.imps.append(b)
                a0 = sorted(w.present_devices("alice"), key=repr)
                w.fork(viewer, "alice", add=[b], approve=[(b, a0[0])] if a0 else [], rev=rev)
            else:
                w.fork(viewer, "alice", delete=[b], rev=rev)
        elif k == "unfork":
            w.forks.clear()
        elif k == "wdown":
            self.wit[act[1]].set_up(False)
        elif k == "wup":
            self.wit[act[1]].set_up(True)
        elif k == "relay":
            w.set_relay(act[1])
        elif k == "unreach":
            self.wit[act[1]].reachable = not act[2]
        elif k == "wait":
            # Running installations advance their frontier every few hours,
            # as the proposal says they should, so warnings mean failures.
            end = w.now + act[1]
            while w.now < end:
                w.now = min(end, w.now + TICK)
                for c in self.inst:
                    c.sync()
        elif k == "jump":
            c = self.inst[act[1]]
            if act[2] < 0 and not c.running:
                pass  # setting a clock back while stopped is finding 4 (backjump)
            else:
                c.clock_offset += act[2]
        elif k == "backjump":
            self.inst[act[1]].clock_offset -= act[2]
        elif k == "stop":
            self.inst[act[1]].stop()
        elif k == "start":
            if not self.inst[act[1]].running:
                self.inst[act[1]].start()
        elif k == "export":
            if self.inst[act[1]].running:
                self.slots[act[2]] = (act[1], self.inst[act[1]].export_state())
        elif k == "restore":
            slot = self.slots.get(act[2])
            if slot is not None and slot[0] == act[1]:
                old = self.inst[act[1]]
                # onto either application's witness: the cursor is a revision
                wit = self.wit[act[3]] if len(act) > 3 else old.witness
                self.inst[act[1]] = self.client_cls().restore(w, slot[1], wit, old.clock_offset)
        elif k == "ack":
            for g in self.inst[act[1]].gap_warnings()[:1]:
                self.inst[act[1]].acknowledge(g)
        elif k == "tick":
            self.inst[act[1]].sync()
        elif k == "query":
            self.others[act[1]].accepted(act[2])
        elif k == "invite":
            self.others[act[1]].invite(act[2], "alice")
        elif k == "lag":
            self.wit[act[1]].lag = act[2]
        elif k == "fresh":
            # Total device loss: a new installation enrolls fresh.
            old = self.inst[act[1]]
            nb = B("alice", f"a{len(self.made)}")
            self.made.append(nb)
            self.legit.add(nb)
            w.add_device(nb)
            self.inst[act[1]] = self.client_cls()(w, nb, old.witness, old.clock_offset)
            self.inst[act[1]].sync()
        elif k == "suspend":
            c = self.inst[act[1]]
            w.now += act[2]
            c.suspended += act[2]
        return self._check(before)

    def _honest(self, what: tuple, rev=None) -> None:
        w = self.w
        if what[0] == "link":
            self.made.append(what[2])
            self.legit.add(what[2])
            w.pds_write("alice", add=[what[2]], approve=[(what[1], what[2])], rev=rev)
        else:
            w.other["alice"] = w.other.get("alice", 0) + 1
            w.commit("alice", rev=rev)

    def _write(self, via: str, **ops) -> None:
        w = self.w
        if via == "commit":
            w.pds_write("alice", **ops)
        elif via == "hidden":
            self.hidden.append(w.pds_write("alice", relay=False, **ops))
        elif via == "sync":
            w.publish_sync("alice", **ops)
        else:
            w.publish_sync("alice", serve_to=frozenset({via.split("-")[1]}), **ops)

    # ---- invariants ----------------------------------------------------------

    def _check(self, before) -> Optional[str]:
        w = self.w
        for v in goal_violations("alice", self.inst, self.others, self.legit, w.now, slack=CLOCK_SKEW):
            return v
        relayed: Dict[tuple, object] = {}
        for e in w.relay:  # the first at a revision, among those a witness accepts the revision of
            if e.commit.rev <= rev_at(e.time + REV_ALLOWANCE):
                relayed.setdefault((e.commit.account, e.commit.rev), e.commit)
        err = self._check_integrity_alarms()
        if err:
            return err
        for c in self.inst + self.others:
            arch: Dict[tuple, object] = {}
            for e in c.witness.archive:
                if e.reconstructed:
                    arch.setdefault((e.hi, e.account), []).append(e)
            for b, (rev, _t) in c.state.basis.items():
                es = arch.get((rev, b.account), [])
                ok = False
                for e in es:
                    d, aps, _other = e.root
                    mentioned = set(d) | {a.target for a in aps} | {a.signer for a in aps}
                    if b in mentioned and relayed.get((b.account, rev)) == e.commit:
                        ok = True
                if not ok:
                    return f"{c.name} accepted {b} on rev {rev}, which its witness did not reconstruct"
            for wc, served in c.state.forks:
                if wc.rev != served.rev or wc == served or not any(
                        e.commit == wc for e in w.relay):
                    return f"{c.name} raised a fork alarm on {wc} / {served}"
        for c, acc0, rev0, alarms0, gaps0 in before:
            if c not in self.inst + self.others:
                continue  # replaced by a restore or fresh enrollment
            st = c.state
            if not acc0 <= set(st.accepted):
                return f"{c.name} lost acceptance of {sorted(acc0 - set(st.accepted), key=repr)}"
            if not rev0 <= st.revoked:
                return f"{c.name} lost revocation of {sorted(rev0 - st.revoked, key=repr)}"
            if not alarms0 <= st.own_alarms:
                return f"{c.name} lost own alarms"
            if gaps0 != [(g.lo, g.hi, g.kind) for g in st.gaps][:len(gaps0)]:
                return f"{c.name} lost or rewrote a gap"
        for x in self.wit.values():
            for e in x.archive:
                if e.reconstructed and e.root != relayed[(e.account, e.hi)].root:
                    return f"{x.name} reconstructed {e.account} rev {e.hi} wrongly"
        return None


    def _check_integrity_alarms(self) -> Optional[str]:
        w = self.w
        events = [e for e in w.relay if e.commit.account == "alice"]
        published = {e.commit for e in events}
        index = {}
        for n, e in enumerate(events):
            index.setdefault(e.commit, n)

        def not_increasing(r: int) -> bool:
            return any(e.commit.rev == r and any(
                r <= p.commit.rev <= rev_at(p.time + REV_ALLOWANCE) for p in events[:n])
                for n, e in enumerate(events))

        for c in self.inst + self.others:
            for before, served, after in c.state.unrelayed:
                # A commit relayed later with a revision below one already
                # relayed is a fault too, alarmed on when the witness gets there.
                if served in published and not not_increasing(served.rev):
                    return f"{c.name} alarmed that relayed {served} was never relayed"
                if served in w.dropped and served not in self.concealed:
                    return f"{c.name} alarmed on {served}, which an honest relay dropped"
                i, j = index.get(before), index.get(after)
                if i is None or j is None or j != i + 1 or not before.rev < served.rev < after.rev:
                    return f"{c.name} alarmed on {served} between {before} and {after}"
            for a in c.state.alarms:
                if a.startswith("revision not increasing alice rev "):
                    if not not_increasing(int(a.rsplit(" ", 1)[1])):
                        return f"{c.name} raised {a!r} on an increasing revision"
        for x in self.wit.values():
            if x.max_rev("alice") > rev_at(w.now + REV_ALLOWANCE):
                return f"{x.name} raised alice's latest revision ahead of the relay's time"
        return None


def replay(cls, offset: float, actions: List[tuple]) -> Optional[str]:
    walk = cls(offset)
    for n, act in enumerate(actions):
        err = walk.step(act)
        if err:
            return f"step {n}: {err}"
    return None


def shrink(cls, offset: float, actions: List[tuple]) -> List[tuple]:
    changed = True
    while changed:
        changed = False
        for n in range(len(actions)):
            trial = actions[:n] + actions[n + 1:]
            if replay(cls, offset, trial):
                actions, changed = trial, True
                break
    return actions


def first_failure(cls, walks: int = WALKS):
    for seed in range(walks):
        rng = random.Random(seed)
        offset = rng.uniform(-100.0, 100.0)
        walk = cls(offset)
        actions = []
        for _ in range(STEPS):
            act = walk.gen(rng)
            actions.append(act)
            if walk.step(act):
                small = shrink(cls, offset, actions)
                return seed, offset, small, replay(cls, offset, small)
    return None


def describe(found) -> str:
    seed, offset, small, err = found
    trace = "\n".join(f"  {a}" for a in small)
    return f"seed {seed}, offset {offset:.1f}: {err}\n{trace}"


class LagWalk(WitnessWalk):
    """The conditions behind findings 1 and 2, which the rules now handle."""

    LAG = True


class FindingWalk(WitnessWalk):
    """Also the clock conditions behind findings 3 and 4: a monotonic clock
    that stops in suspend, and a wall clock set back while stopped."""

    LAG = True
    CLOCKS = True


class WitnessWalks(unittest.TestCase):
    def test_random_witness_walks_keep_the_goal(self):
        found = first_failure(WitnessWalk)
        if found:
            self.fail(describe(found))

    def test_walks_keep_the_goal_with_a_witness_behind_and_late_history(self):
        found = first_failure(LagWalk)
        if found:
            self.fail(describe(found))

    def test_walks_find_the_goal_failing_under_the_clock_conditions(self):
        found = first_failure(FindingWalk)
        self.assertIsNotNone(found, "the clock conditions should break the goal")
        if os.environ.get("NBD_SHOW_FINDINGS"):
            print("\n" + describe(found))


if __name__ == "__main__":
    unittest.main()
