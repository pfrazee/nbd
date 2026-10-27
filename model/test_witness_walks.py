"""Random adversarial walks over WitnessClient (relay-witnessed repos),
checking the proposal's goal after every step. Alice is the account under
attack, with two installations on different applications (app1 and app2,
whose witnesses have different clocks); Bob (app2) and Carol (app1) meet
and invite her. Each walk is a seeded sequence of:

- honest links and removals of Alice's devices, and honest writes to
  other collections, which change the repo root;
- a malicious PDS adding and deleting impostor devices (rooted over her
  devices, approved by a removed device's key, or bare), through `#commit`,
  `#sync` served to some witnesses, or never relayed; resetting her
  account; recreating removed records; replacing `#sync` roots; forking
  what it serves one client, at a new or a witnessed revision; withholding
  and stalling fetches per witness;
- witness outages (longer than the relay's replay window too), relay
  outages, unreachable witnesses, elapsed time, and wall-clock jumps;
- installations stopping and starting, exporting backups, being wiped and
  restored from a stale backup, acknowledging gap warnings, and ticking;
- Bob and Carol querying Alice's devices and inviting her.

Invariants after every step:

- The goal (`goal_violations`): every impostor an honest client accepted is
  in, or leaves a gap in, the history each of Alice's installations read,
  and every running installation has alarmed, noticed, presented, recorded
  a covering gap, or shows the liveness warning 24 hours after acceptance.
- Every acceptance rests on a commit the client's own witness reconstructed
  at that relay seq, whose commit is the one the relay published there.
- Acceptance, revocation, own alarms, and gaps never shrink; acknowledging
  marks a gap, never removes it.
- A fork alarm names two different commits at one revision, one of them
  relayed.

The main walks run the proposal as written, without the conditions behind
findings 1-4 (a witness behind the relay, enrollment after history the
witness lacks, a suspending clock, a clock set back while stopped). The
finding walks add those conditions: as written they find a violation; with
the fixes (LIVE_RULE "head", FRESH_HISTORY_GAP) they keep the goal.

Run: python3 -I -m unittest discover -s model
More walks: NBD_WITNESS_WALKS=2000 python3 -I -m unittest discover -s model -p test_witness_walks.py
"""

import os
import random
import unittest
from typing import Dict, List, Optional

from nbd_trust import Binding
from nbd_witness import (RELAY_REPLAY_WINDOW, WITNESS_RETENTION, RelayWorld, Witness,
                         WitnessClient, goal_violations)

WALKS = int(os.environ.get("NBD_WITNESS_WALKS", "300"))
STEPS = int(os.environ.get("NBD_WITNESS_STEPS", "60"))
WAITS = (0.25, 1.0, 5.0, 12.0, 23.0, 25.0, 48.0, RELAY_REPLAY_WINDOW + 8)
SLOTS = 2
TICK = 4.0  # hours between a running installation's frontier advances during waits
SPACES = ("s1", "s2")


def B(account: str, device: str) -> Binding:
    return Binding(account, device)


class WitnessWalk:
    FINDINGS = False  # add the conditions behind findings 1-4
    FIXED = False  # apply the fixes for findings 1 and 2

    def __init__(self, offset: float):
        w = self.w = RelayWorld()
        rule = "head" if self.FIXED else "literal"
        self.wit = {"app1": Witness(w, "app1"), "app2": Witness(w, "app2", clock_offset=offset / 3)}
        for x in self.wit.values():
            x.LIVE_RULE = rule
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

    def client_cls(self):
        fixed = self.FIXED

        class C(WitnessClient):
            FRESH_HISTORY_GAP = fixed
        return C

    # ---- actions -------------------------------------------------------------

    def gen(self, rng: random.Random) -> tuple:
        w = self.w
        kinds = ["link", "remove", "imp", "imp_del", "resurrect", "reset", "replace_sync",
                 "withhold", "stall", "fork", "unfork", "wdown", "wup", "relay", "unreach",
                 "wait", "jump", "stop", "start", "export", "restore", "ack", "tick", "query", "invite"]
        kinds.append("post")
        weights = [3, 2, 4, 3, 1, 1, 1, 2, 1, 2, 1, 1, 2, 1, 1, 6, 1, 1, 2, 2, 1, 1, 6, 8, 2, 3]
        if self.FINDINGS:
            kinds += ["lag", "fresh", "longwait", "suspend", "backjump"]
            weights += [2, 1, 1, 1, 1]
        kind = rng.choices(kinds, weights)[0]
        present = sorted(w.present_devices("alice"), key=repr)
        legit_present = [b for b in present if b in self.legit]
        removed = [b for b in self.made if b in self.legit and not w.present(b)]
        wname = rng.choice(("app1", "app2"))
        i = rng.randrange(2)
        if kind == "post":
            return ("post", rng.choice(("alice", "bob")))
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
            return ("restore", i, rng.randrange(SLOTS))
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
                self.inst[act[1]] = WitnessClient.restore(w, slot[1], old.witness, old.clock_offset)
                self.inst[act[1]].__class__ = old.__class__
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

    def _write(self, via: str, **ops) -> None:
        w = self.w
        if via == "commit":
            w.pds_write("alice", **ops)
        elif via == "hidden":
            w.pds_write("alice", relay=False, **ops)
        elif via == "sync":
            w.publish_sync("alice", **ops)
        else:
            w.publish_sync("alice", serve_to=frozenset({via.split("-")[1]}), **ops)

    # ---- invariants ----------------------------------------------------------

    def _check(self, before) -> Optional[str]:
        w = self.w
        for v in goal_violations("alice", self.inst, self.others, self.legit, w.now):
            return v
        relayed = {e.seq: e for e in w.relay}
        for c in self.inst + self.others:
            arch: Dict[tuple, object] = {}
            for e in c.witness.archive:
                if e.reconstructed:
                    arch.setdefault((e.seq, e.account), []).append(e)
            for b, (seq, _t) in c.state.basis.items():
                es = arch.get((seq, b.account), [])
                ok = False
                for e in es:
                    d, aps, _other = e.root
                    mentioned = set(d) | {a.target for a in aps} | {a.signer for a in aps}
                    if b in mentioned and relayed.get(seq) is not None \
                            and relayed[seq].commit == e.commit:
                        ok = True
                if not ok:
                    return f"{c.name} accepted {b} on seq {seq}, which its witness did not reconstruct"
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
                if e.reconstructed and e.root != relayed[e.seq].commit.root:
                    return f"{x.name} reconstructed seq {e.seq} wrongly"
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


class FindingWalk(WitnessWalk):
    FINDINGS = True


class FixedWalk(WitnessWalk):
    """Findings 1 and 2 fixed; findings 3 and 4 (clock assumptions) left out."""

    FINDINGS = True
    FIXED = True

    def gen(self, rng):
        act = super().gen(rng)
        return ("tick", act[1]) if act[0] in ("suspend", "backjump") else act


class WitnessWalks(unittest.TestCase):
    def test_random_witness_walks_keep_the_goal(self):
        found = first_failure(WitnessWalk)
        if found:
            self.fail(describe(found))

    def test_walks_with_fixes_keep_the_goal_under_the_finding_conditions(self):
        found = first_failure(FixedWalk)
        if found:
            self.fail(describe(found))

    def test_walks_find_the_goal_failing_as_written(self):
        found = first_failure(FindingWalk)
        self.assertIsNotNone(found, "the finding conditions should break the goal as written")
        if os.environ.get("NBD_SHOW_FINDINGS"):
            print("\n" + describe(found))


if __name__ == "__main__":
    unittest.main()
