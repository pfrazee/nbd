"""Cross-check against the prototype: replay its shared-view traces through
SpecClient, and its inviters traces through InviterClient, and compare the
viewer's decisions after every step.

Each fixture in ../prototype/traces/ records public-repo operations (device
records added, deleted, and recreated, approvals, elapsed time, the viewer's
clock moving back) from a random walk in
the TypeScript prototype, and what the prototype's viewer installation then
accepted and held. Trust depends only on those observations and time, so the
two implementations must agree exactly. Regenerate fixtures with
NBD_WRITE_TRACES=1 npm test -- traces in prototype/.

Run: python3 -I -m unittest discover -s model
"""

import json
import os
import unittest

from nbd_trust import Binding, InviteRecord, InviterClient, SpecClient, World

TRACES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "prototype", "traces")
INVITER_TRACES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "prototype",
                              "traces-inviters")
ACCOUNTS = ("alice", "bob", "carol")


def B(pair):
    return Binding(pair[0], pair[1])


def replay(trace):
    """Yield (step, expected, actual) for every step of a trace."""
    w = World()
    viewer = B(trace["viewer"])
    client = SpecClient(w, viewer)
    seen = []
    for n, step in enumerate(trace["steps"]):
        for op in step["ops"]:
            if op["op"] == "add":
                b = B(op["b"])
                w.add_device(b)
                if b not in seen:
                    seen.append(b)
            elif op["op"] == "approve":
                w.approve(B(op["s"]), B(op["t"]))
            elif op["op"] == "delete":
                w.delete_device(B(op["b"]))
            elif op["op"] == "wait":
                w.now += op["h"]
            elif op["op"] == "skew":
                if op["who"] == viewer.device:  # only the viewer's clock matters here
                    client.clock_offset += op["h"]
            else:
                raise ValueError(op)
        accepted = sorted(repr(b) for b in seen if client.accepted(b))
        holds = sorted(x for x in ACCOUNTS if client.hold_pending(x))
        expected = (sorted(repr(B(p)) for p in step["accepted"]), sorted(step["holds"]))
        yield n, expected, (accepted, holds)


def replay_inviters(trace):
    """Yield (step, expected, actual) for an inviters trace: accepted
    bindings, holds, and standing per space, for the accounts the viewer
    follows. Querying any other account would pin it, so they are skipped."""
    w = World()
    viewer = B(trace["viewer"])
    client = InviterClient(w, viewer)
    client.auto_flush = False  # the trace records each resend
    seen = []
    for n, step in enumerate(trace["steps"]):
        for op in step["ops"]:
            if op["op"] == "add":
                b = B(op["b"])
                w.add_device(b)
                if b not in seen:
                    seen.append(b)
            elif op["op"] == "approve":
                w.approve(B(op["s"]), B(op["t"]))
            elif op["op"] == "delete":
                w.delete_device(B(op["b"]))
            elif op["op"] == "wait":
                w.now += op["h"]
            elif op["op"] == "skew":
                if op["who"] == viewer.device:
                    client.clock_offset += op["h"]
            elif op["op"] == "invite":
                if B(op["by"]) == viewer:
                    w.fail_writes = not op["published"]
                    if op["captures"]:
                        # The viewer met a pending invite's account: the model
                        # must capture the same devices, publishing alike.
                        before = len(w.invites) + len(client.state.outbox)
                        client.sync()
                        client._first_use(op["account"])
                        made = (w.invites + client.state.outbox)[before:]
                        want = InviteRecord(viewer.account, op["space"], op["account"],
                                            frozenset(B(x) for x in op["bindings"]), True,
                                            captures=True)
                        where = w.invites if op["published"] else client.state.outbox
                        if made != [want] or want not in where:
                            raise AssertionError(f"step {n}: model capture {made} for {op}")
                    else:
                        rec = client.invite(op["space"], op["account"])
                        got = None if rec is None else (rec.vouched, rec.pending,
                                                        rec in client.state.outbox)
                        if got != (op["vouched"], op["pending"], not op["published"]):
                            raise AssertionError(f"step {n}: model invite {rec} for {op}")
                    w.fail_writes = False
                elif op.get("published", True):
                    w.invite(InviteRecord(op["by"][0], op["space"], op["account"],
                                          frozenset(B(x) for x in op["bindings"]), op["vouched"],
                                          op.get("pending", False), op.get("captures", False)))
            elif op["op"] == "flush":
                oldest = client.state.outbox[0] if client.state.outbox else None
                client.flush(one=True)
                if oldest is None or oldest in client.state.outbox:
                    raise AssertionError(f"step {n}: model had nothing to resend for {op}")
                if (oldest in w.invites) == op.get("abandoned", False):
                    raise AssertionError(f"step {n}: model {'abandoned' if oldest not in w.invites else 'published'} {oldest} for {op}")
            else:
                raise ValueError(op)
        tracked = set(step["tracked"])
        mine = [b for b in seen if b.account in tracked]
        accepted = sorted(repr(b) for b in mine if client.accepted(b))
        holds = sorted(x for x in tracked if client.hold_pending(x))
        standing = {s: sorted(repr(b) for b in mine if client.standing(b, s)) for s in trace["spaces"]}
        expected = (sorted(repr(B(p)) for p in step["accepted"]), sorted(step["holds"]),
                    {s: sorted(repr(B(p)) for p in step["standing"].get(s, [])) for s in trace["spaces"]})
        yield n, expected, (accepted, holds, standing)


class Traces(unittest.TestCase):
    def test_prototype_inviter_traces_agree_with_model(self):
        files = sorted(f for f in os.listdir(INVITER_TRACES)
                       if f.endswith(".json")) if os.path.isdir(INVITER_TRACES) else []
        if not files:
            self.skipTest("no prototype inviter traces")
        for f in files:
            with open(os.path.join(INVITER_TRACES, f)) as fh:
                trace = json.load(fh)
            for n, expected, actual in replay_inviters(trace):
                if expected != actual:
                    self.fail(f"{f} step {n}:\n prototype {expected}\n model     {actual}")

    def test_prototype_traces_agree_with_model(self):
        files = sorted(f for f in os.listdir(TRACES) if f.endswith(".json")) if os.path.isdir(TRACES) else []
        if not files:
            self.skipTest("no prototype traces")
        for f in files:
            with open(os.path.join(TRACES, f)) as fh:
                trace = json.load(fh)
            for n, expected, actual in replay(trace):
                if expected != actual:
                    ops = "\n".join(
                        f"  step {k}: {s['ops']}" for k, s in enumerate(trace["steps"][: n + 1]))
                    self.fail(f"{f} step {n}:\n prototype accepted {expected[0]} holds {expected[1]}\n"
                              f" model     accepted {actual[0]} holds {actual[1]}\n{ops}")


if __name__ == "__main__":
    unittest.main()
