"""Cross-check against the prototype: replay its shared-view traces through
SpecClient and compare the viewer's decisions after every step.

Each fixture in ../prototype/traces/ records public-repo operations (device
records added, deleted, and recreated, approvals, elapsed time, the viewer's
clock moving back) from a random walk in
the TypeScript prototype, and what the prototype's viewer installation then
accepted and held. Trust depends only on those observations and time, so the
two implementations must agree exactly. Regenerate fixtures with
PEEP_WRITE_TRACES=1 npm test -- traces in prototype/.

Run: python3 -I -m unittest discover -s model
"""

import json
import os
import unittest

from peep_trust import Binding, SpecClient, World

TRACES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "prototype", "traces")
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


class Traces(unittest.TestCase):
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
