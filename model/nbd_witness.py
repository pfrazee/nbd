"""Relay-witnessed repos: a variant of InviterClient for
proposal-reliable-detection.md, beside the unchanged specified design.

The baseline model assumes one shared, current view of every repo. This
variant replaces it with what the proposal relies on:

- `RelayWorld`: the PDS's commits, a reference relay that publishes one
  ordered log of them, delivered identically to every subscriber, and a
  malicious PDS that can serve one client a commit the relay never saw
  (`fork`, `serve`), commit without relaying (`pds_write(relay=False)`) or
  at a chosen revision (`pds_write(rev=...)`), publish a
  `#sync` root and serve its contents only to some witnesses or replace it
  before they fetch (`publish_sync`, `replace_sync`), and withhold or stall
  fetches per witness. Revisions are timestamps the PDS chooses (`rev_at`);
  an honest relay can still drop a commit (`drop_next`), and the PDS can
  publish an earlier commit again (`republish`). The relay stamps each event
  when it sequences it (`STAMP`). `ClientView` is what the PDS serves one
  baseline client.
- `Witness`: one per application. It tails the relay, reconstructs the
  device and approval collections at each exact root or records a gap,
  records stream gaps when the relay refuses to resume, reports per account
  its frontier age (its own clock minus the relay time of the newest event
  it processed in order, held at a commit awaiting a fetch), and keeps
  `WITNESS_RETENTION` of history, served by repo revision.
- `WitnessClient`: InviterClient deciding only on commits its own witness
  reports as published and reconstructed, processing every witnessed commit
  of each pinned account in order, watching its own account's whole history
  from a persisted cursor (a repo revision, so it can move between
  witnesses), and warning on gaps and on coverage age, counted from when
  it sent the request that produced the answer (`request`, `deliver`).
- `goal_violations`: the proposal's goal, checked against client state.

Commits are abstract: a commit is its account, revision, and the two
collections; equal collections mean equal roots. Signatures are implicit:
the PDS holds the repo signing key, so it can sign any commit.

Stdlib only; Python 3.9.
"""

import copy
import math
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from nbd_trust import Approval, Binding, InviterClient, InviterState, World

WITNESS_RETENTION = 90 * 24.0  # hours
RELAY_REPLAY_WINDOW = 72.0  # hours a relay keeps events for resuming subscribers
LIVENESS_LIMIT = 24.0  # hours of coverage age before the liveness warning
FETCH_TIMEOUT = 1.0  # hours a witness waits on a stalled fetch before recording a gap
CLOCK_SKEW = 5 / 60.0  # hours a frontier may be ahead of the witness's clock before it is a fault
REV_ALLOWANCE = 5 / 60.0  # hours a revision may be ahead of its event's relay time
REV_TICKS = 3_600_000  # revision ticks per hour: a revision is a millisecond timestamp
INF = float("inf")
EPS = 1e-9


def rev_at(t: float) -> int:
    """The revision a PDS whose clock reads `t` (hours) gives a commit."""
    return int(math.floor(t * REV_TICKS + 1e-6))


# A repo root: the device and approval collections, plus a count standing
# for every other collection (posts, likes), since an atproto root covers
# the whole repo and changes with any write.
Root = Tuple[FrozenSet[Binding], FrozenSet[Approval], int]
EMPTY: Root = (frozenset(), frozenset(), 0)


class _Incomplete:
    """A decision the client cannot make yet; falsy, so it never grants."""

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "INCOMPLETE"


INCOMPLETE = _Incomplete()


@dataclass(frozen=True)
class Commit:
    account: str
    rev: int  # a timestamp in REV_TICKS, chosen by the PDS
    devices: FrozenSet[Binding]
    approvals: FrozenSet[Approval]
    other: int = 0

    @property
    def root(self) -> Root:
        return (self.devices, self.approvals, self.other)


@dataclass(frozen=True)
class Event:
    """A relay event. `prev` is the root a `#commit`'s operations invert to;
    a `#sync` carries only the commit."""

    seq: int
    kind: str  # "commit" | "sync"
    commit: Commit
    prev: Optional[Root]
    time: float  # relay time: when the (honest) relay sequenced it, not when any witness got it
    hidden_from: FrozenSet[str] = frozenset()  # witnesses a dishonest relay never delivers it to
    claim: Optional[float] = None  # a time the PDS put on it, which only a non-reference relay passes on


class RelayWorld(World):
    """World plus commits, the reference relay, and PDS behaviour. The base
    collections are the PDS's current records; every honest write commits
    and is relayed.

    STAMP: the `time` a subscriber sees on an event. "sequenced" (the
    reference relay): the relay time at which it first sequenced the event,
    the same for every subscriber and on every replay. Two behaviours the
    sync specification allows an honest relay but NBD's reference relay
    must not have, kept for the limitation tests: "sent", the relay time at
    which it sends the event to each subscriber (refreshed on replay, and
    for a subscriber with a backlog), and "pds", a time the PDS chose and
    the relay passed on (`claim`)."""

    STAMP = "sequenced"

    def __init__(self):
        super().__init__()
        self.relay: List[Event] = []
        self.revs: Dict[str, int] = {}
        self.head: Dict[str, Commit] = {}  # latest commit the PDS made (relayed or not)
        self.forks: Dict[Tuple[str, str], Commit] = {}  # (viewer, account) -> commit served instead
        self.sync_served: Dict[Tuple[str, Root], Optional[FrozenSet[str]]] = {}
        self.withheld: Set[Tuple[str, str]] = set()  # (witness, account): fetches refused
        self.stalled: Set[Tuple[str, str]] = set()  # (witness, account): fetches never answer
        self.relay_hides: Dict[str, Set[str]] = {}  # dishonest relay: witness -> hidden accounts
        self.relay_up = True
        self.drop_next: Set[str] = set()  # accounts whose next commit an honest relay drops (rate limit)
        self.dropped: List[Commit] = []
        self.pds_clock: Dict[str, float] = {}  # per account: how far the PDS's clock is ahead
        self.witnesses: List["Witness"] = []
        self.other: Dict[str, int] = {}  # writes to other collections per account
        self._batch: Optional[List[str]] = None
        self._seq = 0

    # ---- honest writes: each commits and is relayed --------------------------

    def add_device(self, b: Binding) -> Binding:
        super().add_device(b)
        self._wrote(b.account)
        return b

    def delete_device(self, b: Binding) -> None:
        super().delete_device(b)
        self._wrote(b.account)

    def approve(self, signer: Binding, target: Binding) -> None:
        super().approve(signer, target)
        self._wrote(signer.account)

    def unapprove(self, signer: Binding, target: Binding) -> None:
        self.approvals.get(signer.account, set()).discard(Approval(signer, target))
        self._wrote(signer.account)

    @contextmanager
    def batch(self):
        """Writes inside commit once per account, as a link's record and
        approval do."""
        outer = self._batch
        if outer is None:
            self._batch = []
        try:
            yield
        finally:
            if outer is None:
                accounts, self._batch = self._batch, None
                for a in dict.fromkeys(accounts):
                    self.commit(a)

    def link(self, signer: Binding, new: Binding) -> Binding:
        with self.batch():
            self.add_device(new)
            self.approve(signer, new)
        return new

    def _wrote(self, account: str) -> None:
        if self._batch is not None:
            self._batch.append(account)
        else:
            self.commit(account)

    def root(self, account: str) -> Root:
        return (frozenset(self.devices.get(account, ())), frozenset(self.approvals.get(account, ())),
                self.other.get(account, 0))

    def post(self, account: str) -> Commit:
        """An honest write to another collection: a new root, no change to
        devices or approvals."""
        self.other[account] = self.other.get(account, 0) + 1
        return self.commit(account)

    def next_rev(self, account: str) -> int:
        """An honest PDS's next revision: its clock as a timestamp, kept
        above the previous one."""
        return max(self.revs.get(account, 0) + 1, rev_at(self.now + self.pds_clock.get(account, 0.0)))

    def commit(self, account: str, relay: bool = True, kind: str = "commit",
               prev=None, serve_to: Optional[FrozenSet[str]] = None,
               rev: Optional[int] = None, claim: Optional[float] = None) -> Commit:
        """Commit the account's current records. An honest `#commit` inverts
        to the PDS's previous commit; prev="relayed" inverts to the last
        relayed one instead, hiding that an unrelayed commit came between.
        An explicit `rev` is written as given and leaves the PDS's own
        revision clock where it was (a clock wrong once, or a lie)."""
        old = self.head.get(account)
        if rev is None:
            rev = self.revs[account] = self.next_rev(account)
        c = Commit(account, rev, *self.root(account))
        self.head[account] = c
        if relay and account in self.drop_next:
            self.drop_next.discard(account)  # an honest relay drops it, e.g. under a rate limit
            self.dropped.append(c)
            relay = False
        if relay:
            if prev == "relayed":
                last = self.relay_head(account)
                prev = last.commit.root if last else EMPTY
            elif prev is None:
                prev = old.root if old else EMPTY
            self._emit(kind, c, prev if kind == "commit" else None, claim)
            if kind == "sync" and serve_to is not None:
                self.sync_served[(account, c.root)] = serve_to
        return c

    def _emit(self, kind: str, c: Commit, prev: Optional[Root], claim: Optional[float] = None) -> Event:
        self._seq += 1
        hidden = frozenset(wn for wn, accts in self.relay_hides.items() if c.account in accts)
        if claim is None:
            claim = self.now + self.pds_clock.get(c.account, 0.0)  # the PDS's own clock
        e = Event(self._seq, kind, c, prev, self.now, hidden, claim)
        self.relay.append(e)
        return e

    def stamp(self, e: Optional[Event], t: float, witness: "Witness") -> float:
        """The `time` a witness sees on an event the relay sequenced at relay
        time `t` (`e` None: the firehose's other traffic, from honest PDSes)."""
        if self.STAMP == "sent":
            return max(t + witness.lag, witness.up_since)  # when the relay sends it to this subscriber
        if self.STAMP == "pds" and e is not None:
            return e.claim
        return t

    # ---- malicious PDS -----------------------------------------------------

    def pds_write(self, account: str, add=(), delete=(), approve=(), unapprove=(),
                  relay: bool = True, kind: str = "commit", prev=None,
                  serve_to: Optional[FrozenSet[str]] = None, rev: Optional[int] = None,
                  claim: Optional[float] = None) -> Commit:
        for b in add:
            self.devices.setdefault(account, set()).add(b)
        for b in delete:
            self.devices.get(account, set()).discard(b)
        for s, t in approve:
            self.approvals.setdefault(account, set()).add(Approval(s, t))
        for s, t in unapprove:
            self.approvals.get(account, set()).discard(Approval(s, t))
        return self.commit(account, relay=relay, kind=kind, prev=prev, serve_to=serve_to, rev=rev,
                           claim=claim)

    def republish(self, c: Commit, kind: str = "commit") -> Commit:
        """Publish an earlier commit again, at its own revision: the PDS puts
        its repo back as it was then and relays that commit once more, which
        a relay that passes on non-increasing revisions carries."""
        a = c.account
        self.devices[a], self.approvals[a], self.other[a] = set(c.devices), set(c.approvals), c.other
        old = self.head.get(a)
        self.head[a] = c
        self._emit(kind, c, (old.root if old else EMPTY) if kind == "commit" else None)
        return c

    def publish_sync(self, account: str, serve_to: Optional[FrozenSet[str]] = None, **writes) -> Commit:
        """A `#sync` event. Like any root, the PDS serves it while it is the
        current one; with `serve_to`, it serves it to those witnesses only,
        and keeps serving it to them until replaced."""
        return self.pds_write(account, kind="sync", serve_to=serve_to, **writes)

    def replace_sync(self, account: str) -> None:
        """Stop serving every earlier `#sync` root of the account."""
        for k in [k for k in self.sync_served if k[0] == account]:
            del self.sync_served[k]

    def fork(self, viewer: str, account: str, add=(), delete=(), approve=(),
             rev: Optional[int] = None) -> Commit:
        """Serve one viewer a validly signed commit the relay never saw, at a
        new revision or at an existing one."""
        d, a, o = self.head[account].root if account in self.head else EMPTY
        d = (set(d) | set(add)) - set(delete)
        a = set(a) | {Approval(s, t) for s, t in approve}
        if rev is None:
            rev = self.revs[account] = self.next_rev(account)
        c = Commit(account, rev, frozenset(d), frozenset(a), o)
        self.forks[(viewer, account)] = c
        return c

    def serve(self, viewer: str, commit: Commit) -> None:
        """Keep serving one viewer a given commit, such as one the PDS made
        and never relayed, or a proof the viewer fetched earlier."""
        self.forks[(viewer, commit.account)] = commit

    def unfork(self, viewer: str, account: str) -> None:
        self.forks.pop((viewer, account), None)

    def withhold(self, witness: str, account: str, on: bool = True) -> None:
        (self.withheld.add if on else self.withheld.discard)((witness, account))

    def stall(self, witness: str, account: str, on: bool = True) -> None:
        (self.stalled.add if on else self.stalled.discard)((witness, account))

    # ---- reads -------------------------------------------------------------

    def pds_serve(self, viewer: str, account: str) -> Optional[Commit]:
        return self.forks.get((viewer, account), self.head.get(account))

    def fetch(self, witness: str, account: str, root: Root) -> Optional[bool]:
        """Whether the PDS serves the repo at exactly this root to the
        witness: True, False, or None while it stalls."""
        if (witness, account) in self.withheld:
            return False
        if (witness, account) in self.stalled:
            return None
        if (account, root) in self.sync_served:
            served = self.sync_served[(account, root)]
            return served is None or witness in served
        return account in self.head and self.head[account].root == root

    def relay_head(self, account: str, witness: Optional[str] = None) -> Optional[Event]:
        for e in reversed(self.relay):
            if e.commit.account == account and (witness is None or witness not in e.hidden_from):
                return e
        return None

    def set_relay(self, up: bool) -> None:
        for wt in self.witnesses:
            if not up:
                wt.interrupted = True
            elif not self.relay_up:
                wt.up_since = self.now
        self.relay_up = up


class ClientView:
    """What the PDS serves one client: baseline clients read repos only here."""

    def __init__(self, world: RelayWorld, viewer: str):
        self._w = world
        self._viewer = viewer

    def _root(self, x: str) -> Root:
        c = self._w.pds_serve(self._viewer, x)
        return c.root if c else EMPTY

    def present(self, b: Binding) -> bool:
        return b in self._root(b.account)[0]

    def present_devices(self, x: str) -> Set[Binding]:
        return set(self._root(x)[0])

    def account_approvals(self, x: str) -> Set[Approval]:
        return set(self._root(x)[1])

    def accounts(self) -> Set[str]:
        return self._w.accounts() | {a for (v, a) in self._w.forks if v == self._viewer}

    def __getattr__(self, name):
        return getattr(self._w, name)


# ---- witness ---------------------------------------------------------------


@dataclass
class Entry:
    """One step of a witness's history of one account. A reconstructed entry
    carries the collections at its commit's exact root; a gap carries none
    and covers the account's revisions lo..hi (a commit the witness did not
    accept into the history for its revision has lo > hi: a gap at its place
    in relay order that covers no revision of its own). Positions are
    revisions, the same at every witness; `idx` is local to this witness and
    never leaves it. `pos` is the cursor after the entry: its last revision,
    except that a stream gap's interval can reach past the revision the
    witness resynchronized at, and the cursor moves only that far, so that
    commits relayed afterwards inside the interval are still read."""

    idx: int
    account: str
    kind: str  # "commit" (by inversion) | "sync" (a #sync, by fetch) | "start" | "resync"
    #           | "gap" | "stream-gap" | "future-rev" | "rev-not-increasing"
    lo: int
    hi: int
    commit: Optional[Commit]
    root: Optional[Root]
    rtime: float  # relay time of the event (when the relay sequenced it)
    wtime: float  # witness-clock time the witness handled it
    alarm: Optional[str] = None  # an integrity alarm the witness raised here
    cursor: Optional[int] = None  # the cursor after it, where not `hi`

    @property
    def reconstructed(self) -> bool:
        return self.root is not None

    @property
    def pos(self) -> int:
        return self.hi if self.cursor is None else self.cursor


class Witness:
    """An application's witness tailing the reference relay.

    Its frontier for an account is the relay time of the newest event it has
    processed in order, or, while a commit of the account awaits a fetch, that
    commit's relay time. The firehose carries the whole network, so the model
    treats the relay as sequencing other accounts' traffic at every instant:
    a witness subscribed with backlog `lag` has processed every event the
    relay sequenced up to `now - lag`. Frontier age is the witness's clock
    minus the frontier; a frontier more than CLOCK_SKEW ahead of its clock is
    a fault, reported as an infinite age. A fault stays until the witness is
    current again with its clock within CLOCK_SKEW of the relay's; a fault
    that cleared as soon as the frontier fell behind the slow clock would
    understate the age of a stalled witness by the clock's whole error.

    PENDING: "account" (the proposal: a commit awaiting a fetch holds only its
    account, whose later events queue behind it), "stream" (it holds the
    whole stream; finding 5) or "aside" (it holds nothing; finding 5).

    Revisions must strictly increase in relay order: a commit whose revision
    is not above the account's previous one is a gap and an integrity alarm.
    One more than REV_ALLOWANCE ahead of its event's relay time is a gap
    without an alarm, since a PDS clock can be wrong, and does not raise the
    account's latest revision. Neither is accepted into the history, so the
    account's next commit is reconstructed as one after a gap is.

    CONSECUTIVE: which two reconstructions bracket a commit the relay never
    published. "inverted" (the model's reading): the later one is a
    `#commit` whose operations inverted to the earlier one. "any" (the
    proposal's text): any two with no gap recorded between them, under which
    a `#sync` after a commit an honest relay dropped is a false alarm."""

    FETCH_TIMEOUT = FETCH_TIMEOUT
    PENDING = "account"
    CONSECUTIVE = "inverted"

    def __init__(self, world: RelayWorld, name: str, clock_offset: float = 0.0,
                 from_now: bool = False):
        self.world, self.name, self.clock_offset = world, name, clock_offset
        self.hist: Dict[str, List[Entry]] = {}  # retained history per account
        self.archive: List[Entry] = []  # never pruned; for checks only
        self.count = 0
        self.pos = 0  # next relay index: the witness's own subscription cursor
        self.stream_time = -INF  # relay time of the newest event processed in order
        self.skewed = False  # a clock-skew fault, latched until resolved
        self.state: Dict[str, Optional[Root]] = {}
        self.commits: Dict[str, Dict[int, Commit]] = {}
        self.latest: Dict[str, Entry] = {}
        self.last_rev: Dict[str, int] = {}  # revision processed through, per account
        self.missing: Dict[str, int] = {}  # revisions <= this were never in its history
        self.pruned_rev: Dict[str, int] = {}  # revisions <= this are past retention
        self.blocked: Dict[str, List[Tuple[Event, Optional[float]]]] = {}  # awaiting a fetch, then queued
        self.unplaced: Dict[str, List[Commit]] = {}  # relayed, not accepted into history for its revision
        self.alarms: List[Tuple[str, str, Commit]] = []  # (account, reason, commit)
        self.up = True
        self.reachable = True  # from clients
        self.lag = 0.0  # hours of backlog between the relay and this witness
        self.interrupted = False
        self.up_since = world.now  # real time the subscription last (re)opened
        world.witnesses.append(self)
        if from_now:  # start following every account at a verified repo
            self.pos = len(world.relay)
            for a in sorted(world.head):
                last = self._head_event(a)
                if last is not None:
                    ok = self._fetch_into(a, last, "start")
                    self.missing[a] = last.commit.rev - (1 if ok else 0)
                    self.last_rev[a] = last.commit.rev

    def wnow(self) -> float:
        return self.world.now + self.clock_offset

    def set_up(self, up: bool) -> None:
        if not up:
            self.interrupted = True
        elif not self.up:
            self.up_since = self.world.now
        self.up = up

    def _when(self, e: Optional[Event]) -> float:
        """The witness-clock time it handled an event: on delivery while
        subscribed (polling is lazy), or when its subscription reopened."""
        if e is None:
            return self.wnow()
        return min(self.wnow(), self.clock_offset + max(e.time + self.lag, self.up_since))

    def poll(self) -> None:
        w = self.world
        if not self.up or not w.relay_up:
            return
        self._drain()
        if self.PENDING == "stream" and self.blocked:
            return  # a stalled fetch holds the stream (and every frontier)
        if self.pos < len(w.relay) and (self.interrupted or self.lag >= RELAY_REPLAY_WINDOW) \
                and w.relay[self.pos].time < w.now - RELAY_REPLAY_WINDOW:
            self._stream_gap()  # the relay refuses a cursor older than its window
        self.interrupted = False
        horizon = w.now - self.lag
        while self.pos < len(w.relay) and w.relay[self.pos].time <= horizon + EPS:
            e = w.relay[self.pos]
            self.pos += 1
            self.stream_time = max(self.stream_time, self._t(e))
            if self.name in e.hidden_from:
                continue
            self._process(e)
            if self.PENDING == "stream" and self.blocked:
                return
        self.stream_time = max(self.stream_time, w.stamp(None, horizon, self))  # other accounts' traffic
        ahead = self.stream_time - self.wnow()
        if ahead > CLOCK_SKEW:
            self.skewed = True
        elif ahead >= -CLOCK_SKEW:
            self.skewed = False  # resolved: current, with a clock agreeing with the relay's
        self._prune()

    def _t(self, e: Event) -> float:
        """The relay `time` on an event as this witness receives it."""
        return self.world.stamp(e, e.time, self)

    def _append(self, a: str, kind: str, lo: int, hi: int, commit: Optional[Commit],
                root: Optional[Root], rtime: float, wtime: float, alarm: Optional[str] = None,
                cursor: Optional[int] = None) -> Entry:
        self.count += 1
        e = Entry(self.count, a, kind, lo, hi, commit, root, rtime, wtime, alarm, cursor)
        self.hist.setdefault(a, []).append(e)
        self.archive.append(e)
        return e

    def _record(self, a: str, kind: str, ev: Event, root: Root) -> None:
        c = ev.commit
        self.commits.setdefault(a, {})[c.rev] = c
        self.latest[a] = self._append(a, kind, c.rev, c.rev, c, root, self._t(ev), self._when(ev))
        self.state[a] = root
        self.last_rev[a] = max(self.last_rev.get(a, 0), c.rev)

    def _gap(self, a: str, ev: Event) -> None:
        c = ev.commit
        self.commits.setdefault(a, {})[c.rev] = c
        self._append(a, "gap", self.last_rev.get(a, 0) + 1, c.rev, c, None, self._t(ev), self._when(ev))
        self.state[a] = None
        self.last_rev[a] = max(self.last_rev.get(a, 0), c.rev)

    def _future(self, ev: Event) -> bool:
        return ev.commit.rev > rev_at(self._t(ev) + REV_ALLOWANCE)

    def _unplaced(self, a: str, ev: Event, kind: str, alarm: Optional[str]) -> None:
        """A relayed commit not accepted into the history for its revision: a
        gap at its place, raising neither the account's latest revision nor
        its cursor positions."""
        c, last = ev.commit, self.last_rev.get(a, 0)
        self.unplaced.setdefault(a, []).append(c)
        self._append(a, kind, last + 1, last, c, None, self._t(ev), self._when(ev), alarm)
        self.state[a] = None
        if alarm:
            self.alarms.append((a, alarm, c))

    def _head_event(self, a: str) -> Optional[Event]:
        """The relay's latest commit for the account that a witness can
        resynchronize at: not hidden from it, and not ahead of its time."""
        for e in reversed(self.world.relay):
            if e.commit.account == a and self.name not in e.hidden_from and not self._future(e):
                return e
        return None

    def _fetch_into(self, a: str, ev: Event, kind: str) -> bool:
        if self.world.fetch(self.name, a, ev.commit.root):
            self._record(a, kind, ev, ev.commit.root)
            return True
        self.state[a] = None
        return False

    def _process(self, e: Event) -> None:
        a = e.commit.account
        if a in self.blocked:
            self.blocked[a].append((e, None))  # in order, behind the commit awaiting a fetch
            return
        if self._future(e):
            self._unplaced(a, e, "future-rev", None)  # a PDS clock can simply be wrong
            return
        if e.commit.rev <= self.last_rev.get(a, 0):
            self._unplaced(a, e, "rev-not-increasing", f"revision not increasing {a} rev {e.commit.rev}")
            return
        cur = self.state.get(a, EMPTY)
        if e.kind == "commit" and cur is not None and e.prev == cur:
            self._record(a, "commit", e, e.commit.root)  # operations invert to the previous root
            return
        if e.kind == "commit":
            if cur is not None:
                self._gap(a, e)  # operations fail inversion
            if not self._fetch_into(a, e, "resync") and cur is None:
                self._gap(a, e)
            return
        res = self.world.fetch(self.name, a, e.commit.root)  # #sync: fetch the exact root
        if res is None:
            self.blocked[a] = [(e, self.wnow())]
            return
        if res:
            self._record(a, "sync", e, e.commit.root)
        else:
            self._gap(a, e)

    def _drain(self) -> None:
        """Retry each account's outstanding fetch; once it succeeds or times
        out (a gap), process that account's queued events in order."""
        for a in sorted(self.blocked):
            q = self.blocked[a]
            e, since = q[0]
            res = self.world.fetch(self.name, a, e.commit.root)
            if res is None and self.wnow() - since < self.FETCH_TIMEOUT:
                continue
            del self.blocked[a]
            if res:
                self._record(a, "sync", e, e.commit.root)
            else:
                self._gap(a, e)
            for e2, _ in q[1:]:
                self._process(e2)

    def _stream_gap(self) -> None:
        """A stream gap is a gap in every account's history, even one the
        witness resynchronizes at the revision it already held: a relay that
        passes on non-increasing revisions may have carried higher revisions
        in between (an impostor, then the original replayed). Any revision up
        to REV_ALLOWANCE past the relay's time when it resumed could have been
        accepted by another witness, so the interval runs that far, past the
        revision it resynchronizes at; the cursor after it moves only to that
        revision."""
        w = self.world
        self.pos = len(w.relay)
        bound = rev_at(w.stamp(None, w.now, self) + REV_ALLOWANCE)
        for a in sorted(set(self.state) | set(w.head) | set(self.blocked)):
            for e, _ in self.blocked.pop(a, []):
                self._gap(a, e)  # unprocessed when the stream broke
            last = self._head_event(a)  # resynchronize at the latest published root
            if last is None:
                continue
            r, known = last.commit.rev, a in self.state
            if known:
                cur, held = self.last_rev.get(a, 0), self.commits.get(a, {}).get(r)
                self._append(a, "stream-gap", cur + 1, max(cur + 1, r, bound), None, None,
                             self._t(last), self.wnow(), cursor=max(cur, r))
                if r == cur and self.state[a] is not None and held == last.commit:
                    continue  # it already holds that root; the gap stands
                if r < cur or (r == cur and held != last.commit):
                    self._unplaced(a, last, "rev-not-increasing", f"revision not increasing {a} rev {r}")
                    continue
            self.state[a] = None
            ok = self._fetch_into(a, last, "resync")
            self.commits.setdefault(a, {})[r] = last.commit
            if not known:
                self.missing[a] = r - (1 if ok else 0)
            self.last_rev[a] = max(self.last_rev.get(a, 0), r)

    def _prune(self) -> None:
        cutoff = self.wnow() - WITNESS_RETENTION
        for a, h in self.hist.items():
            while h and h[0].wtime < cutoff:
                e = h.pop(0)
                self.pruned_rev[a] = max(self.pruned_rev.get(a, 0), e.hi)

    # ---- answers -----------------------------------------------------------

    def read(self, account: str, after: int) -> List[Entry]:
        """The retained history of the account after revision `after`."""
        return [e for e in self.hist.get(account, []) if e.hi > after or e.lo > after]

    def frontier(self, account: str) -> float:
        f = self.stream_time
        q = self.blocked.get(account)
        if q and self.PENDING != "aside":
            f = min(f, self._t(q[0][0]))  # a commit awaiting a fetch holds its account's frontier
        return f

    def frontier_age(self, account: str) -> float:
        if self.skew_fault(account):
            return INF  # a frontier ahead of the witness's clock: a fault, exceeding any limit
        return self.wnow() - self.frontier(account)

    def skew_fault(self, account: str) -> bool:
        return self.skewed or self.frontier(account) > self.wnow() + CLOCK_SKEW

    def lacks(self, account: str) -> Tuple[int, str]:
        """The account's revisions this witness does not have: every revision
        up to the first, older than its retention or before its history."""
        p, m = self.pruned_rev.get(account, 0), self.missing.get(account, 0)
        return (p, "retention") if p >= m else (m, "before history")

    def latest_rec(self, account: str) -> Optional[Entry]:
        return self.latest.get(account)

    def commit_at(self, account: str, rev: int) -> Optional[Commit]:
        return self.commits.get(account, {}).get(rev)

    def max_rev(self, account: str) -> int:
        return max(self.commits.get(account, {0: None}))

    def reports_unplaced(self, account: str, commit: Commit) -> bool:
        """Whether the relay published this commit and the witness recorded
        it as a gap without accepting it into the history."""
        return commit in self.unplaced.get(account, ())

    def unrelayed_between(self, account: str, rev: int) -> Optional[Tuple[Commit, Commit]]:
        """The two commits the witness reconstructed consecutively, with no
        gap recorded between them, whose revisions `rev` falls strictly
        between: there the relay published nothing."""
        prev = None
        for e in self.hist.get(account, []):
            if not e.reconstructed:
                prev = None
                continue
            if prev is not None and prev.hi < rev < e.lo and (self.CONSECUTIVE == "any" or e.kind == "commit"):
                return prev.commit, e.commit
            prev = e
        return None


class LyingWitness(Witness):
    """A dishonest witness: it reports a commit the relay never published as
    published and reconstructed."""

    def lie(self, commit: Commit) -> None:
        self.commits.setdefault(commit.account, {})[commit.rev] = commit
        self.latest[commit.account] = Entry(10 ** 9, commit.account, "commit", commit.rev, commit.rev,
                                            commit, commit.root, self.world.now, self.wnow())


class RogueWitness:
    """A source other than the client's own witness, such as a PDS acting as
    a witness, offering a validly signed commit that the relay never saw."""

    def __init__(self, commit: Commit):
        self.entry = Entry(10 ** 9, commit.account, "commit", commit.rev, commit.rev, commit,
                           commit.root, 0.0, 0.0)

    def latest_rec(self, account: str) -> Optional[Entry]:
        return self.entry if account == self.entry.account else None



# ---- client ----------------------------------------------------------------


@dataclass
class Gap:
    """Revisions lo..hi of an account's history that could not be checked."""

    lo: int
    hi: int
    kind: str
    acknowledged: bool = False
    at: Optional[int] = None  # a commit not accepted into the history: its revision

    def covers(self, rev: int) -> bool:
        return self.lo <= rev <= self.hi

    def key(self) -> tuple:
        return (self.lo, self.hi, self.kind, self.at)


@dataclass
class WitnessState(InviterState):
    own: Optional[Binding] = None
    cursors: Dict[str, int] = field(default_factory=dict)  # account -> repo revision processed through
    obs: Dict[str, Root] = field(default_factory=dict)  # pinned account -> collections applied
    obs_rev: Dict[str, int] = field(default_factory=dict)
    proven: Dict[Binding, int] = field(default_factory=dict)  # binding -> revision first seen present
    read_from: Optional[int] = None  # revision this installation's own history starts after
    gaps: List[Gap] = field(default_factory=list)  # own account's historical gaps
    audit_gaps: Dict[str, List[Gap]] = field(default_factory=dict)  # pinned accounts
    seen_own: Set[Binding] = field(default_factory=set)
    own_alarms: Set[Binding] = field(default_factory=set)
    presented: Set[Binding] = field(default_factory=set)  # shown at fresh enrollment to recognize
    notices: Set[Binding] = field(default_factory=set)  # own bindings this installation did not approve
    forks: List[Tuple[Commit, Commit]] = field(default_factory=list)
    unrelayed: List[Tuple[Commit, Commit, Commit]] = field(default_factory=list)  # (before, served, after)
    basis: Dict[Binding, Tuple[int, float]] = field(default_factory=dict)  # accepted -> (revision, real time)
    cov_base: float = INF  # coverage age at the wall checkpoint
    cov_wall: Optional[float] = None

    def copy(self) -> "WitnessState":
        return copy.deepcopy(self)


@dataclass
class Answer:
    """A witness's answer about the own account, computed when the first
    page's request reaches it: the history after a cursor (each entry with
    the cursor after it), what the witness lacks, and its frontier age at
    that moment. Later pages are served from the same answer."""

    after: int
    lacks: Tuple[int, str]
    entries: List[Tuple[Entry, int]]
    frontier_age: float

    def pages(self, size: Optional[int]) -> List[List[Tuple[Entry, int]]]:
        if not size or not self.entries:
            return [self.entries]
        return [self.entries[i:i + size] for i in range(0, len(self.entries), size)]


@dataclass
class Request:
    """An installation's outstanding request for an answer, possibly in
    pages. Times are its monotonic clock when it sent each page's request."""

    answer: Answer
    epoch: int  # requests sent before a restart are discarded
    first_sent: float  # the first page's request
    sent: float  # the latest page's request
    fresh: bool  # a fresh enrollment's replay
    page: int = 0  # pages processed


class WitnessedView:
    """The repo reads a WitnessClient decides on: for a pinned account, the
    collections at the last witnessed commit it processed; otherwise the
    latest commit its trusted witness reconstructed."""

    def __init__(self, world: RelayWorld, client: "WitnessClient"):
        self._w = world
        self._c = client

    def _root(self, x: str) -> Root:
        st = self._c.state
        if x in st.obs:
            return st.obs[x]
        lr = self._c._latest(x)
        return lr.root if lr else EMPTY

    def present(self, b: Binding) -> bool:
        return b in self._root(b.account)[0]

    def present_devices(self, x: str) -> Set[Binding]:
        return set(self._root(x)[0])

    def account_approvals(self, x: str) -> Set[Approval]:
        return set(self._root(x)[1])

    def accounts(self) -> Set[str]:
        return set(self._c.witness.commits) | set(self._c.state.obs)

    def __getattr__(self, name):
        return getattr(self._w, name)


class WitnessClient(InviterClient):
    """InviterClient under the relay-witness rules: acceptance and removal
    only on commits its own witness reports as published and reconstructed;
    every witnessed commit of each pinned account processed in order; its own
    account's whole history watched from a persisted cursor, with gap
    warnings and a liveness warning on coverage age."""

    FRESH_HISTORY_GAP = True  # finding 2's fix: history the witness lacks is a gap at enrollment too
    PAGE_SIZE: Optional[int] = None  # history entries per page of an answer; None: one page
    MONO_COUNTS_SUSPEND = True  # finding 3: a monotonic clock that stops in suspend
    EXEMPT_UNCHANGED = True  # finding 13's fix: an unrelayed commit with the earlier one's data is no alarm

    def __init__(self, world: RelayWorld, own: Binding, witness: Witness,
                 clock_offset: float = 0.0, transfer: Optional[WitnessState] = None):
        super().__init__(world, own, clock_offset)
        self.relay_world = world
        self.world = WitnessedView(world, self)
        self.witness = witness
        self.name = repr(own)
        self.sources: list = []  # other sources offering commits; never trusted
        self.running = True
        self.suspended = 0.0
        self._mono_ck: Optional[float] = None
        self._epoch = 0
        self._boot = world.now  # the monotonic clock counts from the latest start
        if transfer is None:
            self.state = WitnessState(accepted={own: "own"}, own=own)
        else:  # restore or pairing: resume from the transferred cursor, on any witness
            st = self.state = transfer.copy()
            st.accepted[own] = "own"
            st.own = own
            st.read_from = st.cursors.get(own.account, 0)
            st.cov_base, st.cov_wall = INF, None  # coverage of another installation's clock is unknown here
        self._mono_ck = self.mono()

    @classmethod
    def restore(cls, world: RelayWorld, backup: WitnessState, witness: Witness,
                clock_offset: float = 0.0) -> "WitnessClient":
        c = cls(world, backup.own, witness, clock_offset, transfer=backup)
        c.sync()
        return c

    # ---- clocks and liveness ----------------------------------------------

    def mono(self) -> float:
        return self.relay_world.now - self._boot - (0.0 if self.MONO_COUNTS_SUSPEND else self.suspended)

    def wall(self) -> float:
        return self.local_now()

    def coverage_age(self) -> float:
        if self.state.cov_base == INF or self._mono_ck is None:
            return INF
        return self.state.cov_base + (self.mono() - self._mono_ck)

    def liveness_warning(self) -> bool:
        return self.running and self.coverage_age() > LIVENESS_LIMIT

    def _checkpoint(self) -> None:
        if self.running:
            self.state.cov_base = self.coverage_age()
            self.state.cov_wall = self.wall()
            self._mono_ck = self.mono()

    def stop(self) -> None:
        self._checkpoint()
        self.running = False
        self._mono_ck = None
        self._epoch += 1  # the monotonic clock restarts: outstanding requests are dropped

    def start(self) -> None:
        st = self.state
        d = None if st.cov_wall is None else self.wall() - st.cov_wall
        st.cov_base = INF if d is None or d < 0 else st.cov_base + d
        self.running = True
        self._boot = self.relay_world.now
        self._mono_ck = self.mono()
        st.cov_wall = self.wall()
        self.sync()

    def gap_warnings(self) -> List[Gap]:
        return [g for g in self.state.gaps if not g.acknowledged]

    def acknowledge(self, gap: Gap) -> None:
        gap.acknowledged = True

    def gap_covers(self, rev: int) -> bool:
        return any(g.covers(rev) for g in self.state.gaps)

    def consult(self, source) -> None:
        self.sources.append(source)

    # ---- decisions ----------------------------------------------------------

    def sync(self) -> None:
        """Request an answer, receive it at once (every page), and follow
        every account."""
        if not self.running:
            return
        req = self.request()
        if req is not None:
            self._follow(req)
        else:
            self._observe()
        self._checkpoint()

    def request(self) -> Optional[Request]:
        """Send the first page's request for the own account's history; the
        witness computes its answer as the request reaches it. None while
        stopped or the witness is unreachable."""
        if not self.running:
            return None
        self.witness.poll()
        if not self.witness.reachable:
            return None
        own, w = self.own.account, self.witness
        cur, fresh = self._start_cursor(own)
        ans = Answer(cur, w.lacks(own), self._resume(w, own, cur), w.frontier_age(own))
        return Request(ans, self._epoch, self.mono(), self.mono(), fresh)

    def deliver(self, req: Request) -> bool:
        """The response to the request's outstanding page arrives now and is
        processed. If pages remain, the next page's request is sent at once
        (False); once the whole answer is processed, the monitoring frontier
        advances (True). A response to a request sent before a restart is
        dropped."""
        if req.epoch != self._epoch or not self.running:
            return True
        ans, n = req.answer, req.page
        pages = ans.pages(self.PAGE_SIZE)
        self._follow_account(self.own.account, ans.after, ans.lacks if n == 0 else (0, ""), pages[n], req.fresh)
        req.page += 1
        if req.page < len(pages):
            req.sent = self.mono()  # the next page's request
            return False
        self._advance(ans.frontier_age, req.first_sent)
        return True

    def _advance(self, age: float, sent: float) -> None:
        """The monitoring frontier advances to an answer's. Coverage age is
        the frontier age the witness reported plus the local time elapsed
        since the installation sent the request that produced the answer
        (the first page's, for an answer in pages), so an answer delayed in
        transit cannot make old coverage look fresh. An answer older than
        the coverage already held does not move it back; a clock fault the
        witness reports counts at once."""
        st = self.state
        age = age + (self.mono() - sent)
        st.cov_base = age if age == INF else min(self.coverage_age(), age)
        self._mono_ck = self.mono()
        st.cov_wall = self.wall()

    def accepted(self, b: Binding, space: str = ""):
        self.sync()
        if self._incomplete(b.account):
            return INCOMPLETE
        self._decide(b.account)
        return b in self.state.accepted and b not in self.state.revoked

    def hold_pending(self, account: str, space: str = ""):
        self.sync()
        if self._incomplete(account):
            return INCOMPLETE
        self._decide(account)
        return account in self.state.holds

    def standing(self, b: Binding, space: str):
        self.sync()
        if self._incomplete(b.account):
            return INCOMPLETE
        self._decide(b.account)
        self._tick()
        return self._usable(b) and b in self.state.accepted and self._source(b, space, set())

    def invite(self, space: str, account: str):
        self.sync()
        if self._incomplete(account):
            return INCOMPLETE
        before = set(self.state.accepted)
        rec = super().invite(space, account)
        self._pin_new(account)
        self._record_basis(account, self._rev_of(account), before)
        return rec

    def export_state(self) -> WitnessState:
        self._tick()
        self._checkpoint()
        return self.state.copy()

    def import_state(self, other) -> None:
        st = self.state
        if isinstance(other, WitnessState):
            for x, cur in other.cursors.items():
                if x not in st.cursors and x != self.own.account:
                    st.cursors[x] = cur
                    if x in other.obs:
                        st.obs[x], st.obs_rev[x] = other.obs[x], other.obs_rev[x]
            for b, s in other.proven.items():
                st.proven.setdefault(b, s)
            for g in other.gaps:
                if not any(h.key() == g.key() for h in st.gaps):
                    st.gaps.append(copy.copy(g))
            st.own_alarms |= other.own_alarms
            st.notices |= other.notices
            st.presented |= other.presented
            st.seen_own |= other.seen_own
            st.forks += [f for f in other.forks if f not in st.forks]
            st.unrelayed += [f for f in other.unrelayed if f not in st.unrelayed]
            for b, v in other.basis.items():
                st.basis.setdefault(b, v)
        super().import_state(other)

    # ---- rules --------------------------------------------------------------

    def _latest(self, x: str) -> Optional[Entry]:
        """The latest commit a trusted source reports as published and
        reconstructed: only this client's own witness."""
        best = None
        for src in [self.witness] + self.sources:
            if src is not self.witness:
                continue
            lr = src.latest_rec(x)
            if lr is not None and (best is None or lr.commit.rev > best.commit.rev):
                best = lr
        return best

    def _rev_of(self, x: str) -> int:
        if x in self.state.obs_rev:
            return self.state.obs_rev[x]
        lr = self._latest(x)
        return lr.hi if lr else 0

    def _incomplete(self, x: str) -> bool:
        """A commit the PDS serves that the witness does not report yet
        means wait; one that differs from the witnessed commit at its
        revision is a fork, and one whose revision falls strictly between
        two commits the witness reconstructed consecutively is a commit the
        PDS never relayed (unless its data equals the earlier one's). Anywhere else (inside a recorded gap, or above
        the witness's latest revision) it raises nothing."""
        if not self.witness.reachable:
            return True
        c = self.relay_world.pds_serve(self.name, x)
        if c is None:
            return False
        wc = self.witness.commit_at(x, c.rev)
        if wc is not None:
            if wc != c and (wc, c) not in self.state.forks:
                self.state.forks.append((wc, c))
                self.state.alarms.append(f"fork {x} rev {c.rev}")
            return False
        if self.witness.reports_unplaced(x, c):
            return False  # published, and reported as a gap
        around = self.witness.unrelayed_between(x, c.rev)
        if around is not None and self.EXEMPT_UNCHANGED and c.root == around[0].root:
            return False  # a commit that changes nothing hides nothing
        if around is not None:
            proof = (around[0], c, around[1])
            if proof not in self.state.unrelayed:
                self.state.unrelayed.append(proof)
                self.state.alarms.append(f"unrelayed {x} rev {c.rev}")
            return False
        return c.rev > self.witness.max_rev(x)

    def _decide(self, x: str) -> None:
        before = set(self.state.accepted)
        self._first_use(x)
        self._approvals()
        self._pin_new(x)
        self._record_basis(x, self._rev_of(x), before)

    def _pin_new(self, x: str) -> None:
        """An account this client just came to know is followed from the
        witnessed commit it was met at."""
        st = self.state
        if x in st.cursors or x == self.own.account or not self._knew(x):
            return
        e = self._latest(x)
        if e is None:
            return
        st.cursors[x] = e.hi
        st.obs[x], st.obs_rev[x] = e.root, e.hi
        for b in e.root[0]:
            st.proven.setdefault(b, e.hi)

    def _record_basis(self, x: str, rev: int, before: Set[Binding]) -> None:
        for b in set(self.state.accepted) - before:
            if b.account != self.own.account:
                self.state.basis.setdefault(b, (rev, self.relay_world.now))

    def _follow(self, req: Request) -> None:
        own = self.own.account
        for x in sorted({own} | {b.account for b in self.state.accepted}):
            if x == own:
                while not self.deliver(req):  # every page, at once
                    pass
            else:
                self._follow_account(x)
        self._incomplete(own)  # compare what the PDS serves this installation of its own repo

    def _start_cursor(self, x: str) -> Tuple[int, bool]:
        """The cursor to read the own account's history from, and whether
        this is a fresh enrollment, which replays it from its first event."""
        st = self.state
        if x in st.cursors:
            return st.cursors[x], False
        st.read_from = 0
        st.cursors[x] = 0
        return st.cursors[x], True

    def _follow_account(self, x: str, after: Optional[int] = None, lacks: Optional[Tuple[int, str]] = None,
                        entries: Optional[List[Tuple[Entry, int]]] = None, fresh: bool = False) -> None:
        """Process the account's history after its cursor: read from the
        witness now (pinned accounts), or a page of an answer (the own
        account; `after` is the cursor the answer was computed from)."""
        st, w = self.state, self.witness
        own = x == self.own.account
        if x not in st.cursors:
            self._pin_new(x)
            if x not in st.cursors:
                return
        cur = st.cursors[x] if after is None else after
        lack, kind = w.lacks(x) if lacks is None else lacks  # revisions after the cursor it lacks
        if lack > cur and (self.FRESH_HISTORY_GAP or not fresh):
            self._gap(x, Gap(cur + 1, lack, kind))
        if entries is None:
            entries = self._resume(w, x, cur)
        for e, pos in entries:
            if e.reconstructed:
                st.obs[x], st.obs_rev[x] = e.root, e.hi
                before = set(st.accepted)
                self._observe()
                self._approvals()
                self._record_basis(x, e.hi, before)
                if own:
                    self._watch_own(e, fresh, before)
            else:
                self._gap(x, Gap(e.lo, e.hi, e.kind, at=e.commit.rev if e.lo > e.hi and e.commit else None))
                if e.alarm and e.alarm not in st.alarms:
                    st.alarms.append(e.alarm)  # an integrity alarm the witness raised
            st.cursors[x] = max(st.cursors[x], pos)

    def _resume(self, w: Witness, x: str, cur: int) -> List[Tuple[Entry, int]]:
        """The witness's history of x after cursor `cur`, each entry with the
        cursor after it: the account's repo revision, the same at every witness."""
        return [(e, e.pos) for e in w.read(x, cur)]

    def _gap(self, x: str, g: Gap) -> None:
        gaps = self.state.gaps if x == self.own.account else self.state.audit_gaps.setdefault(x, [])
        if not any(h.key() == g.key() for h in gaps):
            gaps.append(g)

    def _observe(self) -> None:
        """InviterClient.sync against the current witnessed collections,
        revoking a binding only on a commit after one that proved it present."""
        st = self.state
        self._tick()
        for b in set(st.accepted) | st.candidates_seen:
            if b in st.revoked:
                continue
            rev = self._rev_of(b.account)
            if self.world.present(b):
                st.proven.setdefault(b, rev)
            elif b in st.proven and rev > st.proven[b]:
                st.revoked.add(b)
        for b in st.revoked:
            if self.world.present(b) and f"resurrected {b}" not in st.alarms:
                st.alarms.append(f"resurrected {b}")
        self._own_removal_alarm()
        self._reconcile_holds()
        self._own_invites()
        if self.auto_flush:
            self.flush()

    def _watch_own(self, e: Entry, fresh: bool, before: Set[Binding]) -> None:
        """Own-account notices and alarms for every device record and
        approval in every reconstructed commit, not only the latest."""
        st = self.state
        devices, approvals, _other = e.root
        mentioned = set(devices) | {a.signer for a in approvals} | {a.target for a in approvals}
        st.seen_own |= mentioned
        for b in mentioned:
            if b.account != self.own.account or b in st.accepted:
                continue
            if fresh:
                st.presented.add(b)
            elif b not in st.presented:
                st.own_alarms.add(b)
        for b in set(st.accepted) - before:
            if b.account == self.own.account:
                (st.presented if fresh else st.notices).add(b)


# ---- the goal --------------------------------------------------------------


def detected(o: WitnessClient, b: Binding, rev: int) -> bool:
    st = o.state
    return b in st.own_alarms or b in st.notices or b in st.presented or o.gap_covers(rev)


def goal_violations(account: str, installations: List[WitnessClient],
                    clients: List[WitnessClient], legit: Set[Binding], now: float,
                    slack: float = 0.0) -> List[str]:
    """Every binding of `account` that an honest client accepted and that
    none of the account's installations generated, transferred, or approved
    (`legit`) must appear in, or leave a gap in, the history each of the
    account's installations read (positions are repo revisions, so histories
    read from different witnesses compare); and every installation running
    more than 24 hours (plus `slack`) after the acceptance must have alarmed
    (or noticed, or presented it at enrollment), recorded a gap covering it,
    or show the liveness warning. ("More than": coverage age must exceed 24
    hours, so a device accepted at the very instant of the frontier warns an
    instant after 24.)"""
    out = []
    for c in clients:
        if c.own.account == account:
            continue
        for b, (rev, t) in sorted(c.state.basis.items(), key=repr):
            if b.account != account or b in legit:
                continue
            for o in installations:
                st = o.state
                cur = st.cursors.get(account)
                if (cur is not None and st.read_from is not None and st.read_from < rev <= cur
                        and b not in st.seen_own and not o.gap_covers(rev)):
                    out.append(f"{b}, accepted by {c.name} at rev {rev}, is neither in nor a gap "
                               f"in the history {o.name} read")
                if o.running and now - t > LIVENESS_LIMIT + slack + EPS \
                        and not detected(o, b, rev) and not o.liveness_warning():
                    out.append(f"{o.name} neither alarmed nor warned about {b} "
                               f"{now - t:.1f}h after {c.name} accepted it")
    return out
