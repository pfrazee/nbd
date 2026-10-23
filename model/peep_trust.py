"""Executable model of PEEP device trust: accepted(binding, space).

Models the rules in device-enrollment.md (local trust, first-use anchors,
acceptance in a space, revocation, re-enrollment) abstractly. There is no
cryptography: a record "signed by" a binding is valid exactly when whoever
created it held that binding's key, and tests only create records the
creating party could sign. Repos hold the current state the client would
prove by enumeration; deleting a record is revocation.

Stdlib only; Python 3.9.
"""

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

REENROLL_HOLD = 72.0  # hours


@dataclass(frozen=True)
class Binding:
    account: str
    device: str

    def __repr__(self) -> str:
        return f"{self.account}/{self.device}"


@dataclass(frozen=True)
class Approval:
    """An approval record in the signer's (same) account repo."""

    signer: Binding
    target: Binding


@dataclass(frozen=True)
class Grant:
    """A grant record in the issuer account's space repo.

    The model never decrypts: a grant may carry garbage, and third parties
    cannot tell. `provenance` is the id of the grant the issuing device
    used to obtain the key, or None for the creator's generated key.
    """

    gid: str
    space: str
    issuer: Binding
    recipient: Binding
    provenance: Optional[str] = None


@dataclass
class World:
    """Public state: account repos, grants, and host membership."""

    devices: Dict[str, Set[Binding]] = field(default_factory=dict)
    approvals: Dict[str, Set[Approval]] = field(default_factory=dict)
    grants: Dict[str, Grant] = field(default_factory=dict)
    members: Dict[str, Set[str]] = field(default_factory=dict)
    now: float = 0.0

    # Repo writes. Callers model who could make them.

    def add_device(self, b: Binding) -> Binding:
        self.devices.setdefault(b.account, set()).add(b)
        return b

    def delete_device(self, b: Binding) -> None:
        self.devices.get(b.account, set()).discard(b)

    def approve(self, signer: Binding, target: Binding) -> None:
        assert signer.account == target.account, "approvals are same-account"
        self.approvals.setdefault(signer.account, set()).add(Approval(signer, target))

    def grant(self, gid: str, space: str, issuer: Binding, recipient: Binding,
              provenance: Optional[str] = None) -> Grant:
        g = Grant(gid, space, issuer, recipient, provenance)
        self.grants[gid] = g
        return g

    def admit(self, space: str, *accounts: str) -> None:
        self.members.setdefault(space, set()).update(accounts)

    def remove_member(self, space: str, account: str) -> None:
        self.members.get(space, set()).discard(account)

    # Reads (what an enumeration at a verified commit proves).

    def present(self, b: Binding) -> bool:
        return b in self.devices.get(b.account, set())

    def present_devices(self, account: str) -> Set[Binding]:
        return set(self.devices.get(account, set()))

    def account_approvals(self, account: str) -> Set[Approval]:
        return set(self.approvals.get(account, set()))

    def eligible(self, account: str, space: str) -> bool:
        return account in self.members.get(space, set())

    def accounts(self) -> Set[str]:
        return set(self.devices) | set(self.approvals)


@dataclass
class ClientState:
    """Persisted bases, not flattened results (spec: persistence and restore)."""

    account_wide: Set[Binding] = field(default_factory=set)
    scoped_pins: Dict[str, Set[Binding]] = field(default_factory=dict)
    revoked: Set[Binding] = field(default_factory=set)
    history_all: Set[Binding] = field(default_factory=set)
    history_space: Dict[str, Set[Binding]] = field(default_factory=dict)
    holds: Dict[Tuple[str, Optional[str]], float] = field(default_factory=dict)
    alarms: List[str] = field(default_factory=list)

    def copy(self) -> "ClientState":
        return ClientState(
            set(self.account_wide),
            {s: set(v) for s, v in self.scoped_pins.items()},
            set(self.revoked),
            set(self.history_all),
            {s: set(v) for s, v in self.history_space.items()},
            dict(self.holds),
            list(self.alarms),
        )


class Client:
    """One installation's view and decisions."""

    def __init__(self, world: World, own: Binding):
        self.world = world
        self.own = own
        self.state = ClientState(account_wide={own}, history_all={own})

    # ---- public API ------------------------------------------------------

    def pair(self, *bindings: Binding) -> None:
        """Pins copied from the user's own installation (basis 1)."""
        self.state.account_wide.update(bindings)
        self.state.history_all.update(bindings)

    def accepted(self, b: Binding, space: str) -> bool:
        """accepted(b, S), running first use / re-enrollment for b's account."""
        self.sync()
        self._first_use(b.account, space)
        return b in self.accepted_in(space)

    def hold_pending(self, account: str, space: str) -> bool:
        self.sync()
        self._first_use(account, space)
        return any(k[0] == account and (k[1] in (None, space)) and
                   self.world.now - t < REENROLL_HOLD
                   for k, t in self.state.holds.items())

    def sync(self) -> None:
        """Observe repo state: absence of an accepted binding revokes it."""
        st = self.state
        ever = set(st.history_all)
        for hs in st.history_space.values():
            ever |= hs
        for b in ever:
            if b not in st.revoked and not self.world.present(b):
                st.revoked.add(b)
        for b in st.revoked:
            if self.world.present(b):
                msg = f"resurrected {b}"
                if msg not in st.alarms:
                    st.alarms.append(msg)

    def export_state(self) -> ClientState:
        return self.state.copy()

    def import_state(self, other: ClientState) -> None:
        """Merge bases from the user's own installation. Never widens:
        scoped pins stay scoped, revocations union, holds keep earliest."""
        st = self.state
        st.account_wide |= other.account_wide
        for s, v in other.scoped_pins.items():
            st.scoped_pins.setdefault(s, set()).update(v)
        st.revoked |= other.revoked
        st.history_all |= other.history_all
        for s, v in other.history_space.items():
            st.history_space.setdefault(s, set()).update(v)
        for k, t in other.holds.items():
            st.holds[k] = min(t, st.holds.get(k, t))

    # ---- acceptance in a space -------------------------------------------

    def usable(self, b: Binding) -> bool:
        return b not in self.state.revoked and self.world.present(b)

    def account_wide_set(self) -> Set[Binding]:
        """Basis 1: pins plus approvals from account-wide bindings."""
        st = self.state
        acc = {b for b in st.account_wide}
        acc = self._approval_closure(acc, st.history_all)
        st.history_all |= {b for b in acc if self.usable(b)}
        return {b for b in acc if self.usable(b)}

    def accepted_in(self, space: str) -> Set[Binding]:
        st = self.state
        hist = st.history_space.setdefault(space, set())
        acc = self.account_wide_set() | {
            b for b in st.scoped_pins.get(space, set()) if self.usable(b)}
        while True:
            grown = self._approval_closure(acc, hist | st.history_all)
            for x in self.world.accounts():
                # Witnesses serve first use only: an account pinned
                # account-wide adds devices by approval alone.
                if self._pinned_account_wide(x):
                    continue
                anchors = self.anchors(x, space, grown)
                if anchors:
                    grown |= {b for b in self._reach(x, anchors) if self.usable(b)}
            grown = {b for b in grown if self.usable(b)}
            if grown <= acc:
                break
            acc |= grown
        hist |= acc
        return acc

    def _approval_closure(self, acc: Set[Binding], hist: Set[Binding]) -> Set[Binding]:
        """Basis 2. An approver qualifies if accepted here, or if it was
        accepted here before its revocation (approvals survive revocation)."""
        acc = set(acc)
        while True:
            added = set()
            for x in self.world.accounts():
                for ap in self.world.account_approvals(x):
                    signer_ok = ap.signer in acc or (
                        ap.signer in self.state.revoked and ap.signer in hist)
                    if signer_ok and ap.target not in acc and self.usable(ap.target):
                        added.add(ap.target)
            if not added:
                return acc
            acc |= added

    # ---- anchors ---------------------------------------------------------

    def witness_grants(self, x: str, space: str, acc: Set[Binding]) -> List[Grant]:
        out = []
        for g in self.world.grants.values():
            if (g.space == space and g.issuer in acc and g.issuer.account != x
                    and self.world.eligible(g.issuer.account, space)):
                out.append(g)
        return out

    def anchors(self, x: str, space: str, acc: Set[Binding]) -> Set[Binding]:
        """Basis 3 starting points for account x in space, from witnesses
        accepted in this space whose accounts are eligible here."""
        found: Set[Binding] = set()
        for g in self.witness_grants(x, space, acc):
            if g.recipient.account == x:
                found.add(g.recipient)
            # Issuer anchors through key provenance.
            seen = set()
            cur = g
            while cur.provenance and cur.provenance not in seen:
                seen.add(cur.provenance)
                cited = self.world.grants.get(cur.provenance)
                if cited is None or cited.space != space:
                    break
                if cited.issuer.account == x:
                    found.add(cited.issuer)
                    break
                # Chain through the witness account's grants to its own
                # devices, each signed by a binding accepted here.
                if cited.issuer.account == g.issuer.account and cited.issuer in acc:
                    cur = cited
                    continue
                break
        return found

    def anchors_anywhere(self, x: str) -> bool:
        spaces = set(self.world.members) | set(self.state.history_space)
        return any(self.anchors(x, s, self.accepted_in(s)) for s in spaces)

    def _reach(self, x: str, starts: Iterable[Binding]) -> Set[Binding]:
        """Forward reachability through x's approval records, signers of any
        status (records outlive their devices)."""
        aps = self.world.account_approvals(x)
        seen = set(starts)
        frontier = list(seen)
        while frontier:
            n = frontier.pop()
            for ap in aps:
                if ap.signer == n and ap.target not in seen:
                    seen.add(ap.target)
                    frontier.append(ap.target)
        return seen

    def single_root_set(self, x: str) -> Optional[Set[Binding]]:
        """Genuine first contact / re-enrollment candidate: exactly one root
        (no incoming approval) that reaches any present record, and it must
        reach all of them. Roots reaching only deleted devices are ignored."""
        present = {b for b in self.world.present_devices(x) if self.usable(b)}
        if not present:
            return None
        aps = self.world.account_approvals(x)
        nodes = set(present) | {a.signer for a in aps} | {a.target for a in aps}
        incoming = {a.target for a in aps}
        roots = [n for n in nodes if n not in incoming]
        live_roots = [r for r in roots if self._reach(x, [r]) & present]
        if len(live_roots) != 1:
            return None
        reach = self._reach(x, live_roots)
        return present if present <= reach else None

    # ---- first use and re-enrollment ------------------------------------

    def _first_use(self, x: str, space: str) -> None:
        st = self.state
        if x == self.own.account:
            return
        acc = self.accepted_in(space)
        if any(b.account == x for b in acc):
            return
        anchors = self.anchors(x, space, acc)
        ever = st.history_all | st.history_space.get(space, set())
        pinned_before = any(b.account == x for b in ever)
        if anchors or pinned_before:
            # Reset: anchors reach no present device, or every pin revoked.
            cand = self.single_root_set(x)
            if cand is None:
                return
            key = (x, space if (anchors and not self._pinned_account_wide(x)) else None)
            start = st.holds.setdefault(key, self.world.now)
            if self.world.now - start >= REENROLL_HOLD:
                self._pin(cand, None if key[1] is None else space)
                del st.holds[key]
            return
        # Genuine first contact in this space.
        cand = self.single_root_set(x)
        if cand is None:
            return
        self._pin(cand, space if self.anchors_anywhere(x) else None)

    def _pinned_account_wide(self, x: str) -> bool:
        return any(b.account == x for b in self.state.history_all)

    def _pin(self, cand: Set[Binding], space: Optional[str]) -> None:
        st = self.state
        if space is None:
            st.account_wide |= cand
            st.history_all |= cand
        else:
            st.scoped_pins.setdefault(space, set()).update(cand)
            st.history_space.setdefault(space, set()).update(cand)
