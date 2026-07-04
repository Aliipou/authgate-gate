"""Capability enforcement — the first control layer of the governance stack.

Purpose binding (``policy.py``) answers *may this data flow into this action*.
This layer answers a more basic question first: *is this actor even allowed to
request this capability at all?* It is a deny-by-default access-control gate.

Model:
    * A :class:`CapabilityRegistry` records which capabilities each actor holds.
    * A capability is an opaque normalized token, e.g. ``"tool:send_email"`` or a
      coarser grant like ``"email"``. The wildcard ``"*"`` is admin: an actor
      that holds it may do anything.
    * An :class:`Action` requests exactly one capability (``action.capability``,
      which defaults to ``tool:<tool>``). The :class:`CapabilityLayer` ALLOWs iff
      the actor holds that capability (or ``"*"``), else DENY.

Every actor and capability token is normalized through ``normalize_token`` at
both grant time and check time, so grants and requests compare canonically. This
inherits the bypass resistance of ``normalize.py``: no case, NFKC look-alike, or
zero-width / control-character smuggling can split one logical token into two.

The layer fails closed: any unexpected error becomes DENY, never an exception
and never an accidental ALLOW.
"""

from __future__ import annotations

from collections import defaultdict

from .action import Action
from .normalize import normalize_token
from .policy import Decision, Verdict

#: The admin capability. An actor holding this may perform any action.
WILDCARD = "*"


class CapabilityRegistry:
    """A deny-by-default store of actor -> capability grants.

    All actor and capability tokens are normalized via ``normalize_token`` on
    the way in and on the way out, so callers may pass raw (mixed-case, padded,
    look-alike) strings and still get canonical, collision-free behavior.

    An actor with no grants holds the empty set and is therefore denied
    everything (default-deny). Granting the wildcard ``"*"`` makes the actor an
    admin for whom any capability check passes.
    """

    def __init__(self) -> None:
        # actor (normalized) -> set of capabilities (normalized).
        self._grants: dict[str, set[str]] = defaultdict(set)

    def grant(self, actor: str, capability: str) -> None:
        """Grant ``capability`` to ``actor``.

        Both tokens are normalized before storage. Granting the same capability
        twice is idempotent. The wildcard ``"*"`` is preserved verbatim by
        ``normalize_token`` and grants admin.
        """
        self._grants[normalize_token(actor)].add(self._norm_cap(capability))

    def grant_tool(self, actor: str, tool: str) -> None:
        """Sugar for granting the capability ``tool:<tool>`` to ``actor``.

        Mirrors how :class:`Action` derives its default capability, so a tool
        grant lines up with an Action that requests that tool.
        """
        self.grant(actor, f"tool:{normalize_token(tool)}")

    def revoke(self, actor: str, capability: str) -> None:
        """Remove ``capability`` from ``actor`` if present (no-op otherwise)."""
        self._grants[normalize_token(actor)].discard(self._norm_cap(capability))

    def granted(self, actor: str) -> frozenset[str]:
        """Return the (immutable) set of capabilities held by ``actor``."""
        return frozenset(self._grants.get(normalize_token(actor), frozenset()))

    def allows(self, actor: str, capability: str) -> bool:
        """Return True iff ``actor`` holds ``capability`` (or the wildcard)."""
        held = self._grants.get(normalize_token(actor))
        if not held:
            return False
        if WILDCARD in held:
            return True
        return self._norm_cap(capability) in held

    @staticmethod
    def _norm_cap(capability: str) -> str:
        """Normalize a capability token, preserving the bare wildcard ``"*"``.

        ``normalize_token`` strips characters in Unicode "Other" categories but
        ``*`` is punctuation (Po), so it survives normalization unchanged; this
        helper is explicit about that invariant for readability.
        """
        norm = normalize_token(capability)
        return norm


class CapabilityLayer:
    """Enforcement layer that gates an Action on the actor's capabilities.

    Implements the ``Layer`` protocol from ``action.py``: it exposes ``name``
    and ``check(action) -> Decision``. It consults a :class:`CapabilityRegistry`
    and returns ALLOW iff the acting actor holds ``action.capability`` (or the
    wildcard ``"*"``), otherwise DENY. It never returns TRANSFORM.

    Fail-closed: the entire body is guarded so that any unexpected exception
    (e.g. a malformed object that is not a real :class:`Action`) yields a DENY
    decision rather than propagating or — worse — allowing.
    """

    name = "capability"

    def __init__(self, registry: CapabilityRegistry) -> None:
        self._registry = registry

    def check(self, action: Action) -> Decision:
        """Rule on ``action``. ALLOW if the actor holds the requested capability.

        Returns ``Decision(Verdict.ALLOW, ...)`` or ``Decision(Verdict.DENY,
        ...)``. Any error is caught and converted to a DENY, so this method
        never raises.
        """
        try:
            actor = action.actor
            capability = action.capability
            if not isinstance(actor, str) or not isinstance(capability, str):
                return Decision(
                    Verdict.DENY,
                    "capability layer error: action lacks string actor/capability",
                )
            if self._registry.allows(actor, capability):
                return Decision(
                    Verdict.ALLOW,
                    f"actor '{actor}' holds capability '{capability}'",
                )
            return Decision(
                Verdict.DENY,
                f"actor '{actor}' lacks capability '{capability}'",
            )
        except Exception as exc:  # fail closed — never raise, never allow.
            return Decision(Verdict.DENY, f"capability layer error: {exc!r}")
