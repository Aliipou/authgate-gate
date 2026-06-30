"""The Action Packet ABI (v1) — the domain-agnostic unit every layer speaks.

This is the keystone contract. A domain adapter turns a raw domain event (an MCP
tool call, a robot command, a transaction) into a canonical `Action`; every
enforcement layer (capability, purpose, runtime) consumes the *same* Action and
returns a `Decision`. One logic, many worlds.

`Action` is a strict superset of the original `Intent`: the five core fields are
identical, so anything that read an Intent still works. It adds the metadata the
runtime-control and replay defenses need: a `session_id`, a per-call `nonce`, and
the `capability` the call requests.

All identifier tokens are normalized at construction (see `normalize.py`), so no
downstream layer ever compares un-normalized strings.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from .normalize import normalize_labels, normalize_token

ABI_VERSION = 1


@dataclass(frozen=True)
class Action:
    """A normalized, replay-protected request to perform exactly one action.

    Core (Intent-compatible):
        actor:          who is acting, e.g. "agent:support-bot".
        tool:           the tool/effect to invoke, e.g. "send_email".
        action_purpose: WHY this call happens, e.g. "support_reply".
        data_labels:    provenance/purpose of the data used in this call.
        payload:        concrete arguments handed to the tool.

    ABI metadata:
        session_id:     groups a multi-step trajectory for the runtime layer.
        nonce:          unique per action; enables replay rejection.
        capability:     the capability this call requests. Defaults to
                        ``tool:<tool>`` when not given explicitly.
        abi_version:    the packet ABI version (compat gate).
    """

    actor: str
    tool: str
    action_purpose: str
    data_labels: tuple[str, ...] = ()
    payload: Mapping[str, Any] = field(default_factory=dict)
    session_id: str = "default"
    nonce: str = ""
    capability: str = ""
    abi_version: int = ABI_VERSION

    def __post_init__(self) -> None:
        # Frozen dataclass: mutate via object.__setattr__ during init only.
        object.__setattr__(self, "actor", normalize_token(self.actor))
        object.__setattr__(self, "tool", normalize_token(self.tool))
        object.__setattr__(self, "action_purpose", normalize_token(self.action_purpose))
        object.__setattr__(self, "data_labels", normalize_labels(self.data_labels))
        object.__setattr__(self, "session_id", self.session_id.strip() or "default")
        cap = normalize_token(self.capability) if self.capability else f"tool:{self.tool}"
        object.__setattr__(self, "capability", cap)
        # Make payload immutable so a later layer can't mutate a packet another
        # layer already ruled on.
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))
        if self.abi_version != ABI_VERSION:
            raise ValueError(
                f"unsupported Action ABI version {self.abi_version} "
                f"(this gate speaks v{ABI_VERSION})"
            )


@dataclass(frozen=True)
class RiskVector:
    """A domain-independent risk fingerprint for an Action, each in [0, 1].

    reversibility:  1.0 = trivially undoable, 0.0 = irreversible (money sent,
                    physical motion). The runtime layer treats low reversibility
                    as a reason to demand stronger containment.
    blast_radius:   how much can go wrong if this is wrong (0 small, 1 systemic).
    sensitivity:    sensitivity of the data/effect touched (0 public, 1 secret).
    """

    reversibility: float = 1.0
    blast_radius: float = 0.0
    sensitivity: float = 0.0

    def __post_init__(self) -> None:
        for name in ("reversibility", "blast_radius", "sensitivity"):
            v = getattr(self, name)
            if not (isinstance(v, (int, float)) and 0.0 <= v <= 1.0):
                raise ValueError(f"RiskVector.{name} must be in [0, 1], got {v!r}")


@runtime_checkable
class Layer(Protocol):
    """An enforcement layer in the governance stack.

    A layer inspects an Action and returns a Decision. Control layers
    (capability, runtime) return ALLOW/DENY only; the purpose policy may also
    return TRANSFORM. Layers MUST fail closed: any internal error becomes DENY.
    """

    name: str

    def check(self, action: Action) -> Any:  # -> Decision (avoids import cycle)
        ...


@runtime_checkable
class DomainAdapter(Protocol):
    """Maps a domain's raw events to/from the canonical Action ABI.

    Keep the FDK/AuthGate core fixed; vary only the adapter per domain. This is
    the seam that makes the same enforcement logic portable across AI agents,
    robotics, and finance.
    """

    name: str

    def normalize(self, raw: Any) -> Action: ...
    def denormalize(self, result: Any) -> Any: ...
    def map_capabilities(self, action: Action) -> tuple[str, ...]: ...
    def risk_profile(self, action: Action) -> RiskVector: ...
