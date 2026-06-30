"""Domain Adapters — map raw domain events to/from the canonical Action ABI.

One logic, many worlds. The FDK/AuthGate enforcement core is fixed and
domain-agnostic; everything domain-specific lives behind a `DomainAdapter`
(see `authgate.action.DomainAdapter`). An adapter has four jobs:

    normalize(raw)        raw domain event -> canonical `Action`
    denormalize(result)   a tool result/exception -> the domain's reply shape
    map_capabilities(a)   the set of capabilities the call requests, so a
                          policy can grant by *class* (e.g. "effect:network")
                          rather than enumerating every concrete tool
    risk_profile(a)       a domain-independent `RiskVector` (reversibility,
                          blast_radius, sensitivity), each in [0, 1]

This module ships three adapters that exercise three very different worlds with
the *same* downstream logic:

    AIToolAdapter      cloud AI agent / MCP tool calls   (the reference)
    FinanceAdapter     money movement                    (budget-aware)
    QuantumJobAdapter  classical control plane that GATES ACCESS to quantum
                       jobs on cloud QPUs

IMPORTANT scope note for `QuantumJobAdapter`: it is a *classical* control plane.
It runs around the QPU, not on it. It governs who may submit/cancel/calibrate a
job on a cloud quantum backend; it never executes quantum logic itself. The
"quantum" here is the resource being gated, exactly as "money" is for finance.

Every adapter is round-trip safe: a raw event normalized to an Action carries
enough of the original to reconstruct the domain payload, and `denormalize`
never depends on adapter-private state.

Stdlib only.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .action import Action, RiskVector

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Data labels whose presence implies the call touches highly-sensitive data.
# Matched as substrings against each (already-normalized) label, so "ssn",
# "customer_ssn", "card_number", "medical_history" all trip the same wire.
_SENSITIVE_LABEL_MARKERS: tuple[str, ...] = ("ssn", "card", "medical", "pii")


def _has_sensitive_label(data_labels: tuple[str, ...]) -> bool:
    """True if any data label looks like regulated / high-sensitivity data."""
    return any(
        marker in label
        for label in data_labels
        for marker in _SENSITIVE_LABEL_MARKERS
    )


def _ok(result: Any) -> dict[str, Any]:
    """The canonical success envelope shared by every adapter."""
    return {"ok": True, "result": result}


def _err(error: BaseException) -> dict[str, Any]:
    """The canonical failure envelope shared by every adapter.

    The exception is rendered to a stable ``{type, message}`` shape so callers
    never have to depend on a live exception object crossing the boundary.
    """
    return {
        "ok": False,
        "error": {"type": type(error).__name__, "message": str(error)},
    }


def _clamp01(x: float) -> float:
    """Clamp to the [0, 1] domain RiskVector requires."""
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


# ===========================================================================
# 1) AIToolAdapter — the reference adapter
# ===========================================================================
class AIToolAdapter:
    """Reference adapter: cloud AI agent / MCP-style tool calls.

    Accepts an MCP-ish raw event::

        {
            "actor":       "agent:support-bot",
            "tool":        "send_email",
            "arguments":   {"to": "...", "body": "..."},   # -> Action.payload
            "purpose":     "support_reply",                # -> action_purpose
            "data_labels": ["customer_support"],
            "session_id":  "s-1",                          # optional
            "nonce":       "n-1",                          # optional
        }

    Capability is left empty on the Action so the ABI derives the canonical
    ``tool:<tool>`` form itself; `map_capabilities` then widens it by effect
    class so policies can grant ``effect:network`` once instead of naming every
    network tool.
    """

    name = "ai"

    # Tool-name prefix/exact -> extra effect capability. Documented and small
    # on purpose: the gate should be auditable, not clever. A tool whose name
    # *implies a class* gets the class capability added alongside tool:<tool>.
    _EFFECT_PREFIXES: tuple[tuple[str, str], ...] = (
        ("delete_", "effect:destructive"),
        ("drop_", "effect:destructive"),
        ("remove_", "effect:destructive"),
        ("send_", "effect:network"),
        ("post_", "effect:network"),
        ("fetch_", "effect:network"),
        ("http_", "effect:network"),
        ("write_", "effect:write"),
        ("update_", "effect:write"),
        ("create_", "effect:write"),
    )

    # Tools that only observe state: high reversibility, low blast radius.
    _READONLY_PREFIXES: tuple[str, ...] = (
        "read_",
        "get_",
        "list_",
        "search_",
        "fetch_",
        "describe_",
    )

    def normalize(self, raw: Mapping[str, Any]) -> Action:
        """Map an MCP-ish tool call to a canonical Action.

        Tolerant of missing optional fields: ``session_id`` defaults to
        "default" and ``nonce`` to "". ``arguments`` may be absent (-> {}),
        and ``data_labels`` may be absent (-> ()).
        """
        if not isinstance(raw, Mapping):
            raise TypeError(f"AIToolAdapter.normalize expects a mapping, got {type(raw).__name__}")
        return Action(
            actor=str(raw["actor"]),
            tool=str(raw["tool"]),
            action_purpose=str(raw.get("purpose", "")),
            data_labels=tuple(raw.get("data_labels", ()) or ()),
            payload=dict(raw.get("arguments", {}) or {}),
            session_id=str(raw.get("session_id", "default")),
            nonce=str(raw.get("nonce", "")),
            # capability left empty -> ABI derives tool:<tool>
        )

    def denormalize(self, result: Any) -> dict[str, Any]:
        """Wrap a tool result (or Exception) in the canonical envelope."""
        if isinstance(result, BaseException):
            return _err(result)
        return _ok(result)

    def map_capabilities(self, action: Action) -> tuple[str, ...]:
        """Concrete capability plus any effect-class capability it implies."""
        caps: list[str] = [action.capability]
        for prefix, effect in self._EFFECT_PREFIXES:
            if action.tool.startswith(prefix) and effect not in caps:
                caps.append(effect)
        return tuple(caps)

    def risk_profile(self, action: Action) -> RiskVector:
        """Derive risk from the tool's name and the data it touches.

        Reversibility / blast_radius table (by tool name):
            read-only (read_/get_/list_/search_/...)  rev 0.95  blast 0.05
            destructive (delete_/drop_/remove_)       rev 0.10  blast 0.80
            sending (send_/post_)                     rev 0.30  blast 0.50
            other (write/update/unknown)              rev 0.60  blast 0.30

        Sensitivity:
            0.90 if any data label looks regulated (ssn/card/medical/pii),
            else 0.20.
        """
        tool = action.tool
        if tool.startswith(self._READONLY_PREFIXES):
            rev, blast = 0.95, 0.05
        elif tool.startswith(("delete_", "drop_", "remove_")):
            rev, blast = 0.10, 0.80
        elif tool.startswith(("send_", "post_")):
            rev, blast = 0.30, 0.50
        else:
            rev, blast = 0.60, 0.30
        sensitivity = 0.90 if _has_sensitive_label(action.data_labels) else 0.20
        return RiskVector(reversibility=rev, blast_radius=blast, sensitivity=sensitivity)


# ===========================================================================
# 2) FinanceAdapter — money movement
# ===========================================================================
class FinanceAdapter:
    """Adapter for money-movement operations (transfers, payments, refunds).

    Accepts::

        {
            "actor":        "treasury-bot",
            "operation":    "transfer",        # -> Action.tool
            "amount":       2500,              # KEPT NUMERIC in payload
            "currency":     "USD",
            "account_from": "acct:1",
            "account_to":   "acct:2",
            "purpose":      "vendor_payment",  # -> action_purpose
            "session_id":   "s-1",             # optional
            "nonce":        "n-1",             # optional
        }

    The money fields are mapped into ``payload`` with ``amount`` left as a
    *number* so the runtime budget layer can read and sum it without parsing.
    """

    name = "finance"

    # Blast-radius buckets by absolute transfer amount (in the call's currency
    # units). Documented step function, capped at 1.0. Currency-agnostic by
    # design: the gate ranks magnitude, the budget layer handles real limits.
    #   amount <        100  -> 0.10
    #   amount <      1_000  -> 0.25
    #   amount <     10_000  -> 0.50
    #   amount <    100_000  -> 0.75
    #   amount <  1_000_000  -> 0.90
    #   amount >= 1_000_000  -> 1.00
    _AMOUNT_BUCKETS: tuple[tuple[float, float], ...] = (
        (100.0, 0.10),
        (1_000.0, 0.25),
        (10_000.0, 0.50),
        (100_000.0, 0.75),
        (1_000_000.0, 0.90),
    )

    def normalize(self, raw: Mapping[str, Any]) -> Action:
        """Map a money operation to a canonical Action (amount stays numeric)."""
        if not isinstance(raw, Mapping):
            raise TypeError(f"FinanceAdapter.normalize expects a mapping, got {type(raw).__name__}")
        payload: dict[str, Any] = {
            "amount": raw.get("amount", 0),  # numeric, untouched
            "currency": raw.get("currency", ""),
            "account_from": raw.get("account_from", ""),
            "account_to": raw.get("account_to", ""),
        }
        return Action(
            actor=str(raw["actor"]),
            tool=str(raw["operation"]),
            action_purpose=str(raw.get("purpose", "")),
            data_labels=tuple(raw.get("data_labels", ()) or ()),
            payload=payload,
            session_id=str(raw.get("session_id", "default")),
            nonce=str(raw.get("nonce", "")),
        )

    def denormalize(self, result: Any) -> dict[str, Any]:
        """Wrap a settlement result (or Exception) in the canonical envelope."""
        if isinstance(result, BaseException):
            return _err(result)
        return _ok(result)

    def map_capabilities(self, action: Action) -> tuple[str, ...]:
        """Concrete capability plus the financial effect class."""
        return (action.capability, "effect:financial")

    def _amount_blast(self, amount: float) -> float:
        """Map an absolute amount to a blast_radius bucket, capped at 1.0."""
        a = abs(amount)
        for threshold, blast in self._AMOUNT_BUCKETS:
            if a < threshold:
                return blast
        return 1.0

    def risk_profile(self, action: Action) -> RiskVector:
        """Money moves are hard to undo, scale with size, and are sensitive.

        reversibility: 0.10 (a sent transfer is effectively irreversible).
        blast_radius:  bucketed on ``payload['amount']`` (see `_amount_blast`).
        sensitivity:   0.70 baseline (account/PII-adjacent), 0.90 if a label
                       looks regulated (ssn/card/medical/pii).
        """
        raw_amount = action.payload.get("amount", 0)
        try:
            amount = float(raw_amount)
        except (TypeError, ValueError):
            amount = 0.0
        sensitivity = 0.90 if _has_sensitive_label(action.data_labels) else 0.70
        return RiskVector(
            reversibility=0.10,
            blast_radius=_clamp01(self._amount_blast(amount)),
            sensitivity=sensitivity,
        )


# ===========================================================================
# 3) QuantumJobAdapter — classical control plane around cloud QPUs
# ===========================================================================
class QuantumJobAdapter:
    """Adapter for a CLASSICAL control plane that gates ACCESS to quantum jobs.

    This adapter does NOT run on a QPU and contains no quantum logic. It is a
    purely classical seam that governs *who may do what* to a job on a cloud
    quantum backend — submit a circuit, cancel it, or run a hardware-affecting
    calibration/reset. The "quantum" is the gated resource, exactly as "money"
    is for the finance adapter.

    Accepts::

        {
            "actor":      "researcher:lab-7",
            "job":        "submit_circuit",   # -> Action.tool
            "backend":    "ibmq_kolkata",
            "shots":      4096,
            "circuit_id": "qc:abc",
            "purpose":    "vqe_experiment",   # -> action_purpose
            "session_id": "s-1",              # optional
            "nonce":      "n-1",              # optional
        }
    """

    name = "quantum"

    # Job-name prefixes that touch shared hardware state (calibration, reset).
    # These are harder to undo than a queued/runnable job, which can simply be
    # cancelled — so they get a lower reversibility.
    _HARDWARE_AFFECTING_PREFIXES: tuple[str, ...] = ("calibrate", "reset")

    def normalize(self, raw: Mapping[str, Any]) -> Action:
        """Map a quantum job request to a canonical Action."""
        if not isinstance(raw, Mapping):
            raise TypeError(
                f"QuantumJobAdapter.normalize expects a mapping, got {type(raw).__name__}"
            )
        payload: dict[str, Any] = {
            "backend": raw.get("backend", ""),
            "shots": raw.get("shots", 0),
            "circuit_id": raw.get("circuit_id", ""),
        }
        return Action(
            actor=str(raw["actor"]),
            tool=str(raw["job"]),
            action_purpose=str(raw.get("purpose", "")),
            data_labels=tuple(raw.get("data_labels", ()) or ()),
            payload=payload,
            session_id=str(raw.get("session_id", "default")),
            nonce=str(raw.get("nonce", "")),
        )

    def denormalize(self, result: Any) -> dict[str, Any]:
        """Wrap a job result/handle (or Exception) in the canonical envelope."""
        if isinstance(result, BaseException):
            return _err(result)
        return _ok(result)

    def map_capabilities(self, action: Action) -> tuple[str, ...]:
        """Concrete capability plus the quantum-job effect class."""
        return (action.capability, "effect:quantum_job")

    def risk_profile(self, action: Action) -> RiskVector:
        """Risk of acting on a cloud quantum job.

        blast_radius:  0.40 — moderate; the cost is mostly compute/queue time
                       on a shared backend, not data loss.
        reversibility: 0.90 — a queued or running job can be cancelled, so most
                       jobs are highly reversible. Hardware-affecting jobs
                       (``calibrate*`` / ``reset*``) drop to 0.20 because they
                       mutate shared device state that other users depend on.
        sensitivity:   0.30 — experiment metadata; 0.90 if a data label looks
                       regulated (ssn/card/medical/pii).
        """
        tool = action.tool
        if tool.startswith(self._HARDWARE_AFFECTING_PREFIXES):
            reversibility = 0.20
        else:
            reversibility = 0.90
        sensitivity = 0.90 if _has_sensitive_label(action.data_labels) else 0.30
        return RiskVector(
            reversibility=reversibility,
            blast_radius=0.40,
            sensitivity=sensitivity,
        )


__all__ = ["AIToolAdapter", "FinanceAdapter", "QuantumJobAdapter"]
