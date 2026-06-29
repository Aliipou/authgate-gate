"""AuthGate — a deterministic purpose-bound authorization gate for agent tool calls.

The agent never executes a tool directly. It emits an `Intent`; AuthGate decides
ALLOW / DENY / TRANSFORM and records every decision. No AI inside the gate, no
analytics in the critical path. Just: Can do != May do.
"""

from .intent import Intent
from .action import ABI_VERSION, Action, DomainAdapter, Layer, RiskVector
from .normalize import normalize_labels, normalize_token
from .policy import Decision, PolicyEngine, Verdict
from .audit import AuditLog
from .gate import AuthGate, GateResult

__all__ = [
    "Intent",
    "Action",
    "ABI_VERSION",
    "RiskVector",
    "Layer",
    "DomainAdapter",
    "normalize_token",
    "normalize_labels",
    "Decision",
    "PolicyEngine",
    "Verdict",
    "AuditLog",
    "AuthGate",
    "GateResult",
]
