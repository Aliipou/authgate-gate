"""AuthGate — a deterministic purpose-bound authorization gate for agent tool calls.

The agent never executes a tool directly. It emits an `Intent`; AuthGate decides
ALLOW / DENY / TRANSFORM and records every decision. No AI inside the gate, no
analytics in the critical path. Just: Can do != May do.
"""

from .intent import Intent
from .action import ABI_VERSION, Action, DomainAdapter, Layer, RiskVector
from .normalize import normalize_labels, normalize_token
from .policy import Decision, PolicyEngine, Verdict
from .capability import CapabilityLayer, CapabilityRegistry
from .runtime import RuntimeConfig, RuntimeLayer, RuntimeMonitor, default_cost_fn
from .adapter import AIToolAdapter, FinanceAdapter, QuantumJobAdapter
from .audit import AuditLog
from .audit_chain import HashChainedAudit
from .gate import AuthGate, GateResult
from .controlled_gate import ControlledGate, build_gate

__all__ = [
    # ABI
    "Intent",
    "Action",
    "ABI_VERSION",
    "RiskVector",
    "Layer",
    "DomainAdapter",
    "normalize_token",
    "normalize_labels",
    # decision
    "Decision",
    "PolicyEngine",
    "Verdict",
    # enforcement layers
    "CapabilityLayer",
    "CapabilityRegistry",
    "RuntimeConfig",
    "RuntimeLayer",
    "RuntimeMonitor",
    "default_cost_fn",
    # adapters
    "AIToolAdapter",
    "FinanceAdapter",
    "QuantumJobAdapter",
    # audit
    "AuditLog",
    "HashChainedAudit",
    # gates
    "AuthGate",
    "GateResult",
    "ControlledGate",
    "build_gate",
]
