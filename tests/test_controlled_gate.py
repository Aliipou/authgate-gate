"""Composition tests for the production `ControlledGate`.

The per-layer suites prove each layer in isolation; this proves the *wiring*:
layer order, DENY short-circuit, TRANSFORM carry-forward into the runtime layer
and the executor, per-layer audit tagging, fail-closed at the boundary, and the
end-to-end dispatch path. Plain asserts; run with `python tests/test_controlled_gate.py`.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from authgate import (
    Action,
    CapabilityRegistry,
    HashChainedAudit,
    RuntimeConfig,
    Verdict,
    build_gate,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "purpose_policy.json"


def _gate(*, grants=None, tool_grants=None, config=None):
    reg = CapabilityRegistry()
    for actor, caps in (grants or {}).items():
        for c in caps:
            reg.grant(actor, c)
    for actor, tools in (tool_grants or {}).items():
        for t in tools:
            reg.grant_tool(actor, t)
    audit = pathlib.Path(tempfile.mkdtemp()) / "audit.jsonl"
    gate, monitor = build_gate(
        policy_path=POLICY,
        registry=reg,
        runtime_config=config or RuntimeConfig(),
        audit_path=audit,
    )
    return gate, monitor, audit


def test_all_layers_allow() -> None:
    gate, _, _ = _gate(tool_grants={"agent:bot": ["send_email"]})
    a = Action("agent:bot", "send_email", "support_reply", ("customer_support",),
               {"body": "hi"}, "s1", "n1")
    assert gate.enforce(a).verdict is Verdict.ALLOW


def test_capability_denies_first_and_short_circuits() -> None:
    # No grant at all -> capability layer must DENY (before purpose/runtime).
    gate, _, _ = _gate()
    a = Action("agent:bot", "send_email", "support_reply", ("customer_support",),
               {"body": "hi"}, "s1", "n1")
    d = gate.enforce(a)
    assert d.verdict is Verdict.DENY
    assert "capability" in d.reason


def test_purpose_denies_when_capability_ok() -> None:
    # Capability granted, but support data into a marketing purpose -> purpose DENY.
    gate, _, _ = _gate(tool_grants={"agent:bot": ["send_email"]})
    a = Action("agent:bot", "send_email", "marketing", ("customer_support",),
               {"body": "spam"}, "s1", "n1")
    d = gate.enforce(a)
    assert d.verdict is Verdict.DENY
    assert "purpose" in d.reason


def test_transform_carries_forward_and_redacts_executed_payload() -> None:
    # support_reply with an SSN -> policy TRANSFORM (redact ssn). The executor
    # must receive the REDACTED payload, and the final verdict is TRANSFORM.
    gate, _, _ = _gate(tool_grants={"agent:bot": ["send_email"]})
    a = Action("agent:bot", "send_email", "support_reply", ("customer_support",),
               {"body": "ok", "ssn": "123-45-6789"}, "s1", "n1")
    seen = {}

    def tool(payload):
        seen.update(payload)
        return "sent"

    result = gate.dispatch(a, {"send_email": tool})
    assert result.executed is True
    assert result.decision.verdict is Verdict.TRANSFORM
    assert seen["ssn"] == "[REDACTED]"          # the secret never reached the tool
    assert result.output == "sent"


def test_runtime_runs_on_transformed_action() -> None:
    # A TRANSFORM must still be subject to the runtime layer: replay the same
    # nonce after a redacted call and the runtime layer must DENY.
    gate, _, _ = _gate(tool_grants={"agent:bot": ["send_email"]})
    a = Action("agent:bot", "send_email", "support_reply", ("customer_support",),
               {"body": "ok", "ssn": "111-22-3333"}, "s1", "dup")
    assert gate.enforce(a).verdict is Verdict.TRANSFORM
    d2 = gate.enforce(a)  # same nonce -> runtime replay DENY
    assert d2.verdict is Verdict.DENY
    assert "replay" in d2.reason


def test_runtime_denies_when_upstream_ok() -> None:
    gate, _, _ = _gate(
        tool_grants={"agent:bot": ["pay"]},
        config=RuntimeConfig(budgets={"spend": 100.0}),
    )
    ok = Action("agent:bot", "pay", "fulfillment", ("payments",), {"amount": 60.0}, "s1", "p1")
    assert gate.enforce(ok).verdict is Verdict.ALLOW
    over = Action("agent:bot", "pay", "fulfillment", ("payments",), {"amount": 60.0}, "s1", "p2")
    d = gate.enforce(over)  # 60+60 > 100
    assert d.verdict is Verdict.DENY
    assert "budget" in d.reason


def test_dispatch_does_not_execute_on_deny() -> None:
    gate, _, _ = _gate()  # no grants -> DENY
    called = {"n": 0}

    def tool(_payload):
        called["n"] += 1
        return "ran"

    result = gate.dispatch(
        Action("agent:bot", "send_email", "support_reply", ("customer_support",), {}, "s1", "n1"),
        {"send_email": tool},
    )
    assert result.executed is False
    assert called["n"] == 0


def test_killswitch_denies_everything() -> None:
    gate, monitor, _ = _gate(tool_grants={"agent:bot": ["send_email"]})
    monitor.stop()
    a = Action("agent:bot", "send_email", "support_reply", ("customer_support",), {}, "s1", "n1")
    d = gate.enforce(a)
    assert d.verdict is Verdict.DENY
    assert "kill-switch" in d.reason


def test_fail_closed_on_non_action() -> None:
    gate, _, _ = _gate(grants={"x": ["*"]})

    class NotAnAction:
        pass

    d = gate.enforce(NotAnAction())  # must DENY, not raise
    assert d.verdict is Verdict.DENY
    assert "not an Action" in d.reason


def test_every_decision_is_audited_and_chain_verifies() -> None:
    gate, _, audit_path = _gate(tool_grants={"agent:bot": ["send_email"]})
    gate.enforce(Action("agent:bot", "send_email", "support_reply", ("customer_support",),
                        {"body": "hi"}, "s1", "n1"))
    gate.enforce(Action("agent:bot", "send_email", "marketing", ("customer_support",),
                        {"body": "x"}, "s1", "n2"))
    assert HashChainedAudit(audit_path).verify() is True


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
    print(f"\n{'all passed' if not failures else f'{failures} failed'}")
    sys.exit(1 if failures else 0)
