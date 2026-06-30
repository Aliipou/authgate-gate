"""End-to-end demo of the composed governance stack (`ControlledGate`).

Runs the full pipeline — capability → purpose-binding → runtime/drift — over a
short agent session and prints each decision, then verifies the audit chain.

    python examples/controlled_gate_demo.py

Unlike `prompt_injection_demo.py` (which shows the legacy single-layer gate),
this drives the production `build_gate(...)` object the README architecture
describes: every layer, the tamper-evident log, and the fleet kill-switch.
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
    build_gate,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> None:
    # Grant the agent exactly two tools; everything else is denied by default.
    reg = CapabilityRegistry()
    reg.grant_tool("agent:support-bot", "send_email")
    reg.grant_tool("agent:support-bot", "charge_card")

    audit_path = pathlib.Path(tempfile.mkdtemp()) / "decisions.jsonl"
    gate, monitor = build_gate(
        policy_path=ROOT / "policies" / "purpose_policy.json",
        registry=reg,
        runtime_config=RuntimeConfig(
            max_steps=50,
            budgets={"spend": 100.0},
            sensitive_labels=frozenset({"customer_support"}),
        ),
        audit_path=audit_path,
    )

    def email(payload):
        return f"emailed: {payload}"

    def charge(payload):
        return f"charged: {payload}"

    tools = {"send_email": email, "charge_card": charge}

    # (label, Action) scenarios walking one session "s1".
    scenarios = [
        ("legit support reply",
         Action("agent:support-bot", "send_email", "support_reply",
                ("customer_support",), {"body": "Here is your answer."}, "s1", "n1")),
        ("prompt-injection: support data -> marketing (purpose DENY)",
         Action("agent:support-bot", "send_email", "marketing",
                ("customer_support",), {"body": "Buy now!"}, "s1", "n2")),
        ("redaction: SSN not needed for a support reply (TRANSFORM)",
         Action("agent:support-bot", "send_email", "support_reply",
                ("customer_support",), {"body": "ok", "ssn": "123-45-6789"}, "s1", "n3")),
        ("capability escalation: tool never granted (capability DENY)",
         Action("agent:support-bot", "delete_database", "support_reply",
                (), {}, "s1", "n4")),
        ("legit charge within budget",
         Action("agent:support-bot", "charge_card", "fulfillment",
                ("payments",), {"amount": 80.0}, "s1", "n5")),
        ("cumulative budget exhaustion (runtime DENY)",
         Action("agent:support-bot", "charge_card", "fulfillment",
                ("payments",), {"amount": 40.0}, "s1", "n6")),
        ("replay of an earlier nonce (runtime DENY)",
         Action("agent:support-bot", "send_email", "support_reply",
                ("customer_support",), {"body": "again"}, "s1", "n1")),
    ]

    print(f"{'scenario':<58} {'verdict':<10} reason")
    print("-" * 100)
    for label, action in scenarios:
        result = gate.dispatch(action, tools)
        v = result.decision.verdict.value.upper()
        print(f"{label:<58} {v:<10} {result.decision.reason}")

    # Fleet kill-switch: after this, everything denies (within this process).
    monitor.stop()
    killed = gate.enforce(
        Action("agent:support-bot", "send_email", "support_reply",
               ("customer_support",), {"body": "x"}, "s1", "n7")
    )
    print(f"{'after kill-switch':<58} {killed.verdict.value.upper():<10} {killed.reason}")

    ok = HashChainedAudit(audit_path).verify()
    print("-" * 100)
    print(f"audit chain verifies: {ok}   ({audit_path})")


if __name__ == "__main__":
    main()
