"""Run the gate against a real agent plan and watch it stop a prompt injection.

    python examples/prompt_injection_demo.py
"""

from __future__ import annotations

import pathlib
import sys

# Make the project importable when run as a plain script.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

# Windows consoles default to a legacy codepage; keep output UTF-8 safe.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from agent.agent import planned_intents
from authgate import AuditLog, AuthGate, PolicyEngine, Verdict

ROOT = pathlib.Path(__file__).resolve().parents[1]


def fake_send_email(payload: dict) -> str:
    return f"EMAIL SENT to {payload.get('to')}: {payload.get('body')!r}"


VERDICT_MARK = {
    Verdict.ALLOW: "[ALLOW]",
    Verdict.DENY: "[DENY ]",
    Verdict.TRANSFORM: "[XFORM]",
}


def main() -> None:
    gate = AuthGate(
        policy=PolicyEngine.from_file(ROOT / "policies" / "purpose_policy.json"),
        audit=AuditLog(ROOT / "audit" / "decisions.jsonl"),
    )
    tools = {"send_email": fake_send_email}

    print("AuthGate agent-gate — purpose-bound control over tool calls")
    print("=" * 68)
    for i, intent in enumerate(planned_intents(), 1):
        result = gate.dispatch(intent, tools)
        mark = VERDICT_MARK[result.decision.verdict]
        print(f"\n{i}. {mark} {intent.actor} -> {intent.tool} "
              f"(purpose={intent.action_purpose}, data={list(intent.data_labels)})")
        print(f"        reason: {result.decision.reason}")
        if result.executed:
            print(f"        ran:    {result.output}")
        else:
            print("        ran:    <blocked, tool never executed>")

    print("\n" + "=" * 68)
    print(f"audit trail -> {ROOT / 'audit' / 'decisions.jsonl'}")


if __name__ == "__main__":
    main()
