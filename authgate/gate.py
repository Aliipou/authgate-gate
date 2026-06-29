from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .audit import AuditLog
from .intent import Intent
from .policy import Decision, PolicyEngine, Verdict


@dataclass(frozen=True)
class GateResult:
    executed: bool
    decision: Decision
    output: Any = None


# A tool is just a function that takes a payload and does the side effect.
Tool = Callable[[dict[str, Any]], Any]


class AuthGate:
    """The authority. Sits between the agent and the execution layer.

    enforce()  -> rules on an Intent and records it (no side effects).
    dispatch() -> enforce, then run the tool only if allowed/transformed.
    """

    def __init__(self, policy: PolicyEngine, audit: AuditLog) -> None:
        self._policy = policy
        self._audit = audit

    def enforce(self, intent: Intent) -> Decision:
        decision = self._policy.evaluate(intent)
        self._audit.record(intent, decision)
        return decision

    def dispatch(self, intent: Intent, tools: dict[str, Tool]) -> GateResult:
        decision = self.enforce(intent)
        if decision.verdict is Verdict.DENY:
            return GateResult(executed=False, decision=decision, output=None)

        effective = decision.transformed or intent
        tool = tools.get(effective.tool)
        if tool is None:
            # A permitted-but-unknown tool is still a hard failure, not a guess.
            raise KeyError(f"no executor registered for tool '{effective.tool}'")

        output = tool(effective.payload)
        return GateResult(executed=True, decision=decision, output=output)
