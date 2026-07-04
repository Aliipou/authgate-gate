"""The composed governance stack — the production gate.

`ControlledGate` wires the three enforcement layers into one ordered,
defense-in-depth pipeline and runs an effect only if *every* layer permits it:

    Action
      │
      ▼  1. capability   — is this actor even allowed to request this? (cheapest
      │                     hard boundary; an unauthorized actor never reaches,
      │                     and never consumes, the runtime budget)
      ▼  2. purpose      — may this data, collected for that purpose, flow into
      │                     this action? (may also TRANSFORM: redact + continue)
      ▼  3. runtime      — is the session's behavior over time still valid?
      │                     (drift / rate / budget / replay / laundering /
      │                      fleet kill-switch; commits state only on ALLOW)
      ▼
    Execution (dumb executor)        Audit (every decision, tamper-evident)

The first layer to DENY wins and short-circuits. A TRANSFORM from the purpose
layer is carried forward: the runtime layer rules on the transformed Action and
the executor runs the transformed payload. The whole stack is fail-closed —
each layer already converts internal errors to DENY, so an error anywhere
produces a refusal, never an accidental allow.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from .action import Action
from .audit_chain import HashChainedAudit
from .capability import CapabilityLayer, CapabilityRegistry
from .gate import GateResult, Tool
from .policy import Decision, PolicyEngine, Verdict
from .runtime import RuntimeConfig, RuntimeLayer, RuntimeMonitor


class ControlledGate:
    """Capability → purpose → runtime, fail-closed, with tamper-evident audit."""

    def __init__(
        self,
        capability: CapabilityLayer,
        policy: PolicyEngine,
        runtime: RuntimeLayer,
        audit: HashChainedAudit,
    ) -> None:
        self._capability = capability
        self._policy = policy
        self._runtime = runtime
        self._audit = audit

    def enforce(self, action: Action) -> Decision:
        """Rule on a single Action without executing it. Records every layer's
        decision to the audit log, tagged with the deciding layer.

        Fail-closed at the boundary: anything that is not a real ``Action`` is
        refused before it can touch a layer or the audit log, and any unexpected
        error inside the pipeline becomes a DENY rather than a crash."""
        if not isinstance(action, Action):
            return Decision(
                Verdict.DENY,
                f"controlled gate: input is not an Action packet "
                f"(got {type(action).__name__})",
            )
        try:
            return self._enforce(action)
        except Exception as exc:  # defense in depth — never crash, never allow.
            return Decision(Verdict.DENY, f"controlled gate: failing closed ({exc!r})")

    def _enforce(self, action: Action) -> Decision:
        # 1. Capability — cheapest hard boundary; deny here costs nothing downstream.
        cap = self._capability.check(action)
        self._audit.record(action, cap, layer="capability")
        if cap.verdict is Verdict.DENY:
            return cap

        # 2. Purpose binding — may DENY or TRANSFORM (redact + continue).
        pol = self._policy.evaluate(action)
        self._audit.record(action, pol, layer="policy")
        if pol.verdict is Verdict.DENY:
            return pol
        # In this pipeline the policy only ever sees an Action, so a TRANSFORM
        # carries an Action back; cast keeps the runtime layer's type honest.
        effective = cast(Action, pol.transformed) if pol.transformed is not None else action

        # 3. Runtime / drift — temporal & global; commits state only on ALLOW, so
        #    the order matters: nothing above has consumed budget/steps yet.
        run = self._runtime.check(effective)
        self._audit.record(effective, run, layer="runtime")
        if run.verdict is Verdict.DENY:
            return run

        # Everything permits. Preserve a purpose-layer TRANSFORM so the caller
        # executes the minimized payload; otherwise a clean ALLOW.
        if pol.verdict is Verdict.TRANSFORM:
            return pol
        return Decision(Verdict.ALLOW, "capability + purpose + runtime all permit")

    def dispatch(self, action: Action, tools: dict[str, Tool]) -> GateResult:
        """Enforce, then run the tool only if the stack permitted it."""
        decision = self.enforce(action)
        if decision.verdict is Verdict.DENY:
            return GateResult(executed=False, decision=decision, output=None)

        effective = decision.transformed or action
        tool = tools.get(effective.tool)
        if tool is None:
            # Permitted-but-unregistered tool is a hard failure, not a guess.
            raise KeyError(f"no executor registered for tool '{effective.tool}'")
        output = tool(dict(effective.payload))
        return GateResult(executed=True, decision=decision, output=output)


def build_gate(
    *,
    policy_path: str | Path,
    registry: CapabilityRegistry,
    runtime_config: RuntimeConfig | None = None,
    audit_path: str | Path,
) -> tuple[ControlledGate, RuntimeMonitor]:
    """Assemble a production `ControlledGate` from its parts.

    Returns the gate and the `RuntimeMonitor` (so an operator keeps a handle on
    the **process-wide** kill-switch — `monitor.stop()`). Construct one gate per
    trust domain; share a registry/policy across sessions but keep the monitor's
    per-session state local to the gate.

    Honest scope: the monitor's state (budgets, nonce-sets, kill-switch) lives in
    this process's memory. Across multiple processes/machines these guarantees do
    not coordinate — `stop()` halts only this process, and budgets are per-process.
    A cross-machine control plane needs a shared, consistent store (see
    `CRITICAL_RESEARCH.md`, gap G6). Don't market this as a multi-host "fleet" stop.
    """
    monitor = RuntimeMonitor(runtime_config or RuntimeConfig())
    gate = ControlledGate(
        capability=CapabilityLayer(registry),
        policy=PolicyEngine.from_file(policy_path),
        runtime=RuntimeLayer(monitor),
        audit=HashChainedAudit(audit_path),
    )
    return gate, monitor
