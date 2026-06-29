from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Intent:
    """A normalized request to perform one action — what the agent *wants* to do.

    The agent is an intent generator, never an executor. It hands an Intent to
    AuthGate; the gate is the authority that decides whether the action runs.

    Fields:
        actor:          who/what is acting, e.g. "agent:support-bot".
        tool:           the tool to invoke, e.g. "send_email".
        action_purpose: WHY this call happens, e.g. "support_reply" / "marketing".
        data_labels:    provenance/purpose of the data being used in this call.
                        This is the heart of purpose-binding: data carries the
                        purpose it was collected for, and that constrains use.
        payload:        the concrete arguments handed to the tool.
    """

    actor: str
    tool: str
    action_purpose: str
    data_labels: tuple[str, ...] = ()
    payload: dict[str, Any] = field(default_factory=dict)
