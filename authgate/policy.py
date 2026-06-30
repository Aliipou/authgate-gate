from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .action import Action
from .intent import Intent

# The purpose policy reads only the five core fields shared by the legacy
# `Intent` and the canonical `Action` packet, so it accepts either.
Packet = Intent | Action


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    TRANSFORM = "transform"


@dataclass(frozen=True)
class Decision:
    """The gate's ruling on a single packet. Deterministic and explainable."""

    verdict: Verdict
    reason: str
    transformed: Packet | None = None  # populated only when verdict is TRANSFORM


class PolicyEngine:
    """Deterministic purpose-binding policy. No ML, no probability, no surprises.

    Rule of evaluation:
      1. Every data label attached to a call carries a *purpose*. The action's
         purpose must be permitted for each of those data purposes. One mismatch
         -> DENY. An unknown data purpose under default-deny -> DENY.
      2. If allowed, redaction rules may strip fields that are not needed for the
         action's purpose -> TRANSFORM (the call still runs, but minimized).
      3. Otherwise -> ALLOW.
    """

    def __init__(self, policy: dict[str, Any]) -> None:
        self._default_deny = policy.get("default", "deny") == "deny"
        # data_purpose -> list of action purposes that data may flow into
        self._bindings: dict[str, list[str]] = policy.get("purpose_bindings", {})
        self._redactions: list[dict[str, Any]] = policy.get("redactions", [])

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyEngine:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def evaluate(self, intent: Packet) -> Decision:
        # 1. Purpose-binding: data may only be used for purposes it permits.
        for label in intent.data_labels:
            allowed = self._bindings.get(label)
            if allowed is None:
                if self._default_deny:
                    return Decision(
                        Verdict.DENY,
                        f"unknown data purpose '{label}' -> default-deny",
                    )
                continue
            if intent.action_purpose not in allowed:
                return Decision(
                    Verdict.DENY,
                    f"purpose mismatch: '{label}' data may not flow into "
                    f"action purpose '{intent.action_purpose}'",
                )

        # 2. Data minimization: redact fields not needed for this purpose.
        for rule in self._redactions:
            if rule.get("action_purpose") != intent.action_purpose:
                continue
            present = [
                f
                for f in rule.get("redact_fields", [])
                if f in intent.payload and intent.payload[f] not in (None, "")
            ]
            if present:
                new_payload = dict(intent.payload)
                for f in present:
                    new_payload[f] = "[REDACTED]"
                transformed = dataclasses.replace(intent, payload=new_payload)
                return Decision(
                    Verdict.TRANSFORM,
                    f"allowed, but redacted {present} (not required for "
                    f"'{intent.action_purpose}')",
                    transformed=transformed,
                )

        # 3. All data purposes permit this action.
        return Decision(Verdict.ALLOW, "all data purposes permit this action")
