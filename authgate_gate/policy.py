from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .action import Action
from .intent import Intent

_REDACTED = "[REDACTED]"
# Below this length a redacted value is too generic to chase across other fields
# without risking absurd over-redaction (e.g. a secret of "1" blanking every "1"
# in the payload). The *named* field is redacted regardless of length; only the
# cross-field value scrub for aliases/echoes is gated by this.
_MIN_SCRUB_LEN = 4


def _redact_fields(value: Any, fields: set[str], hits: set[str], secrets: set[str]) -> Any:
    """Recursively replace any mapping key in ``fields`` with ``[REDACTED]``.

    A shallow, top-level-only redaction is trivially bypassed by nesting the
    secret (``meta.ssn``). This walks the whole structure so a named field is
    redacted at *any* depth. Field names actually hit are recorded in ``hits``
    (for the reason string) and their scalar values in ``secrets`` (so the same
    value can then be scrubbed where it was aliased/echoed under another name).
    """
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if k in fields and v not in (None, ""):
                hits.add(k)
                if isinstance(v, str) or (isinstance(v, (int, float)) and not isinstance(v, bool)):
                    sv = str(v)
                    if len(sv) >= _MIN_SCRUB_LEN:
                        secrets.add(sv)
                out[k] = _REDACTED
            else:
                out[k] = _redact_fields(v, fields, hits, secrets)
        return out
    if isinstance(value, list):
        return [_redact_fields(v, fields, hits, secrets) for v in value]
    if isinstance(value, tuple):
        return tuple(_redact_fields(v, fields, hits, secrets) for v in value)
    return value


def _pattern_secrets(value: Any, patterns: list[re.Pattern[str]], out: set[str]) -> None:
    """Collect every substring in the payload matching a sensitive-content
    pattern (e.g. an SSN or PAN), at any depth.

    Field-name redaction trusts the attacker to put the secret in the one named
    key. A lying agent instead hides a raw SSN in ``body`` or ``to`` under a
    blessed label. Content screening catches the *value* wherever it hides,
    independent of the self-attached label — closing the trivial exfil. It is
    pattern-based, so it is a floor (known formats), not a proof; an obfuscated/
    encoded secret can still slip. It raises the bar; it does not make egress of
    unknown-shaped sensitive data safe.
    """
    if isinstance(value, str):
        for pat in patterns:
            for m in pat.findall(value):
                s = m if isinstance(m, str) else next((g for g in m if g), "")
                if s:
                    out.add(s)
    elif isinstance(value, Mapping):
        for v in value.values():
            _pattern_secrets(v, patterns, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _pattern_secrets(v, patterns, out)


def _scrub_values(value: Any, secrets: set[str]) -> Any:
    """Replace every occurrence of a known secret value with ``[REDACTED]``.

    Catches the same secret surfacing under a *different* field name
    (``ssn_copy``) or embedded inside free text (``body``) — cases a
    field-name-based redaction cannot see. Content-based, so the minimization
    guarantee no longer depends on the attacker using the one named key.
    """
    if not secrets:
        return value
    if isinstance(value, str):
        out = value
        for s in secrets:
            if s and s in out:
                out = out.replace(s, _REDACTED)
        return out
    if isinstance(value, Mapping):
        return {k: _scrub_values(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_values(v, secrets) for v in value]
    if isinstance(value, tuple):
        return tuple(_scrub_values(v, secrets) for v in value)
    return value

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
        # Precompile any content patterns per redaction rule once. A rule may
        # declare `redact_patterns` (regexes) alongside `redact_fields`: the
        # former screens by *value* (content), the latter by *field name*.
        self._patterns: list[list[re.Pattern[str]]] = [
            [re.compile(p) for p in rule.get("redact_patterns", [])]
            for rule in self._redactions
        ]

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
        #    Two passes: (a) redact the named fields wherever they appear, at any
        #    depth — collecting the secret values; (b) scrub those values from
        #    anywhere else they were aliased or echoed. A shallow top-level
        #    name-match alone is bypassed by nesting/aliasing/echoing the secret.
        for rule, patterns in zip(self._redactions, self._patterns, strict=True):
            if rule.get("action_purpose") != intent.action_purpose:
                continue
            fields = {f for f in rule.get("redact_fields", [])}
            hits: set[str] = set()
            secrets: set[str] = set()
            redacted = _redact_fields(dict(intent.payload), fields, hits, secrets)
            # Content screen: collect values matching a sensitive pattern anywhere
            # in the payload, regardless of the (possibly lying) label.
            if patterns:
                _pattern_secrets(redacted, patterns, secrets)
            if hits or secrets:
                scrubbed = _scrub_values(redacted, secrets)
                transformed = dataclasses.replace(intent, payload=scrubbed)
                what = sorted(hits) or "sensitive content"
                return Decision(
                    Verdict.TRANSFORM,
                    f"allowed, but redacted {what} (not required for "
                    f"'{intent.action_purpose}')",
                    transformed=transformed,
                )

        # 3. All data purposes permit this action.
        return Decision(Verdict.ALLOW, "all data purposes permit this action")
