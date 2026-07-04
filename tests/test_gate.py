"""Deterministic checks. No framework needed: `python tests/test_gate.py`."""

from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from authgate_gate import AuditLog, AuthGate, Intent, PolicyEngine, Verdict

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _gate() -> AuthGate:
    tmp = pathlib.Path(tempfile.mkdtemp()) / "audit.jsonl"
    return AuthGate(
        policy=PolicyEngine.from_file(ROOT / "policies" / "purpose_policy.json"),
        audit=AuditLog(tmp),
    )


def test_legit_support_reply_allowed() -> None:
    d = _gate().enforce(Intent("a", "send_email", "support_reply", ("customer_support",)))
    assert d.verdict is Verdict.ALLOW, d


def test_purpose_mismatch_denied() -> None:
    # The prompt-injection case: support data into a marketing action.
    d = _gate().enforce(Intent("a", "send_email", "marketing", ("customer_support",)))
    assert d.verdict is Verdict.DENY, d


def test_unknown_purpose_default_deny() -> None:
    d = _gate().enforce(Intent("a", "send_email", "marketing", ("scraped_pii",)))
    assert d.verdict is Verdict.DENY, d


def test_redaction_transforms() -> None:
    d = _gate().enforce(
        Intent("a", "send_email", "support_reply", ("customer_support",),
               {"body": "ok", "ssn": "123-45-6789"})
    )
    assert d.verdict is Verdict.TRANSFORM, d
    assert d.transformed is not None
    assert d.transformed.payload["ssn"] == "[REDACTED]"


def test_determinism() -> None:
    intent = Intent("a", "send_email", "marketing", ("customer_support",))
    g = _gate()
    assert g.enforce(intent).verdict == g.enforce(intent).verdict


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
