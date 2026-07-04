"""Deterministic checks for the capability layer.

No framework needed: `python tests/test_capability.py`.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from authgate_gate import Action, Verdict
from authgate_gate.capability import CapabilityLayer, CapabilityRegistry


def _layer(registry: CapabilityRegistry) -> CapabilityLayer:
    return CapabilityLayer(registry)


def test_granted_tool_allows() -> None:
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    d = _layer(reg).check(Action("agent:bot", "send_email", "support_reply"))
    assert d.verdict is Verdict.ALLOW, d


def test_ungranted_tool_denied_default_deny() -> None:
    # No grants at all -> actor can do nothing.
    reg = CapabilityRegistry()
    d = _layer(reg).check(Action("agent:bot", "send_email", "support_reply"))
    assert d.verdict is Verdict.DENY, d


def test_granted_other_tool_does_not_leak() -> None:
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "read_file")
    d = _layer(reg).check(Action("agent:bot", "send_email", "support_reply"))
    assert d.verdict is Verdict.DENY, d


def test_revoke_removes_access() -> None:
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    layer = _layer(reg)
    assert layer.check(Action("agent:bot", "send_email", "p")).verdict is Verdict.ALLOW
    reg.revoke("agent:bot", "tool:send_email")
    d = layer.check(Action("agent:bot", "send_email", "p"))
    assert d.verdict is Verdict.DENY, d


def test_wildcard_allows_anything() -> None:
    reg = CapabilityRegistry()
    reg.grant("admin", "*")
    layer = _layer(reg)
    assert layer.check(Action("admin", "send_email", "p")).verdict is Verdict.ALLOW
    assert layer.check(Action("admin", "delete_database", "p")).verdict is Verdict.ALLOW
    # Even an explicit non-tool capability is covered by the wildcard.
    assert layer.check(Action("admin", "x", "p", capability="billing:refund")).verdict is Verdict.ALLOW


def test_explicit_non_tool_capability_grant() -> None:
    reg = CapabilityRegistry()
    reg.grant("agent:bot", "billing:refund")
    layer = _layer(reg)
    allow = layer.check(Action("agent:bot", "x", "p", capability="billing:refund"))
    assert allow.verdict is Verdict.ALLOW, allow
    # Holding the explicit capability does NOT grant the tool capability.
    deny = layer.check(Action("agent:bot", "send_email", "p"))
    assert deny.verdict is Verdict.DENY, deny


def test_actor_cannot_use_another_actors_grant() -> None:
    reg = CapabilityRegistry()
    reg.grant_tool("agent:alice", "send_email")
    d = _layer(reg).check(Action("agent:bob", "send_email", "p"))
    assert d.verdict is Verdict.DENY, d


def test_granted_returns_canonical_set() -> None:
    reg = CapabilityRegistry()
    reg.grant_tool("Agent:Bot", "Send_Email")
    # Grant stored/queried under normalized actor + capability.
    assert reg.granted("agent:bot") == frozenset({"tool:send_email"})
    assert reg.granted("AGENT:BOT") == frozenset({"tool:send_email"})


def test_case_normalization_no_bypass() -> None:
    # Grant with mixed case; Action tool given in different case -> still matches.
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "Send_Email")
    d = _layer(reg).check(Action("agent:bot", "send_email", "p"))
    assert d.verdict is Verdict.ALLOW, d


def test_zero_width_unicode_no_bypass() -> None:
    # Raw tool name carries a zero-width joiner (U+200D, category Cf). It is
    # stripped by normalization, so "send‍_email" canonicalizes to the same
    # token as the granted "send_email" -> no split, no bypass.
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    smuggled = "send‍_email"
    assert smuggled != "send_email"  # raw strings differ
    d = _layer(reg).check(Action("agent:bot", smuggled, "p"))
    assert d.verdict is Verdict.ALLOW, d


def test_fullwidth_unicode_no_bypass() -> None:
    # NFKC folds fullwidth look-alikes; the grant and the look-alike tool match.
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    # 'ｓｅｎｄ＿ｅｍａｉｌ' fullwidth -> 'send_email' after NFKC.
    fullwidth = "ｓｅｎｄ＿ｅｍａｉｌ"
    assert fullwidth != "send_email"
    d = _layer(reg).check(Action("agent:bot", fullwidth, "p"))
    assert d.verdict is Verdict.ALLOW, d


def test_determinism() -> None:
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    layer = _layer(reg)
    action = Action("agent:bot", "send_email", "p")
    assert layer.check(action).verdict == layer.check(action).verdict
    # And a denied case is equally stable.
    denied = Action("agent:bot", "delete_db", "p")
    assert layer.check(denied).verdict == layer.check(denied).verdict


def test_fail_closed_on_malformed_object() -> None:
    # A non-Action object with no .capability attribute must DENY, not raise.
    class Bogus:
        actor = "agent:bot"
        # no `capability` attribute -> AttributeError inside check()

    reg = CapabilityRegistry()
    reg.grant("agent:bot", "*")  # even an admin grant must not rescue a malformed packet
    d = _layer(reg).check(Bogus())  # type: ignore[arg-type]
    assert d.verdict is Verdict.DENY, d
    assert "capability layer error" in d.reason, d


def test_fail_closed_on_non_string_fields() -> None:
    # Actor present but not a string -> deny, no exception.
    class Weird:
        actor = 123
        capability = object()

    reg = CapabilityRegistry()
    d = _layer(reg).check(Weird())  # type: ignore[arg-type]
    assert d.verdict is Verdict.DENY, d


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
            except Exception as e:  # surface unexpected errors as failures too
                failures += 1
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print(f"\n{'all passed' if not failures else f'{failures} failed'}")
    sys.exit(1 if failures else 0)
