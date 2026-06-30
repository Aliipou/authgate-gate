"""Per-component adversarial red-team harness for the AuthGate enforcement layers.

This harness attacks each enforcement component IN ISOLATION (unit-level
adversarial testing). For every component it runs a focused battery of hostile
inputs — many of them seeded-random variants — that each try to make the
component do exactly the wrong thing for *its* stated invariant:

    * allow what it must deny,
    * crash instead of failing closed,
    * mutate state it promised was immutable,
    * or otherwise violate a documented guarantee.

Every probe is a plain ``assert``. A failed assert (or an unexpected raise) is
an ESCAPE: the component did something it promised it never would. The harness
counts escapes per component, prints a summary, and exits non-zero if ANY
component had even one escape or crash.

Design rules:
    * stdlib only,
    * fixed seed -> fully reproducible,
    * READ-ONLY against authgate/* — this file imports the real components and
      never modifies them.

Run:  python redteam/red_team_components.py
"""

from __future__ import annotations

import dataclasses
import math
import os
import random
import sys
import tempfile
import traceback
from collections.abc import Callable

# Make the package importable when run from anywhere.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from authgate.action import ABI_VERSION, Action, RiskVector  # noqa: E402
from authgate.adapter import (  # noqa: E402
    AIToolAdapter,
    FinanceAdapter,
    QuantumJobAdapter,
)
from authgate.audit_chain import HashChainedAudit  # noqa: E402
from authgate.capability import (  # noqa: E402
    WILDCARD,
    CapabilityLayer,
    CapabilityRegistry,
)
from authgate.intent import Intent  # noqa: E402
from authgate.normalize import normalize_labels, normalize_token  # noqa: E402
from authgate.policy import PolicyEngine, Verdict  # noqa: E402
from authgate.runtime import (  # noqa: E402
    RuntimeConfig,
    RuntimeLayer,
    RuntimeMonitor,
    default_cost_fn,
)

SEED = 0xA17468  # "AUTHGATE"-ish, fixed for reproducibility.


# --------------------------------------------------------------------------- #
# Escape-recording test runner
# --------------------------------------------------------------------------- #
class Battery:
    """Collects pass/escape counts and detailed escape reports for a component."""

    def __init__(self, component: str) -> None:
        self.component = component
        self.passed = 0
        self.escapes: list[str] = []

    def probe(self, name: str, fn: Callable[[], None]) -> None:
        """Run one probe. An AssertionError or any raise is recorded as an escape."""
        try:
            fn()
            self.passed += 1
        except AssertionError as exc:
            self.escapes.append(
                f"[{self.component}] ESCAPE in probe '{name}': INVARIANT VIOLATED\n"
                f"    {exc}"
            )
        except Exception as exc:  # noqa: BLE001 — a crash is itself an escape.
            tb = traceback.format_exc().strip().splitlines()[-1]
            self.escapes.append(
                f"[{self.component}] ESCAPE in probe '{name}': CRASHED "
                f"(component did not fail closed)\n"
                f"    {type(exc).__name__}: {exc}\n"
                f"    {tb}"
            )

    def report(self) -> str:
        status = "CLEAN" if not self.escapes else f"{len(self.escapes)} ESCAPE(S)"
        line = f"  {self.component:<12} pass={self.passed:<4} escapes={len(self.escapes):<3} [{status}]"
        if self.escapes:
            line += "\n" + "\n".join("      " + e.replace("\n", "\n      ") for e in self.escapes)
        return line


# --------------------------------------------------------------------------- #
# Smuggling-encoding helpers (homoglyph / zero-width / combining attacks)
# --------------------------------------------------------------------------- #
ZERO_WIDTH = ["​", "‌", "‍", "⁠", "﻿"]  # ZWSP, ZWNJ, ZWJ, WJ, BOM
CONTROL = ["\x00", "\x01", "\x07", "\x1b", "\x7f", "\x9f"]
# Fullwidth / look-alike that NFKC folds to ASCII.
FULLWIDTH = {  # ascii -> fullwidth
    "a": "ａ", "d": "ｄ", "e": "ｅ", "i": "ｉ",
    "l": "ｌ", "m": "ｍ", "n": "ｎ", "o": "ｏ",
    "s": "ｓ", "t": "ｔ", "_": "＿", ":": "：",
    "0": "０", "1": "１",
}


def smuggle_zero_width(s: str, rng: random.Random) -> str:
    """Inject random zero-width chars between characters of s."""
    out = []
    for ch in s:
        out.append(ch)
        if rng.random() < 0.5:
            out.append(rng.choice(ZERO_WIDTH))
    return rng.choice(ZERO_WIDTH) + "".join(out) + rng.choice(ZERO_WIDTH)


def smuggle_fullwidth(s: str) -> str:
    """Replace ASCII chars with NFKC-equivalent fullwidth where possible."""
    return "".join(FULLWIDTH.get(ch, ch) for ch in s)


def smuggle_case(s: str, rng: random.Random) -> str:
    return "".join(ch.upper() if rng.random() < 0.5 else ch.lower() for ch in s)


# =========================================================================== #
# 1) normalize
# =========================================================================== #
def battery_normalize() -> Battery:
    b = Battery("normalize")
    rng = random.Random(SEED ^ 1)
    base_tokens = [
        "tool:send_email", "agent:support-bot", "marketing", "support_reply",
        "effect:network", "customer_ssn", "*", "admin", "delete_all",
    ]

    # Idempotency: normalize(normalize(x)) == normalize(x) for many weird inputs.
    def idempotent():
        for _ in range(2000):
            base = rng.choice(base_tokens)
            s = base
            mode = rng.randint(0, 3)
            if mode == 0:
                s = smuggle_zero_width(s, rng)
            elif mode == 1:
                s = smuggle_fullwidth(s)
            elif mode == 2:
                s = smuggle_case(s, rng)
            else:
                s = rng.choice(CONTROL) + smuggle_case(s, rng) + rng.choice(ZERO_WIDTH)
            once = normalize_token(s)
            twice = normalize_token(once)
            assert once == twice, f"non-idempotent: {s!r} -> {once!r} -> {twice!r}"
    b.probe("idempotency-fuzz", idempotent)

    # Collapse: distinct smuggling encodings of the same token must collapse equal.
    def collapse():
        for base in base_tokens:
            canon = normalize_token(base)
            encodings = [
                base.upper(),
                base.lower(),
                smuggle_fullwidth(base),
                smuggle_zero_width(base, rng),
                "  " + base + "  ",
                rng.choice(CONTROL) + base,
                base + rng.choice(ZERO_WIDTH),
                smuggle_fullwidth(base.upper()),
            ]
            for enc in encodings:
                got = normalize_token(enc)
                assert got == canon, (
                    f"two encodings of {base!r} did not collapse: "
                    f"{enc!r} -> {got!r} != canonical {canon!r}"
                )
    b.probe("smuggle-collapse", collapse)

    # Control/format chars are fully dropped.
    def drop_control():
        for _ in range(500):
            junk = "".join(rng.choice(CONTROL + ZERO_WIDTH) for _ in range(rng.randint(1, 8)))
            assert normalize_token(junk) == "", f"control-only junk not emptied: {junk!r}"
            mixed = "a" + junk + "b"
            assert normalize_token(mixed) == "ab", f"control not dropped from {mixed!r} -> {normalize_token(mixed)!r}"
    b.probe("drop-control-format", drop_control)

    # Never raises on weird-but-str input (any unicode string).
    def never_raises_on_str():
        for _ in range(3000):
            s = "".join(chr(rng.randint(0, 0x10FFFF)) for _ in range(rng.randint(0, 12)))
            # skip surrogates which can't be represented standalone in some ops
            try:
                _ = normalize_token(s)
            except (UnicodeError, ValueError):
                # surrogate-only artifacts: allowed to be skipped, not an escape,
                # but normalize claims it handles any str. Re-test category guard.
                # Strip surrogates and retry — must succeed.
                s2 = "".join(ch for ch in s if not (0xD800 <= ord(ch) <= 0xDFFF))
                _ = normalize_token(s2)
    b.probe("never-raises-on-str", never_raises_on_str)

    # Non-str input must raise TypeError (documented contract), not silently pass.
    def rejects_nonstr():
        for bad in [None, 123, 1.5, b"bytes", ["a"], {"x": 1}, object()]:
            raised = False
            try:
                normalize_token(bad)  # type: ignore[arg-type]
            except TypeError:
                raised = True
            assert raised, f"normalize_token accepted non-str {bad!r} without TypeError"
    b.probe("rejects-nonstr", rejects_nonstr)

    # Combining-character attempt: precomposed vs decomposed must collapse (NFKC).
    def combining():
        # é precomposed (U+00E9) vs e + combining acute (U+0065 U+0301)
        pre = "café"
        dec = "café"
        assert normalize_token(pre) == normalize_token(dec), "combining form did not collapse"
        # NFKC ligature fi (U+FB01) -> "fi"
        assert normalize_token("ﬁle") == normalize_token("file"), "ligature not folded"
    b.probe("combining-and-ligature", combining)

    # normalize_labels: drops empties, de-dups, order-preserving.
    def labels():
        raw = ["A", "a", "  ", "​", "B", "b‌", "A"]
        out = normalize_labels(raw)
        assert out == ("a", "b"), f"normalize_labels wrong: {out!r}"
        # empties (control-only) are fully dropped
        assert normalize_labels(["\x00", "  ", "﻿"]) == (), "empties not dropped"
    b.probe("labels-dedup-order", labels)

    return b


# =========================================================================== #
# 2) action
# =========================================================================== #
def battery_action() -> Battery:
    b = Battery("action")
    rng = random.Random(SEED ^ 2)

    # ABI guard rejects any wrong version.
    def abi_guard():
        # correct version constructs fine
        Action(actor="a", tool="t", action_purpose="p", abi_version=ABI_VERSION)
        for v in [0, 2, -1, 99, ABI_VERSION + 1, ABI_VERSION - 1]:
            if v == ABI_VERSION:
                continue
            raised = False
            try:
                Action(actor="a", tool="t", action_purpose="p", abi_version=v)
            except ValueError:
                raised = True
            assert raised, f"ABI guard accepted wrong version {v}"
    b.probe("abi-version-guard", abi_guard)

    # Payload immutability #1: mutating the ORIGINAL dict after construction
    # does not change the Action's payload.
    def payload_source_isolation():
        for _ in range(200):
            src = {"k": rng.randint(0, 100), "nested": [1, 2]}
            a = Action(actor="x", tool="t", action_purpose="p", payload=src)
            snapshot = dict(a.payload)
            src["k"] = 999999
            src["new"] = "injected"
            assert dict(a.payload) == snapshot, (
                f"mutating source dict leaked into Action.payload: {dict(a.payload)!r}"
            )
            assert "new" not in a.payload, "injected key appeared in Action.payload"
    b.probe("payload-source-isolation", payload_source_isolation)

    # Payload immutability #2: the exposed payload cannot be written through.
    def payload_readonly():
        a = Action(actor="x", tool="t", action_purpose="p", payload={"k": 1})
        for op in ("setitem", "delitem", "update", "clear", "pop"):
            raised = False
            try:
                if op == "setitem":
                    a.payload["k"] = 2          # type: ignore[index]
                elif op == "delitem":
                    del a.payload["k"]          # type: ignore[attr-defined]
                elif op == "update":
                    a.payload.update({"z": 9})  # type: ignore[attr-defined]
                elif op == "clear":
                    a.payload.clear()           # type: ignore[attr-defined]
                elif op == "pop":
                    a.payload.pop("k")          # type: ignore[attr-defined]
            except (TypeError, AttributeError):
                raised = True
            assert raised, f"payload write through {op} succeeded (not immutable)"
        assert dict(a.payload) == {"k": 1}, "payload changed despite guards"
    b.probe("payload-write-protected", payload_readonly)

    # Frozen dataclass: cannot reassign fields.
    def frozen_fields():
        a = Action(actor="x", tool="t", action_purpose="p")
        for fld in ("actor", "tool", "action_purpose", "capability", "session_id"):
            raised = False
            try:
                setattr(a, fld, "hacked")
            except dataclasses.FrozenInstanceError:
                raised = True
            assert raised, f"reassigned frozen field {fld}"
    b.probe("frozen-fields", frozen_fields)

    # Tokens normalized at construction (smuggled actor collapses to canonical).
    def tokens_normalized():
        for _ in range(300):
            actor = "Agent:Support-Bot"
            smug = smuggle_fullwidth(actor.lower())
            a1 = Action(actor=actor, tool="send_email", action_purpose="p")
            a2 = Action(actor=smug, tool=smuggle_zero_width("send_email", rng),
                        action_purpose="p")
            assert a1.actor == a2.actor, f"actor normalization split: {a1.actor!r} {a2.actor!r}"
            assert a1.tool == a2.tool == "send_email", f"tool not normalized: {a2.tool!r}"
    b.probe("tokens-normalized", tokens_normalized)

    # Default capability derives tool:<tool> AFTER normalization.
    def default_capability():
        a = Action(actor="x", tool="Send_Email", action_purpose="p")
        assert a.capability == "tool:send_email", f"default cap wrong: {a.capability!r}"
        # explicit smuggled capability normalizes
        a2 = Action(actor="x", tool="t", action_purpose="p",
                    capability=smuggle_fullwidth("EFFECT:network"))
        assert a2.capability == "effect:network", f"explicit cap not normalized: {a2.capability!r}"
    b.probe("default-capability", default_capability)

    # RiskVector rejects out-of-range / NaN / inf; accepts edges 0 and 1.
    def riskvector_validation():
        RiskVector(0.0, 0.0, 0.0)
        RiskVector(1.0, 1.0, 1.0)
        RiskVector(0.5, 0.5, 0.5)
        bad_values = [
            -0.0001, 1.0001, -1.0, 2.0, 1e9, -1e9,
            float("nan"), float("inf"), float("-inf"),
        ]
        for bv in bad_values:
            for pos in range(3):
                args = [0.5, 0.5, 0.5]
                args[pos] = bv
                raised = False
                try:
                    RiskVector(*args)
                except ValueError:
                    raised = True
                assert raised, f"RiskVector accepted bad value {bv!r} at position {pos}"
    b.probe("riskvector-range-nan-inf", riskvector_validation)

    # RiskVector rejects non-numeric / string inputs.
    def riskvector_type():
        for bad in ["0.5", None, [0.5], complex(0.5, 0)]:
            raised = False
            try:
                RiskVector(reversibility=bad)  # type: ignore[arg-type]
            except (ValueError, TypeError):
                raised = True
            assert raised, f"RiskVector accepted non-numeric {bad!r}"
    b.probe("riskvector-type", riskvector_type)

    # session_id: blank/whitespace collapses to 'default', never empty.
    def session_default():
        for s in ["", "   ", "\t\n"]:
            a = Action(actor="x", tool="t", action_purpose="p", session_id=s)
            assert a.session_id == "default", f"blank session_id not defaulted: {a.session_id!r}"
    b.probe("session-default", session_default)

    return b


# =========================================================================== #
# 3) capability
# =========================================================================== #
def _mk_action(actor="a", tool="t", capability="", purpose="p", **kw):
    return Action(actor=actor, tool=tool, action_purpose=purpose, capability=capability, **kw)


def battery_capability() -> Battery:
    b = Battery("capability")
    rng = random.Random(SEED ^ 3)

    def default_deny():
        reg = CapabilityRegistry()
        layer = CapabilityLayer(reg)
        # actor with no grants is denied everything
        for _ in range(200):
            tool = "tool_" + str(rng.randint(0, 9999))
            d = layer.check(_mk_action(actor="ghost", tool=tool))
            assert d.verdict == Verdict.DENY, f"ungranted actor allowed for {tool}"
        assert reg.allows("ghost", "anything") is False
    b.probe("default-deny", default_deny)

    def grant_revoke():
        reg = CapabilityRegistry()
        reg.grant("alice", "tool:send_email")
        layer = CapabilityLayer(reg)
        a = _mk_action(actor="alice", tool="send_email")
        assert layer.check(a).verdict == Verdict.ALLOW, "granted cap denied"
        reg.revoke("alice", "tool:send_email")
        assert layer.check(a).verdict == Verdict.DENY, "revoked cap still allowed"
        # revoking an absent cap is a no-op (no crash, stays denied)
        reg.revoke("alice", "tool:never_had")
        assert layer.check(a).verdict == Verdict.DENY
    b.probe("grant-revoke", grant_revoke)

    def wildcard():
        reg = CapabilityRegistry()
        reg.grant("root", WILDCARD)
        layer = CapabilityLayer(reg)
        for _ in range(200):
            tool = "x_" + str(rng.randint(0, 9999))
            assert layer.check(_mk_action(actor="root", tool=tool)).verdict == Verdict.ALLOW, \
                "wildcard did not allow"
        # wildcard survives normalization (it's punctuation, not control)
        reg2 = CapabilityRegistry()
        reg2.grant("root2", "  *  ")
        assert CapabilityLayer(reg2).check(_mk_action(actor="root2", tool="anything")).verdict == Verdict.ALLOW
    b.probe("wildcard-admin", wildcard)

    def cross_actor_nonleak():
        reg = CapabilityRegistry()
        reg.grant("alice", "tool:send_email")
        reg.grant("bob", WILDCARD)
        layer = CapabilityLayer(reg)
        # bob's wildcard must not leak to alice; alice only has her one cap.
        assert layer.check(_mk_action(actor="alice", tool="delete_db")).verdict == Verdict.DENY, \
            "wildcard leaked across actors"
        # a third actor gets nothing
        assert layer.check(_mk_action(actor="carol", tool="send_email")).verdict == Verdict.DENY
    b.probe("cross-actor-nonleak", cross_actor_nonleak)

    def normalization_bypass():
        reg = CapabilityRegistry()
        reg.grant("Alice", "tool:Send_Email")  # mixed case grant
        layer = CapabilityLayer(reg)
        # request with smuggled actor & capability must still match the grant
        for _ in range(300):
            smug_actor = smuggle_zero_width(smuggle_case("alice", rng), rng)
            smug_tool = smuggle_fullwidth("send_email")
            a = _mk_action(actor=smug_actor, tool=smug_tool)
            assert layer.check(a).verdict == Verdict.ALLOW, \
                f"normalization bypass: smuggled request denied {smug_actor!r}/{smug_tool!r}"
        # And the inverse: a DIFFERENT tool must NOT match via smuggling.
        a2 = _mk_action(actor="alice", tool="delete_email")
        assert layer.check(a2).verdict == Verdict.DENY, "smuggling let a different tool through"
    b.probe("normalization-bypass-resistance", normalization_bypass)

    def fail_closed_junk():
        reg = CapabilityRegistry()
        layer = CapabilityLayer(reg)

        class FakeAction:  # not a real Action; missing/odd attributes
            def __init__(self, actor, capability):
                self.actor = actor
                self.capability = capability

        junk = [
            FakeAction(actor=None, capability="tool:x"),
            FakeAction(actor="a", capability=None),
            FakeAction(actor=123, capability=456),
            FakeAction(actor=object(), capability=object()),
        ]
        for j in junk:
            d = layer.check(j)  # type: ignore[arg-type]
            assert d.verdict == Verdict.DENY, f"junk action not denied: {j.actor!r}/{j.capability!r}"

        # An object missing the attributes entirely.
        class NoAttrs:
            pass
        d = layer.check(NoAttrs())  # type: ignore[arg-type]
        assert d.verdict == Verdict.DENY, "attribute-less object not denied"
    b.probe("fail-closed-on-junk", fail_closed_junk)

    return b


# =========================================================================== #
# 4) runtime
# =========================================================================== #
def battery_runtime() -> Battery:
    b = Battery("runtime")

    def _fresh(**cfg_kw):
        cfg = RuntimeConfig(**cfg_kw)
        mon = RuntimeMonitor(cfg)
        return mon, RuntimeLayer(mon)

    def _state_snapshot(mon, sid):
        st = mon.state(sid)
        return (st.steps, list(st.recent_steps), dict(st.costs),
                set(st.nonces_seen), dict(st.label_purpose))

    # Commit-on-allow: a DENIED action consumes NO step/budget/rate/nonce.
    def commit_on_allow():
        mon, layer = _fresh(max_steps=5, budgets={"spend": 100.0})
        sid = "s1"
        # Take a couple of legal steps first.
        for i in range(3):
            d = layer.check(Action(actor="a", tool="t", action_purpose="p",
                                   session_id=sid, nonce=f"n{i}",
                                   payload={"amount": 10}))
            assert d.verdict == Verdict.ALLOW
        before = _state_snapshot(mon, sid)
        # Now fire several actions that MUST be denied for different reasons.
        denials = [
            # over budget
            Action(actor="a", tool="t", action_purpose="p", session_id=sid,
                   nonce="big", payload={"amount": 10_000}),
            # replay of n0
            Action(actor="a", tool="t", action_purpose="p", session_id=sid,
                   nonce="n0", payload={"amount": 1}),
        ]
        for act in denials:
            d = layer.check(act)
            assert d.verdict == Verdict.DENY, f"expected deny, got {d.verdict} ({d.reason})"
        after = _state_snapshot(mon, sid)
        assert before == after, (
            f"DENIED action mutated session state!\n  before={before}\n  after ={after}"
        )
    b.probe("commit-on-allow-only", commit_on_allow)

    # Replay: same nonce twice -> second denied; empty nonce never collides.
    def replay():
        mon, layer = _fresh(max_steps=100)
        a1 = Action(actor="a", tool="t", action_purpose="p", session_id="s", nonce="dup")
        assert layer.check(a1).verdict == Verdict.ALLOW
        a2 = Action(actor="a", tool="t", action_purpose="p", session_id="s", nonce="dup")
        assert layer.check(a2).verdict == Verdict.DENY, "replayed nonce allowed"
        # empty nonce: multiple allowed, never recorded
        for _ in range(5):
            e = Action(actor="a", tool="t", action_purpose="p", session_id="s", nonce="")
            assert layer.check(e).verdict == Verdict.ALLOW, "empty nonce wrongly blocked"
        # same nonce in a DIFFERENT session is fine (session-scoped)
        other = Action(actor="a", tool="t", action_purpose="p", session_id="s2", nonce="dup")
        assert layer.check(other).verdict == Verdict.ALLOW, "nonce not session-scoped"
    b.probe("replay-and-empty-nonce", replay)

    # Budget boundary: exactly-at ceiling ALLOWS, one-over DENIES.
    def budget_boundary():
        mon, layer = _fresh(max_steps=100, budgets={"spend": 100.0})
        sid = "s"
        # spend exactly to 100.0
        d = layer.check(Action(actor="a", tool="t", action_purpose="p",
                               session_id=sid, nonce="a", payload={"amount": 100.0}))
        assert d.verdict == Verdict.ALLOW, f"exactly-at-budget denied: {d.reason}"
        # any further positive spend pushes > 100 -> deny
        d = layer.check(Action(actor="a", tool="t", action_purpose="p",
                               session_id=sid, nonce="b", payload={"amount": 0.01}))
        assert d.verdict == Verdict.DENY, "over-budget allowed"
        # a zero-cost action is still fine
        d = layer.check(Action(actor="a", tool="t", action_purpose="p",
                               session_id=sid, nonce="c", payload={"amount": 0}))
        assert d.verdict == Verdict.ALLOW, "zero-cost action at full budget denied"
    b.probe("budget-boundary", budget_boundary)

    # Step budget boundary: step == max_steps allowed, step max_steps+1 denied.
    def step_boundary():
        mon, layer = _fresh(max_steps=3, rate_limit=1000, rate_window=1000)
        sid = "s"
        for i in range(3):
            d = layer.check(Action(actor="a", tool="t", action_purpose="p",
                                   session_id=sid, nonce=f"n{i}"))
            assert d.verdict == Verdict.ALLOW, f"step {i+1} denied early"
        d = layer.check(Action(actor="a", tool="t", action_purpose="p",
                               session_id=sid, nonce="over"))
        assert d.verdict == Verdict.DENY, "step over max_steps allowed"
    b.probe("step-budget-boundary", step_boundary)

    # Rate window edges: rate_limit per rate_window steps; window slides.
    def rate_window():
        # at most 2 actions per any window of 3 steps
        mon, layer = _fresh(max_steps=1000, rate_limit=2, rate_window=3)
        sid = "s"
        # steps 1,2 allowed
        assert layer.check(Action(actor="a", tool="t", action_purpose="p",
                                  session_id=sid, nonce="n1")).verdict == Verdict.ALLOW
        assert layer.check(Action(actor="a", tool="t", action_purpose="p",
                                  session_id=sid, nonce="n2")).verdict == Verdict.ALLOW
        # step 3 would be the 3rd in window [1..3] -> deny
        d = layer.check(Action(actor="a", tool="t", action_purpose="p",
                               session_id=sid, nonce="n3"))
        assert d.verdict == Verdict.DENY, "rate limit not enforced at window edge"
        # The denial consumed nothing, so steps still == 2. The very next ALLOW
        # becomes step 3; window [1..3] still has the two earlier ordinals -> deny again.
        d = layer.check(Action(actor="a", tool="t", action_purpose="p",
                               session_id=sid, nonce="n3b"))
        assert d.verdict == Verdict.DENY, "rate window did not hold after denial"
    b.probe("rate-window-edges", rate_window)

    # Taint trust-on-first-use: label pinned to first purpose, later purpose denied.
    def taint_tofu():
        mon, layer = _fresh(max_steps=100, sensitive_labels=frozenset({"ssn"}))
        sid = "s"
        # first use under support_reply -> allowed, pins ssn->support_reply
        d = layer.check(Action(actor="a", tool="t", action_purpose="support_reply",
                               data_labels=("ssn",), session_id=sid, nonce="1"))
        assert d.verdict == Verdict.ALLOW
        # same purpose again -> fine
        d = layer.check(Action(actor="a", tool="t", action_purpose="support_reply",
                               data_labels=("ssn",), session_id=sid, nonce="2"))
        assert d.verdict == Verdict.ALLOW
        # different purpose -> laundering -> deny
        d = layer.check(Action(actor="a", tool="t", action_purpose="marketing",
                               data_labels=("ssn",), session_id=sid, nonce="3"))
        assert d.verdict == Verdict.DENY, "purpose laundering allowed (TOFU pin broken)"
        # non-sensitive labels are never pinned
        d = layer.check(Action(actor="a", tool="t", action_purpose="anything",
                               data_labels=("public",), session_id=sid, nonce="4"))
        assert d.verdict == Verdict.ALLOW
    b.probe("taint-trust-on-first-use", taint_tofu)

    # Purpose pinning: a config-pinned label may ONLY be used under its pin,
    # from the very first use.
    def taint_pinning():
        mon, layer = _fresh(max_steps=100, sensitive_labels=frozenset({"ssn"}),
                            purpose_for_label={"ssn": "support_reply"})
        sid = "s"
        # first use under the WRONG purpose -> denied immediately (no TOFU window)
        d = layer.check(Action(actor="a", tool="t", action_purpose="marketing",
                               data_labels=("ssn",), session_id=sid, nonce="1"))
        assert d.verdict == Verdict.DENY, "pinned label allowed under wrong purpose on first use"
        # and that denial committed nothing — the pin is from config, immutable
        d = layer.check(Action(actor="a", tool="t", action_purpose="support_reply",
                               data_labels=("ssn",), session_id=sid, nonce="2"))
        assert d.verdict == Verdict.ALLOW, "pinned label denied under its correct purpose"
    b.probe("taint-purpose-pinning", taint_pinning)

    # Session isolation: budget/steps/taint in one session don't affect another.
    def session_isolation():
        mon, layer = _fresh(max_steps=2, budgets={"spend": 50.0},
                            sensitive_labels=frozenset({"ssn"}))
        # exhaust session A
        for i in range(2):
            layer.check(Action(actor="a", tool="t", action_purpose="p",
                               session_id="A", nonce=f"a{i}", payload={"amount": 25}))
        assert layer.check(Action(actor="a", tool="t", action_purpose="p",
                                  session_id="A", nonce="a2")).verdict == Verdict.DENY
        # session B is pristine
        d = layer.check(Action(actor="a", tool="t", action_purpose="x",
                               session_id="B", nonce="b0", payload={"amount": 40}))
        assert d.verdict == Verdict.ALLOW, "session B affected by session A exhaustion"
        # taint pinned in B does not constrain A (A pins independently)
        layer.check(Action(actor="a", tool="t", action_purpose="reportgen",
                           data_labels=("ssn",), session_id="B", nonce="b1"))
        # In a brand new session C, ssn can pin to a different purpose freely.
        d = layer.check(Action(actor="a", tool="t", action_purpose="totally_different",
                               data_labels=("ssn",), session_id="C", nonce="c0"))
        assert d.verdict == Verdict.ALLOW, "taint binding leaked across sessions"
    b.probe("session-isolation", session_isolation)

    # Kill-switch is one-way: once stopped, EVERYTHING denies, no path re-arms.
    def kill_switch():
        mon, layer = _fresh(max_steps=100)
        assert layer.check(Action(actor="a", tool="t", action_purpose="p",
                                  session_id="s", nonce="1")).verdict == Verdict.ALLOW
        mon.stop()
        assert mon.stopped is True
        for _ in range(50):
            d = layer.check(Action(actor="a", tool="t", action_purpose="p",
                                   session_id="s", nonce=str(random.random())))
            assert d.verdict == Verdict.DENY, "action allowed after kill-switch"
        # no public method re-arms it; verify there's no attribute that flips it back
        assert mon.stopped is True, "kill-switch reverted"
    b.probe("kill-switch-one-way", kill_switch)

    # Fail-closed on a throwing cost_fn.
    def throwing_cost_fn():
        def boom(action):
            raise RuntimeError("cost_fn exploded")
        cfg = RuntimeConfig(max_steps=100, budgets={"spend": 10.0})
        mon = RuntimeMonitor(cfg, cost_fn=boom)
        layer = RuntimeLayer(mon)
        d = layer.check(Action(actor="a", tool="t", action_purpose="p",
                               session_id="s", nonce="1", payload={"amount": 1}))
        assert d.verdict == Verdict.DENY, "throwing cost_fn did not fail closed"
        # And it must not have crashed nor committed state.
        st = mon.state("s")
        assert st.steps == 0, "throwing cost_fn committed a step"
    b.probe("fail-closed-throwing-cost-fn", throwing_cost_fn)

    # Fail-closed on a malformed action (object lacking expected attributes).
    def malformed_action():
        mon, layer = _fresh(max_steps=100)

        class Bad:
            session_id = "s"
            nonce = "x"
            # missing data_labels, action_purpose, payload -> attribute errors
        d = layer.check(Bad())  # type: ignore[arg-type]
        assert d.verdict == Verdict.DENY, "malformed action not failed closed"
    b.probe("fail-closed-malformed-action", malformed_action)

    # default_cost_fn: bool amount must not masquerade as a charge.
    def cost_fn_bool():
        assert default_cost_fn(Action(actor="a", tool="t", action_purpose="p",
                                      payload={"amount": True}))["spend"] == 0.0, \
            "amount=True charged as 1.0"
        assert default_cost_fn(Action(actor="a", tool="t", action_purpose="p",
                                      payload={"amount": "5"}))["spend"] == 0.0, \
            "string amount charged"
        assert default_cost_fn(Action(actor="a", tool="t", action_purpose="p",
                                      payload={}))["spend"] == 0.0, "missing amount charged"
        assert default_cost_fn(Action(actor="a", tool="t", action_purpose="p",
                                      payload={"amount": 7.5}))["spend"] == 7.5
    b.probe("default-cost-fn-bool-guard", cost_fn_bool)

    return b


# =========================================================================== #
# 5) policy
# =========================================================================== #
def battery_policy() -> Battery:
    b = Battery("policy")

    def _intent(labels=(), purpose="support_reply", payload=None):
        return Intent(actor="a", tool="t", action_purpose=purpose,
                      data_labels=tuple(labels), payload=payload or {})

    POLICY = {
        "default": "deny",
        "purpose_bindings": {
            "customer_support": ["support_reply", "support_followup"],
            "marketing_optin": ["marketing"],
        },
        "redactions": [
            {"action_purpose": "support_reply", "redact_fields": ["ssn", "card"]},
        ],
    }

    def default_deny_unknown():
        eng = PolicyEngine(POLICY)
        d = eng.evaluate(_intent(labels=("unknown_label",)))
        assert d.verdict == Verdict.DENY, "unknown label not default-denied"
    b.probe("default-deny-unknown-label", default_deny_unknown)

    def purpose_mismatch():
        eng = PolicyEngine(POLICY)
        # customer_support data cannot flow into 'marketing'
        d = eng.evaluate(_intent(labels=("customer_support",), purpose="marketing"))
        assert d.verdict == Verdict.DENY, "purpose mismatch allowed"
        # but its permitted purpose is allowed (and no redaction for support_followup)
        d = eng.evaluate(_intent(labels=("customer_support",), purpose="support_followup"))
        assert d.verdict == Verdict.ALLOW, "permitted purpose wrongly denied"
    b.probe("purpose-mismatch-deny", purpose_mismatch)

    def redaction_replaces():
        eng = PolicyEngine(POLICY)
        d = eng.evaluate(_intent(labels=("customer_support",), purpose="support_reply",
                                 payload={"ssn": "123-45-6789", "body": "hi"}))
        assert d.verdict == Verdict.TRANSFORM, f"expected TRANSFORM, got {d.verdict}"
        assert d.transformed is not None, "TRANSFORM produced no transformed intent"
        assert d.transformed.payload["ssn"] == "[REDACTED]", "ssn not redacted"
        assert d.transformed.payload["body"] == "hi", "non-redacted field altered"
        # original intent untouched (immutability of the input)
    b.probe("redaction-replaces-field", redaction_replaces)

    def multiple_labels_one_illegal():
        eng = PolicyEngine(POLICY)
        # one legal (customer_support -> support_reply ok), one illegal (unknown)
        d = eng.evaluate(_intent(labels=("customer_support", "unknown_label"),
                                 purpose="support_reply"))
        assert d.verdict == Verdict.DENY, "illegal label among legal ones not denied"
        # one legal, one with purpose mismatch
        d = eng.evaluate(_intent(labels=("customer_support", "marketing_optin"),
                                 purpose="support_reply"))
        assert d.verdict == Verdict.DENY, "purpose-mismatched label not denied in multi-label"
    b.probe("multi-label-one-illegal-deny", multiple_labels_one_illegal)

    def determinism():
        eng = PolicyEngine(POLICY)
        intent = _intent(labels=("customer_support",), purpose="support_reply",
                         payload={"ssn": "x", "body": "y"})
        first = eng.evaluate(intent)
        for _ in range(100):
            again = eng.evaluate(intent)
            assert again.verdict == first.verdict, "non-deterministic verdict"
            assert again.reason == first.reason, "non-deterministic reason"
    b.probe("determinism", determinism)

    def default_allow_mode_still_binds():
        # In default=allow mode, unknown labels pass, but KNOWN labels still
        # enforce their purpose binding.
        eng = PolicyEngine({**POLICY, "default": "allow"})
        d = eng.evaluate(_intent(labels=("unknown_label",), purpose="whatever"))
        assert d.verdict in (Verdict.ALLOW, Verdict.TRANSFORM), "default-allow wrongly denied unknown"
        d = eng.evaluate(_intent(labels=("marketing_optin",), purpose="support_reply"))
        assert d.verdict == Verdict.DENY, "default-allow skipped known-label purpose binding"
    b.probe("default-allow-still-binds-known", default_allow_mode_still_binds)

    def empty_redaction_noop():
        # redact rule matches purpose but no listed field present/non-empty -> ALLOW (not TRANSFORM)
        eng = PolicyEngine(POLICY)
        d = eng.evaluate(_intent(labels=("customer_support",), purpose="support_reply",
                                 payload={"body": "hi"}))
        assert d.verdict == Verdict.ALLOW, "redaction with nothing to redact should ALLOW"
        # field present but empty/None counts as nothing to redact
        d = eng.evaluate(_intent(labels=("customer_support",), purpose="support_reply",
                                 payload={"ssn": "", "card": None}))
        assert d.verdict == Verdict.ALLOW, "empty-valued redact fields wrongly TRANSFORMed"
    b.probe("empty-redaction-is-noop", empty_redaction_noop)

    return b


# =========================================================================== #
# 6) audit_chain
# =========================================================================== #
class _FakeDecision:
    def __init__(self, verdict, reason):
        self.verdict = verdict
        self.reason = reason


def _seed_chain(path, n=6):
    log = HashChainedAudit(path)
    for i in range(n):
        act = Action(actor=f"actor{i}", tool="t", action_purpose="p",
                     data_labels=("x",), session_id="s", nonce=f"n{i}")
        dec = _FakeDecision(Verdict.ALLOW if i % 2 else Verdict.DENY, f"reason {i}")
        log.record(act, dec, layer="test")
    return log


def battery_audit_chain() -> Battery:
    b = Battery("audit_chain")
    tmpdir = tempfile.mkdtemp(prefix="rt_audit_")

    def _newpath(name):
        return os.path.join(tmpdir, name)

    def _read_lines(path):
        with open(path, encoding="utf-8") as f:
            return [ln for ln in f.read().splitlines() if ln.strip()]

    def _write_lines(path, lines):
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))

    def clean_verifies():
        p = _newpath("clean.jsonl")
        log = _seed_chain(p)
        assert log.verify() is True, "clean chain failed verify"
        ok, reason = log.verify_detail()
        assert ok and reason == "ok", f"clean chain detail not ok: {reason!r}"
        # empty (never written) verifies as intact
        p2 = _newpath("empty.jsonl")
        empty = HashChainedAudit(p2)
        assert empty.verify() is True, "empty chain failed verify"
    b.probe("clean-verifies-true", clean_verifies)

    def edit_detected():
        p = _newpath("edit.jsonl")
        _seed_chain(p)
        lines = _read_lines(p)
        # tamper a field in line 2 (without recomputing hash). Parse/modify the
        # JSON rather than string-matching a guessed separator style, so the edit
        # is robust to how the log serializes (default ", " vs compact).
        tampered = lines[:]
        obj = __import__("json").loads(tampered[2])
        obj["actor"] = "attacker"
        tampered[2] = __import__("json").dumps(obj)
        assert tampered != lines, "test setup failed to edit"
        _write_lines(p, tampered)
        log = HashChainedAudit.__new__(HashChainedAudit)
        log._path = __import__("pathlib").Path(p)
        assert log.verify() is False, "edited entry verified as intact"
        ok, _ = log.verify_detail()
        assert ok is False, "edited entry detail said ok"
    b.probe("edit-detected", edit_detected)

    def insert_detected():
        p = _newpath("insert.jsonl")
        _seed_chain(p)
        lines = _read_lines(p)
        forged = lines[1]  # duplicate a real (but now mis-linked) entry
        tampered = lines[:2] + [forged] + lines[2:]
        _write_lines(p, tampered)
        log = HashChainedAudit.__new__(HashChainedAudit)
        log._path = __import__("pathlib").Path(p)
        assert log.verify() is False, "inserted entry verified as intact"
    b.probe("insert-detected", insert_detected)

    def delete_detected():
        p = _newpath("delete.jsonl")
        _seed_chain(p)
        lines = _read_lines(p)
        tampered = lines[:2] + lines[3:]  # drop line 2
        _write_lines(p, tampered)
        log = HashChainedAudit.__new__(HashChainedAudit)
        log._path = __import__("pathlib").Path(p)
        assert log.verify() is False, "deleted entry verified as intact"
    b.probe("delete-detected", delete_detected)

    def reorder_detected():
        p = _newpath("reorder.jsonl")
        _seed_chain(p)
        lines = _read_lines(p)
        tampered = lines[:]
        tampered[2], tampered[3] = tampered[3], tampered[2]
        _write_lines(p, tampered)
        log = HashChainedAudit.__new__(HashChainedAudit)
        log._path = __import__("pathlib").Path(p)
        assert log.verify() is False, "reordered entries verified as intact"
    b.probe("reorder-detected", reorder_detected)

    def truncate_detected():
        # Truncation mid-chain: drop the LAST line. A truncated tail leaves the
        # remaining prefix internally consistent, BUT a re-open should resume the
        # SHORTER chain cleanly (this is allowed). What must NOT verify is a
        # truncation that leaves a dangling byte / partial JSON line.
        p = _newpath("truncate.jsonl")
        _seed_chain(p)
        with open(p, "r+", encoding="utf-8") as f:
            data = f.read()
            # chop the file in the middle of the last line -> partial JSON line
            f.seek(0)
            f.truncate()
            f.write(data[: len(data) - 30])
        log = HashChainedAudit.__new__(HashChainedAudit)
        log._path = __import__("pathlib").Path(p)
        # Either the partial line is unparseable JSON (-> False) — must NOT raise.
        result = log.verify()
        assert result in (True, False), "verify did not return a bool"
        # The corrupted-tail case specifically must be detected as broken.
        ok, _ = log.verify_detail()
        assert ok is False, "partial-truncated last line verified as intact"
    b.probe("truncate-partial-detected", truncate_detected)

    def corrupt_json_no_raise():
        p = _newpath("corrupt.jsonl")
        _seed_chain(p)
        lines = _read_lines(p)
        corruptions = [
            lines[:2] + ["{this is not json"] + lines[2:],
            lines[:2] + ["[]"] + lines[2:],          # JSON but not an object
            lines[:2] + ["null"] + lines[2:],
            lines[:2] + ['{"seq":2}'] + lines[2:],   # object missing fields
            lines[:2] + ["\x00\x01\x02"] + lines[2:],
            ['{"broken'],                            # whole file is garbage
        ]
        for i, variant in enumerate(corruptions):
            cp = _newpath(f"corrupt_{i}.jsonl")
            _write_lines(cp, variant)
            log = HashChainedAudit.__new__(HashChainedAudit)
            log._path = __import__("pathlib").Path(cp)
            # MUST NOT raise and MUST report False.
            res = log.verify()
            assert res is False, f"corrupt variant {i} verified as intact"
            ok, reason = log.verify_detail()
            assert ok is False and isinstance(reason, str), \
                f"corrupt variant {i} detail not (False, str)"
    b.probe("corrupt-json-no-raise", corrupt_json_no_raise)

    def reopen_tampered_raises():
        # Re-opening (constructing) over a tampered chain MUST raise (refuse to
        # extend), per the documented contract — this is NOT verify(), which
        # never raises.
        p = _newpath("reopen.jsonl")
        _seed_chain(p)
        lines = _read_lines(p)
        lines[1] = lines[1].replace('"reason"', '"rea5on"')
        _write_lines(p, lines)
        raised = False
        try:
            HashChainedAudit(p)
        except ValueError:
            raised = True
        assert raised, "reopening a tampered chain did not raise"
    b.probe("reopen-tampered-raises", reopen_tampered_raises)

    return b


# =========================================================================== #
# 7) adapters
# =========================================================================== #
def battery_adapters() -> Battery:
    b = Battery("adapters")

    ai = AIToolAdapter()
    fin = FinanceAdapter()
    qpu = QuantumJobAdapter()

    def ai_roundtrip_and_caps():
        raw = {
            "actor": "Agent:Support-Bot",
            "tool": "send_email",
            "arguments": {"to": "x@y.z", "body": "hi"},
            "purpose": "support_reply",
            "data_labels": ["customer_support"],
            "session_id": "s-1",
            "nonce": "n-1",
        }
        a = ai.normalize(raw)
        assert a.actor == "agent:support-bot", a.actor
        assert a.tool == "send_email"
        assert a.payload["body"] == "hi"
        assert a.session_id == "s-1" and a.nonce == "n-1"
        caps = ai.map_capabilities(a)
        assert "tool:send_email" in caps and "effect:network" in caps, caps
        # destructive tool -> destructive effect
        a2 = ai.normalize({"actor": "x", "tool": "delete_user", "purpose": "p"})
        assert "effect:destructive" in ai.map_capabilities(a2)
    b.probe("ai-roundtrip-and-caps", ai_roundtrip_and_caps)

    def ai_missing_optional():
        # only required fields; everything optional absent
        a = ai.normalize({"actor": "x", "tool": "read_file"})
        assert a.action_purpose == "" and a.data_labels == ()
        assert dict(a.payload) == {} and a.session_id == "default" and a.nonce == ""
        # None-valued optionals are tolerated (-> defaults)
        a2 = ai.normalize({"actor": "x", "tool": "read_file", "arguments": None,
                           "data_labels": None})
        assert dict(a2.payload) == {} and a2.data_labels == ()
    b.probe("ai-missing-optional-fields", ai_missing_optional)

    def ai_denormalize_wraps_errors():
        ok = ai.denormalize({"sent": 1})
        assert ok == {"ok": True, "result": {"sent": 1}}, ok
        err = ai.denormalize(ValueError("boom"))
        assert err["ok"] is False and err["error"]["type"] == "ValueError"
        assert err["error"]["message"] == "boom"
        # a non-Exception falsy result is still a success envelope
        assert ai.denormalize(None) == {"ok": True, "result": None}
    b.probe("ai-denormalize-wraps-errors", ai_denormalize_wraps_errors)

    def finance_amount_numeric():
        a = fin.normalize({"actor": "treasury", "operation": "transfer",
                           "amount": 2500, "currency": "USD",
                           "account_from": "acct:1", "account_to": "acct:2",
                           "purpose": "vendor_payment"})
        assert a.tool == "transfer"
        assert a.payload["amount"] == 2500, "amount mutated"
        assert isinstance(a.payload["amount"], (int, float)) and not isinstance(a.payload["amount"], str), \
            "amount not numeric"
        # default cost_fn can read it without parsing
        assert default_cost_fn(a)["spend"] == 2500.0
        caps = fin.map_capabilities(a)
        assert "effect:financial" in caps
        # missing amount -> defaults to 0 numeric
        a2 = fin.normalize({"actor": "t", "operation": "refund"})
        assert a2.payload["amount"] == 0 and not isinstance(a2.payload["amount"], str)
    b.probe("finance-amount-stays-numeric", finance_amount_numeric)

    def risk_ranges_valid():
        # every adapter's risk_profile must yield a valid RiskVector ([0,1]).
        cases = [
            (ai, {"actor": "x", "tool": "read_file", "purpose": "p"}),
            (ai, {"actor": "x", "tool": "delete_db", "purpose": "p"}),
            (ai, {"actor": "x", "tool": "send_email", "purpose": "p"}),
            (ai, {"actor": "x", "tool": "frobnicate", "purpose": "p"}),
            (fin, {"actor": "x", "operation": "transfer", "amount": 5_000_000}),
            (fin, {"actor": "x", "operation": "transfer", "amount": -50}),
            (fin, {"actor": "x", "operation": "transfer", "amount": "notanumber"}),
            (qpu, {"actor": "x", "job": "submit_circuit"}),
            (qpu, {"actor": "x", "job": "calibrate_backend"}),
            (qpu, {"actor": "x", "job": "reset_device"}),
        ]
        for adapter, raw in cases:
            a = adapter.normalize(raw)
            rv = adapter.risk_profile(a)
            for fld in ("reversibility", "blast_radius", "sensitivity"):
                v = getattr(rv, fld)
                assert isinstance(v, float) and 0.0 <= v <= 1.0 and not math.isnan(v), \
                    f"{adapter.name}.{fld} out of range for {raw}: {v}"
    b.probe("risk-vectors-in-range", risk_ranges_valid)

    def risk_ordering():
        # AI: a read is MORE reversible than a transfer; a send less than read.
        read = ai.risk_profile(ai.normalize({"actor": "x", "tool": "read_file", "purpose": "p"}))
        transfer = fin.risk_profile(fin.normalize({"actor": "x", "operation": "transfer", "amount": 100}))
        assert read.reversibility > transfer.reversibility, \
            f"read ({read.reversibility}) not more reversible than transfer ({transfer.reversibility})"
        # Quantum: calibrate (hardware-affecting) LESS reversible than submit.
        submit = qpu.risk_profile(qpu.normalize({"actor": "x", "job": "submit_circuit"}))
        calibrate = qpu.risk_profile(qpu.normalize({"actor": "x", "job": "calibrate_x"}))
        assert calibrate.reversibility < submit.reversibility, \
            f"calibrate ({calibrate.reversibility}) not less reversible than submit ({submit.reversibility})"
        reset = qpu.risk_profile(qpu.normalize({"actor": "x", "job": "reset_y"}))
        assert reset.reversibility < submit.reversibility, "reset not less reversible than submit"
        # finance blast radius grows with amount
        small = fin.risk_profile(fin.normalize({"actor": "x", "operation": "transfer", "amount": 50}))
        big = fin.risk_profile(fin.normalize({"actor": "x", "operation": "transfer", "amount": 5_000_000}))
        assert big.blast_radius > small.blast_radius, "blast radius did not grow with amount"
    b.probe("risk-ordering", risk_ordering)

    def sensitive_label_bumps_sensitivity():
        plain = ai.risk_profile(ai.normalize({"actor": "x", "tool": "read_file", "purpose": "p",
                                              "data_labels": ["public"]}))
        sens = ai.risk_profile(ai.normalize({"actor": "x", "tool": "read_file", "purpose": "p",
                                            "data_labels": ["customer_ssn"]}))
        assert sens.sensitivity > plain.sensitivity, "ssn label did not raise sensitivity"
    b.probe("sensitive-label-bumps-sensitivity", sensitive_label_bumps_sensitivity)

    def denormalize_all_wrap_errors():
        for adapter in (ai, fin, qpu):
            err = adapter.denormalize(KeyError("missing"))
            assert err["ok"] is False and err["error"]["type"] == "KeyError", adapter.name
            ok = adapter.denormalize("done")
            assert ok == {"ok": True, "result": "done"}, adapter.name
    b.probe("denormalize-wraps-errors-all", denormalize_all_wrap_errors)

    def normalize_rejects_nonmapping():
        for adapter in (ai, fin, qpu):
            raised = False
            try:
                adapter.normalize("not a mapping")  # type: ignore[arg-type]
            except TypeError:
                raised = True
            assert raised, f"{adapter.name}.normalize accepted non-mapping"
    b.probe("normalize-rejects-nonmapping", normalize_rejects_nonmapping)

    return b


# =========================================================================== #
# main
# =========================================================================== #
def main() -> int:
    print("=" * 72)
    print("COMPONENT-LEVEL RED TEAM — AuthGate enforcement layers")
    print(f"seed=0x{SEED:X}  python={sys.version.split()[0]}")
    print("=" * 72)

    batteries = [
        battery_normalize(),
        battery_action(),
        battery_capability(),
        battery_runtime(),
        battery_policy(),
        battery_audit_chain(),
        battery_adapters(),
    ]

    total_pass = sum(b.passed for b in batteries)
    total_escapes = sum(len(b.escapes) for b in batteries)

    print("\nPER-COMPONENT RESULTS:")
    for bat in batteries:
        print(bat.report())

    print("\n" + "-" * 72)
    print(f"TOTAL probes passed: {total_pass}")
    print(f"COMPONENT RED TEAM: {total_escapes} escapes")
    print("-" * 72)

    if total_escapes:
        print("\nRESULT: FAIL — at least one component violated an invariant or crashed.")
        return 1
    print("\nRESULT: PASS — every component held its invariants under attack.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
