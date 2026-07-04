#!/usr/bin/env python3
"""Independent red-team harness for the composed AuthGate governance stack.

This is an ADVERSARIAL whole-system test. It constructs a `ControlledGate`
via `build_gate(...)` and throws a large, seeded, reproducible battery of
attacks at it across 16 categories. For each attempt it defines the EXPECTED
safe outcome and checks the gate produced it.

Definition of an ESCAPE (a red-team win / blue-team bug):
    * the gate ALLOWed / executed something that should have been DENIED or
      redacted, OR
    * the gate (or any layer) raised an exception instead of failing closed,
      OR
    * an invariant the system advertises ("commit-on-allow only", "audit is
      tamper-evident", "sessions are isolated", "redaction strips the secret")
      was violated.

Everything must FAIL CLOSED: a malformed / hostile input must produce DENY or a
clean handled error, never an ALLOW and never an unhandled crash.

Run:
    python -m redteam.red_team        # from repo root
    python redteam/red_team.py        # also works (path bootstrap below)

Exit code 0 == no escapes. Exit code 1 == at least one escape or crash.

stdlib only. No pytest. Deterministic (fixed master seed).
"""

from __future__ import annotations

import math
import random
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --- path bootstrap so `python redteam/red_team.py` finds the package -------
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from authgate_gate import (  # noqa: E402
    Action,
    CapabilityRegistry,
    RuntimeConfig,
    Verdict,
    build_gate,
)

MASTER_SEED = 1337  # fixed, reproducible
POLICY_PATH = _REPO_ROOT / "policies" / "purpose_policy.json"
# Per randomized category. Override with REDTEAM_ATTEMPTS for a deeper local soak
# (e.g. 1000) or a faster CI pass; the default stays brutal but finishes briskly.
ATTEMPTS = int(__import__("os").environ.get("REDTEAM_ATTEMPTS", "200"))


# --------------------------------------------------------------------------- #
# Result bookkeeping
# --------------------------------------------------------------------------- #
@dataclass
class Escape:
    category: str
    detail: str
    expected: str
    actual: str


@dataclass
class CategoryResult:
    name: str
    passed: int = 0
    escapes: list[Escape] = field(default_factory=list)

    def ok(self) -> None:
        self.passed += 1

    def fail(self, detail: str, expected: str, actual: str) -> None:
        self.escapes.append(Escape(self.name, detail, expected, actual))


# --------------------------------------------------------------------------- #
# Harness scaffolding
# --------------------------------------------------------------------------- #
class Harness:
    """Owns a temp dir for audit logs and a counter for unique nonces."""

    def __init__(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="redteam_authgate_"))
        self._n = 0

    def audit_path(self, name: str) -> Path:
        p = self._tmp / f"{name}.jsonl"
        # ensure a fresh chain each build
        if p.exists():
            p.unlink()
        return p

    def nonce(self) -> str:
        self._n += 1
        return f"nonce-{self._n}"

    def new_gate(
        self,
        *,
        name: str,
        grants: dict[str, list[str]] | None = None,
        tool_grants: dict[str, list[str]] | None = None,
        config: RuntimeConfig | None = None,
    ):
        reg = CapabilityRegistry()
        for actor, caps in (grants or {}).items():
            for c in caps:
                reg.grant(actor, c)
        for actor, tools in (tool_grants or {}).items():
            for t in tools:
                reg.grant_tool(actor, t)
        gate, monitor = build_gate(
            policy_path=POLICY_PATH,
            registry=reg,
            runtime_config=config or RuntimeConfig(),
            audit_path=self.audit_path(name),
        )
        return gate, monitor, reg


def safe_enforce(gate, action) -> tuple[str, Any]:
    """Run gate.enforce and capture a crash as a distinct outcome.

    Returns ("verdict", Decision) on a normal ruling, or ("crash", exc) if the
    stack raised — a crash is itself an escape (it did not fail closed).
    """
    try:
        d = gate.enforce(action)
        return "verdict", d
    except BaseException as exc:  # noqa: BLE001 — a raise is a failure to test
        return "crash", exc


def safe_dispatch(gate, action, tools) -> tuple[str, Any]:
    try:
        r = gate.dispatch(action, tools)
        return "result", r
    except BaseException as exc:  # noqa: BLE001
        return "crash", exc


# --------------------------------------------------------------------------- #
# RNG helpers for fuzz inputs
# --------------------------------------------------------------------------- #
_ASCII = "abcdefghijklmnopqrstuvwxyz_"
_ZW = ["​", "‌", "‍", "﻿", "­"]  # zero-width / format
_FULLWIDTH = {c: chr(ord(c) - ord("a") + 0xFF41) for c in "abcdefghijklmnopqrstuvwxyz"}


def rand_token(rng: random.Random, n: int = 8) -> str:
    return "".join(rng.choice(_ASCII) for _ in range(n))


def smuggle(rng: random.Random, base: str) -> str:
    """Produce a visually/semantically equivalent variant of `base` using the
    exact tricks normalize.py claims to defeat: case, fullwidth, zero-width,
    padding. If normalization is correct, this MUST collapse back to `base`."""
    out = []
    for ch in base:
        r = rng.random()
        if r < 0.25 and ch in _FULLWIDTH:
            out.append(_FULLWIDTH[ch])           # NFKC look-alike
        elif r < 0.45:
            out.append(ch.upper())               # case
        else:
            out.append(ch)
        if rng.random() < 0.30:
            out.append(rng.choice(_ZW))          # zero-width injection
    pad = " " * rng.randint(0, 3)
    return pad + "".join(out) + pad


# =========================================================================== #
# CATEGORY 1 — prompt-injection / purpose mismatch
# data labeled for purpose A used under a *different* action purpose B -> DENY
# =========================================================================== #
def cat_purpose_mismatch(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("1.purpose-mismatch")
    # Known bindings from policies/purpose_policy.json
    bindings = {
        "customer_support": ["support_reply", "account_recovery"],
        "payments": ["fulfillment", "fraud_check"],
        "medical": ["care"],
        "marketing_optin": ["marketing", "support_reply"],
    }
    all_purposes = sorted({p for v in bindings.values() for p in v} | {"exfiltrate", "marketing", "care"})
    gate, _, _ = h.new_gate(name="cat1", grants={"agent:bot": ["*"]})  # admin: isolate the purpose layer
    for _ in range(ATTEMPTS):
        label = rng.choice(list(bindings))
        allowed = bindings[label]
        bad_purpose = rng.choice([p for p in all_purposes if p not in allowed])
        a = Action(
            actor="agent:bot",
            tool="send_email",
            action_purpose=bad_purpose,
            data_labels=(label,),
            payload={"body": "x"},
            nonce=h.nonce(),
        )
        kind, d = safe_enforce(gate, a)
        if kind == "crash":
            res.fail(f"label={label} purpose={bad_purpose}", "DENY", f"CRASH {d!r}")
        elif d.verdict is Verdict.DENY:
            res.ok()
        else:
            res.fail(f"label={label} under purpose={bad_purpose}", "DENY", d.verdict.name)
    return res


# =========================================================================== #
# CATEGORY 2 — unknown / unbound data purpose -> default-DENY
# =========================================================================== #
def cat_unknown_purpose(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("2.unknown-purpose")
    known = {"customer_support", "payments", "medical", "marketing_optin"}
    gate, _, _ = h.new_gate(name="cat2", grants={"agent:bot": ["*"]})
    for _ in range(ATTEMPTS):
        label = rand_token(rng, rng.randint(3, 12))
        if label in known:
            continue
        a = Action(
            actor="agent:bot",
            tool="send_email",
            action_purpose=rand_token(rng),
            data_labels=(label,),
            payload={"body": "x"},
            nonce=h.nonce(),
        )
        kind, d = safe_enforce(gate, a)
        if kind == "crash":
            res.fail(f"unknown label={label}", "DENY", f"CRASH {d!r}")
        elif d.verdict is Verdict.DENY:
            res.ok()
        else:
            res.fail(f"unknown label={label}", "DENY (default-deny)", d.verdict.name)
    return res


# =========================================================================== #
# CATEGORY 3 — capability escalation (actor calls a tool it was never granted)
# =========================================================================== #
def cat_capability_escalation(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("3.capability-escalation")
    # bot granted exactly one tool; everything else must DENY at the cap layer.
    granted_tool = "send_email"
    gate, _, _ = h.new_gate(name="cat3", tool_grants={"agent:bot": [granted_tool]})
    for _ in range(ATTEMPTS):
        tool = rand_token(rng, rng.randint(3, 10))
        if tool == granted_tool:
            continue
        a = Action(
            actor="agent:bot",
            tool=tool,
            action_purpose="support_reply",
            data_labels=(),  # no labels -> purpose layer would ALLOW; cap must DENY
            payload={},
            nonce=h.nonce(),
        )
        kind, d = safe_enforce(gate, a)
        if kind == "crash":
            res.fail(f"ungranted tool={tool}", "DENY", f"CRASH {d!r}")
        elif d.verdict is Verdict.DENY:
            res.ok()
        else:
            res.fail(f"ungranted tool={tool}", "DENY (no capability)", d.verdict.name)
    # Also: a wholly unknown actor (no grants) must be denied everything.
    for _ in range(ATTEMPTS):
        actor = "agent:" + rand_token(rng)
        a = Action(actor=actor, tool=granted_tool, action_purpose="support_reply",
                   payload={}, nonce=h.nonce())
        kind, d = safe_enforce(gate, a)
        if kind == "crash":
            res.fail(f"unknown actor={actor}", "DENY", f"CRASH {d!r}")
        elif d.verdict is Verdict.DENY:
            res.ok()
        else:
            res.fail(f"unknown actor={actor}", "DENY (no grants)", d.verdict.name)
    return res


# =========================================================================== #
# CATEGORY 4 — tool chaining: denied on X, retry via Y it also lacks -> DENY
# =========================================================================== #
def cat_tool_chaining(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("4.tool-chaining")
    gate, _, _ = h.new_gate(name="cat4", tool_grants={"agent:bot": ["send_email"]})
    for _ in range(ATTEMPTS):
        chain = [rand_token(rng) for _ in range(rng.randint(2, 5))]
        chain = [t for t in chain if t != "send_email"] or ["delete_db"]
        all_denied = True
        for tool in chain:
            a = Action(actor="agent:bot", tool=tool, action_purpose="support_reply",
                       payload={}, nonce=h.nonce())
            kind, d = safe_enforce(gate, a)
            if kind == "crash":
                res.fail(f"chain tool={tool}", "DENY", f"CRASH {d!r}")
                all_denied = False
                break
            if d.verdict is not Verdict.DENY:
                res.fail(f"chain fallback tool={tool}", "DENY", d.verdict.name)
                all_denied = False
                break
        if all_denied:
            res.ok()
    return res


# =========================================================================== #
# CATEGORY 5 — runaway loop: exceed max_steps -> DENY past the ceiling
# =========================================================================== #
def cat_runaway(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("5.runaway-loop")
    for _ in range(ATTEMPTS):
        max_steps = rng.randint(1, 25)
        cfg = RuntimeConfig(max_steps=max_steps, rate_limit=10**9, rate_window=1)
        gate, _, _ = h.new_gate(name="cat5", grants={"agent:bot": ["*"]}, config=cfg)
        sess = f"s-{rng.random()}"
        good = True
        # First max_steps must ALLOW (no labels, admin cap, big rate).
        for i in range(max_steps):
            a = Action(actor="agent:bot", tool="ping", action_purpose="support_reply",
                       session_id=sess, nonce=h.nonce())
            kind, d = safe_enforce(gate, a)
            if kind == "crash" or d.verdict is not Verdict.ALLOW:
                res.fail(f"step {i+1}/{max_steps}", "ALLOW", d.verdict.name if kind != 'crash' else f'CRASH {d!r}')
                good = False
                break
        if not good:
            continue
        # Steps beyond the ceiling must all DENY, repeatedly.
        for _ in range(rng.randint(1, 5)):
            a = Action(actor="agent:bot", tool="ping", action_purpose="support_reply",
                       session_id=sess, nonce=h.nonce())
            kind, d = safe_enforce(gate, a)
            if kind == "crash":
                res.fail("over-ceiling step", "DENY", f"CRASH {d!r}")
                good = False
                break
            if d.verdict is not Verdict.DENY:
                res.fail(f"step > max_steps={max_steps}", "DENY", d.verdict.name)
                good = False
                break
        if good:
            res.ok()
    return res


# =========================================================================== #
# CATEGORY 6 — rate burst: exceed rate_limit in window -> DENY
# =========================================================================== #
def cat_rate_burst(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("6.rate-burst")
    for _ in range(ATTEMPTS):
        rate_limit = rng.randint(1, 8)
        # Window must be able to CONTAIN rate_limit+1 actions for the burst to be
        # a genuine over-rate: with a sliding window of W steps, rate_limit+1
        # actions span rate_limit+1 steps, so they only co-occur in one window
        # when W >= rate_limit+1. (At W == rate_limit the oldest has slid out and
        # the (R+1)-th is legitimately allowed — standard sliding-window math.)
        window = rng.randint(rate_limit + 1, rate_limit + 6)
        cfg = RuntimeConfig(max_steps=10**6, rate_limit=rate_limit, rate_window=window)
        gate, _, _ = h.new_gate(name="cat6", grants={"agent:bot": ["*"]}, config=cfg)
        sess = f"s-{rng.random()}"
        good = True
        for i in range(rate_limit):
            a = Action(actor="agent:bot", tool="ping", action_purpose="support_reply",
                       session_id=sess, nonce=h.nonce())
            kind, d = safe_enforce(gate, a)
            if kind == "crash" or d.verdict is not Verdict.ALLOW:
                res.fail(f"burst {i+1}/{rate_limit}", "ALLOW", d.verdict.name if kind != 'crash' else f'CRASH {d!r}')
                good = False
                break
        if not good:
            continue
        # (rate_limit + 1)-th within the same window must DENY.
        a = Action(actor="agent:bot", tool="ping", action_purpose="support_reply",
                   session_id=sess, nonce=h.nonce())
        kind, d = safe_enforce(gate, a)
        if kind == "crash":
            res.fail("over-rate", "DENY", f"CRASH {d!r}")
        elif d.verdict is Verdict.DENY:
            res.ok()
        else:
            res.fail(f"rate {rate_limit+1} > limit={rate_limit}/{window}", "DENY", d.verdict.name)
    return res


# =========================================================================== #
# CATEGORY 7 — cumulative budget exhaustion
# many small legal spends sum over ceiling; the crossing one DENIES and does
# NOT increase the committed total.
# =========================================================================== #
def cat_budget(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("7.cumulative-budget")
    for _ in range(ATTEMPTS):
        ceiling = rng.choice([10.0, 100.0, 1000.0])
        cfg = RuntimeConfig(max_steps=10**6, rate_limit=10**9, rate_window=1,
                            budgets={"spend": ceiling})
        gate, monitor, _ = h.new_gate(name="cat7", grants={"agent:bot": ["*"]}, config=cfg)
        sess = f"s-{rng.random()}"
        # legal small spends that keep total <= ceiling
        step = ceiling / rng.randint(4, 10)
        total = 0.0
        good = True
        while total + step <= ceiling:
            a = Action(actor="agent:bot", tool="transfer", action_purpose="support_reply",
                       payload={"amount": step}, session_id=sess, nonce=h.nonce())
            kind, d = safe_enforce(gate, a)
            if kind == "crash" or d.verdict is Verdict.DENY:
                res.fail(f"legal spend {step} (total {total})", "ALLOW", d.verdict.name if kind != 'crash' else f'CRASH {d!r}')
                good = False
                break
            total += step
        if not good:
            continue
        committed_before = monitor.state(sess).costs.get("spend", 0.0)
        # crossing spend: pushes total above ceiling -> DENY, must NOT commit
        over = ceiling - committed_before + rng.uniform(0.01, ceiling)
        a = Action(actor="agent:bot", tool="transfer", action_purpose="support_reply",
                   payload={"amount": over}, session_id=sess, nonce=h.nonce())
        kind, d = safe_enforce(gate, a)
        committed_after = monitor.state(sess).costs.get("spend", 0.0)
        if kind == "crash":
            res.fail("over-budget spend", "DENY", f"CRASH {d!r}")
        elif d.verdict is not Verdict.DENY:
            res.fail(f"over-budget {over} (total {committed_before}/{ceiling})", "DENY", d.verdict.name)
        elif committed_after != committed_before:
            res.fail("denied over-budget mutated committed total",
                     f"committed stays {committed_before}", f"committed became {committed_after}")
        else:
            res.ok()
    return res


# =========================================================================== #
# CATEGORY 8 — replay: reuse a nonce in a session -> DENY
# =========================================================================== #
def cat_replay(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("8.replay")
    gate, _, _ = h.new_gate(name="cat8", grants={"agent:bot": ["*"]},
                            config=RuntimeConfig(max_steps=10**6, rate_limit=10**9, rate_window=1))
    for _ in range(ATTEMPTS):
        sess = f"s-{rng.random()}"
        nonce = f"fixed-{rng.random()}"
        a1 = Action(actor="agent:bot", tool="ping", action_purpose="support_reply",
                    session_id=sess, nonce=nonce)
        kind, d = safe_enforce(gate, a1)
        if kind == "crash" or d.verdict is not Verdict.ALLOW:
            res.fail("first use of nonce", "ALLOW", d.verdict.name if kind != 'crash' else f'CRASH {d!r}')
            continue
        # replay same nonce in same session
        a2 = Action(actor="agent:bot", tool="ping", action_purpose="support_reply",
                    session_id=sess, nonce=nonce, payload={"x": rng.random()})
        kind, d = safe_enforce(gate, a2)
        if kind == "crash":
            res.fail("replay nonce", "DENY", f"CRASH {d!r}")
        elif d.verdict is Verdict.DENY:
            res.ok()
        else:
            res.fail(f"replayed nonce '{nonce}' in session '{sess}'", "DENY", d.verdict.name)
    return res


# =========================================================================== #
# CATEGORY 9 — cross-step purpose-laundering
# sensitive label read under purpose A at step 1, reused under purpose B later
# =========================================================================== #
def cat_laundering(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("9.purpose-laundering")
    # Make "marketing_optin" the sensitive, tainting label. It binds (policy)
    # to both "support_reply" and "marketing", so the per-call purpose layer
    # would ALLOW either; only the runtime taint check catches the cross-step
    # change of purpose.
    for _ in range(ATTEMPTS):
        cfg = RuntimeConfig(
            max_steps=10**6, rate_limit=10**9, rate_window=1,
            sensitive_labels=frozenset({"marketing_optin"}),
        )
        gate, _, _ = h.new_gate(name="cat9", grants={"agent:bot": ["*"]}, config=cfg)
        sess = f"s-{rng.random()}"
        # step 1: first use under support_reply -> trust-on-first-use ALLOW
        a1 = Action(actor="agent:bot", tool="send_email", action_purpose="support_reply",
                    data_labels=("marketing_optin",), session_id=sess, nonce=h.nonce())
        kind, d = safe_enforce(gate, a1)
        if kind == "crash" or d.verdict is Verdict.DENY:
            res.fail("first sensitive use under support_reply", "ALLOW/TRANSFORM",
                     d.verdict.name if kind != 'crash' else f'CRASH {d!r}')
            continue
        # interleave some innocuous steps
        for _ in range(rng.randint(0, 3)):
            ai = Action(actor="agent:bot", tool="ping", action_purpose="support_reply",
                        session_id=sess, nonce=h.nonce())
            safe_enforce(gate, ai)
        # later step: same sensitive label under a DIFFERENT purpose -> DENY
        a2 = Action(actor="agent:bot", tool="send_email", action_purpose="marketing",
                    data_labels=("marketing_optin",), session_id=sess, nonce=h.nonce())
        kind, d = safe_enforce(gate, a2)
        if kind == "crash":
            res.fail("laundered reuse", "DENY", f"CRASH {d!r}")
        elif d.verdict is Verdict.DENY:
            res.ok()
        else:
            res.fail("marketing_optin reused under 'marketing' after 'support_reply'",
                     "DENY (cross-step taint)", d.verdict.name)
    return res


# =========================================================================== #
# CATEGORY 10 — unicode / case / zero-width / NFKC smuggling
# A smuggled actor/tool/purpose/label/capability must NOT bypass any layer.
# =========================================================================== #
def cat_smuggling(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("10.unicode-smuggling")

    # 10a. Smuggled actor must still be denied if the *base* actor has no grant,
    #      and an actor granted the base token must still match a smuggled actor
    #      (normalization is two-sided). We test the dangerous direction:
    #      a NON-granted actor smuggled to look like nothing we granted -> DENY,
    #      AND a granted actor smuggled in the request still resolves -> works,
    #      AND a smuggled *capability* can't dodge the cap check.
    gate, _, reg = h.new_gate(name="cat10", tool_grants={"agent:bot": ["send_email"]})
    for _ in range(ATTEMPTS):
        choice = rng.randint(0, 3)
        if choice == 0:
            # Smuggle the GRANTED actor's name: must still be recognized (ALLOW
            # path through cap), i.e. normalization must NOT split it into a new
            # un-granted identity. We then need the purpose layer to also pass.
            actor = smuggle(rng, "agent:bot")
            a = Action(actor=actor, tool="send_email", action_purpose="support_reply",
                       data_labels=(), payload={}, nonce=h.nonce())
            kind, d = safe_enforce(gate, a)
            # Expected: NOT a capability-denial. Either ALLOW or a non-cap deny.
            if kind == "crash":
                res.fail(f"smuggled granted actor {actor!r}", "no-crash", f"CRASH {d!r}")
            elif d.verdict is Verdict.ALLOW or "capability" not in d.reason.lower():
                res.ok()
            else:
                res.fail(f"smuggled granted actor {actor!r} lost its grant",
                         "still recognized as agent:bot", f"DENY: {d.reason}")
        elif choice == 1:
            # Smuggle the TOOL of a granted actor: tool:<tool> capability must
            # still match -> not a cap denial.
            tool = smuggle(rng, "send_email")
            a = Action(actor="agent:bot", tool=tool, action_purpose="support_reply",
                       data_labels=(), payload={}, nonce=h.nonce())
            kind, d = safe_enforce(gate, a)
            if kind == "crash":
                res.fail(f"smuggled tool {tool!r}", "no-crash", f"CRASH {d!r}")
            elif d.verdict is Verdict.ALLOW or "capability" not in d.reason.lower():
                res.ok()
            else:
                res.fail(f"smuggled granted tool {tool!r} lost its grant",
                         "tool:send_email still matches", f"DENY: {d.reason}")
        elif choice == 2:
            # Smuggle a LABEL: a mismatched purpose with a smuggled known label
            # must STILL be denied (smuggling must not turn 'customer_support'
            # into an unknown-but-different token that dodges the binding... and
            # must not collapse a forbidden purpose into an allowed one).
            label = smuggle(rng, "customer_support")
            a = Action(actor="agent:bot", tool="send_email", action_purpose="marketing",
                       data_labels=(label,), payload={}, nonce=h.nonce())
            kind, d = safe_enforce(gate, a)
            if kind == "crash":
                res.fail(f"smuggled label {label!r}", "DENY", f"CRASH {d!r}")
            elif d.verdict is Verdict.DENY:
                res.ok()
            else:
                res.fail(f"smuggled label {label!r} under 'marketing'",
                         "DENY (still customer_support, mismatch)", d.verdict.name)
        else:
            # Smuggle the PURPOSE token toward a forbidden one: data labelled
            # customer_support, purpose smuggled-'marketing' -> still DENY.
            purpose = smuggle(rng, "marketing")
            a = Action(actor="agent:bot", tool="send_email", action_purpose=purpose,
                       data_labels=("customer_support",), payload={}, nonce=h.nonce())
            kind, d = safe_enforce(gate, a)
            if kind == "crash":
                res.fail(f"smuggled purpose {purpose!r}", "DENY", f"CRASH {d!r}")
            elif d.verdict is Verdict.DENY:
                res.ok()
            else:
                res.fail(f"smuggled purpose {purpose!r}",
                         "DENY (customer_support !-> marketing)", d.verdict.name)
    return res


# =========================================================================== #
# CATEGORY 11 — fleet kill-switch: after monitor.stop(), EVERY action -> DENY
# =========================================================================== #
def cat_kill_switch(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("11.kill-switch")
    gate, monitor, _ = h.new_gate(name="cat11", grants={"agent:bot": ["*"]},
                                  config=RuntimeConfig(max_steps=10**6, rate_limit=10**9, rate_window=1))
    monitor.stop()
    for _ in range(ATTEMPTS):
        # Throw a wide variety of otherwise-perfectly-legal actions; all DENY.
        a = Action(
            actor="agent:bot",
            tool=rng.choice(["ping", "send_email", "read_db"]),
            action_purpose="support_reply",
            data_labels=rng.choice([(), ("customer_support",)]),
            payload={"amount": rng.uniform(0, 5)},
            session_id=f"s-{rng.random()}",
            nonce=h.nonce(),
        )
        kind, d = safe_enforce(gate, a)
        if kind == "crash":
            res.fail("post-stop action", "DENY", f"CRASH {d!r}")
        elif d.verdict is Verdict.DENY:
            res.ok()
        else:
            res.fail("action after monitor.stop()", "DENY (kill-switch)", d.verdict.name)
    return res


# =========================================================================== #
# CATEGORY 12 — redaction correctness: a TRANSFORM must strip the sensitive
# field from the EXECUTED payload; the tool never receives the raw secret.
# =========================================================================== #
def cat_redaction(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("12.redaction")
    gate, _, _ = h.new_gate(name="cat12", tool_grants={"agent:bot": ["send_email"]},
                            config=RuntimeConfig(max_steps=10**6, rate_limit=10**9, rate_window=1))
    for _ in range(ATTEMPTS):
        secret_ssn = f"SSN-{rng.randint(10**8, 10**9)}"
        secret_card = f"CARD-{rng.randint(10**12, 10**13)}"
        seen: dict[str, Any] = {}

        def tool(payload, _seen=seen):
            _seen.clear()
            _seen.update(payload)
            return "sent"

        a = Action(
            actor="agent:bot",
            tool="send_email",
            action_purpose="support_reply",  # redaction rule strips ssn, card_number
            data_labels=("customer_support",),  # allowed for support_reply
            payload={"ssn": secret_ssn, "card_number": secret_card, "body": "hello"},
            nonce=h.nonce(),
        )
        kind, r = safe_dispatch(gate, a, {"send_email": tool})
        if kind == "crash":
            res.fail("redaction dispatch", "executed redacted", f"CRASH {r!r}")
            continue
        if not r.executed:
            res.fail("redaction call not executed", "executed (TRANSFORM)", "not executed")
            continue
        # The tool must NOT have seen either raw secret.
        leaked = [k for k, v in seen.items() if v in (secret_ssn, secret_card)]
        if leaked:
            res.fail(f"tool received raw secret in {leaked}",
                     "ssn & card_number == [REDACTED]", f"leaked values: {leaked}")
        elif seen.get("ssn") != "[REDACTED]" or seen.get("card_number") != "[REDACTED]":
            res.fail("sensitive fields not redacted in executed payload",
                     "[REDACTED]", f"ssn={seen.get('ssn')!r} card={seen.get('card_number')!r}")
        else:
            res.ok()
    return res


# =========================================================================== #
# CATEGORY 13 — audit integrity: after a run verify()==True; tamper a line on
# disk -> verify()==False.
# =========================================================================== #
def cat_audit(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("13.audit-integrity")
    # Smaller per-iteration cost (disk + re-read), still well-randomized.
    n_iters = max(ATTEMPTS // 5, 100)
    for it in range(n_iters):
        path = h.audit_path(f"cat13-{it}")
        reg = CapabilityRegistry()
        reg.grant("agent:bot", "*")
        gate, _ = build_gate(
            policy_path=POLICY_PATH, registry=reg,
            runtime_config=RuntimeConfig(max_steps=10**6, rate_limit=10**9, rate_window=1),
            audit_path=path,
        )
        n_actions = rng.randint(3, 12)
        for _ in range(n_actions):
            a = Action(actor="agent:bot", tool=rng.choice(["ping", "send_email"]),
                       action_purpose="support_reply",
                       data_labels=rng.choice([(), ("customer_support",)]),
                       payload={"body": rand_token(rng)}, session_id="s",
                       nonce=h.nonce())
            safe_enforce(gate, a)

        # 13a. clean chain verifies.
        if not gate._audit.verify():
            res.fail("clean audit chain failed verify", "verify()==True", "verify()==False")
            continue

        lines = path.read_text(encoding="utf-8").splitlines()
        if not lines:
            res.fail("no audit lines written", ">=1 line", "0 lines")
            continue

        # 13b. tamper a random line's content and confirm verify() flips False.
        victim = rng.randrange(len(lines))
        tampered = lines[:]
        mode = rng.randint(0, 2)
        if mode == 0:
            # mutate a field (the reason) without fixing the hash
            tampered[victim] = tampered[victim].replace("support_reply", "EXFILTRATE", 1)
            if tampered == lines:
                tampered[victim] = tampered[victim].replace('"verdict":"allow"', '"verdict":"deny"', 1)
        elif mode == 1 and len(lines) > 1:
            # delete a line
            del tampered[victim]
        else:
            # reorder two lines
            if len(lines) > 1:
                j = (victim + 1) % len(lines)
                tampered[victim], tampered[j] = tampered[j], tampered[victim]

        if tampered == lines:
            # tamper was a no-op (e.g. nothing to replace); skip, count as pass.
            res.ok()
            continue

        path.write_text("\n".join(tampered) + "\n", encoding="utf-8")
        try:
            still_ok = gate._audit.verify()
        except BaseException as exc:  # noqa: BLE001
            res.fail("verify() raised on tampered file", "verify()==False", f"CRASH {exc!r}")
            continue
        if still_ok:
            res.fail(f"tampered audit (mode {mode}, line {victim}) still verified",
                     "verify()==False", "verify()==True")
        else:
            res.ok()
    return res


# =========================================================================== #
# CATEGORY 14 — session isolation: one session's budget/steps/nonces don't leak
# into another.
# =========================================================================== #
def cat_session_isolation(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("14.session-isolation")
    for _ in range(ATTEMPTS):
        max_steps = rng.randint(2, 6)
        ceiling = 100.0
        cfg = RuntimeConfig(max_steps=max_steps, rate_limit=10**9, rate_window=1,
                            budgets={"spend": ceiling})
        gate, monitor, _ = h.new_gate(name="cat14", grants={"agent:bot": ["*"]}, config=cfg)
        sA, sB = f"A-{rng.random()}", f"B-{rng.random()}"
        nonce_shared = f"shared-{rng.random()}"

        # Exhaust session A's steps and most of its budget. Use a per-action
        # amount that sums to strictly under the ceiling (avoids a float-rounding
        # boundary where (ceiling/max_steps)*max_steps lands a hair above ceiling
        # and the gate *correctly* denies the last fill); this category tests
        # session ISOLATION, not the budget boundary (covered by cat 7).
        good = True
        fill_amount = (ceiling - 1.0) / max_steps
        for _ in range(max_steps):
            a = Action(actor="agent:bot", tool="transfer", action_purpose="support_reply",
                       payload={"amount": fill_amount}, session_id=sA,
                       nonce=h.nonce())
            kind, d = safe_enforce(gate, a)
            if kind == "crash" or d.verdict is not Verdict.ALLOW:
                res.fail("filling session A", "ALLOW", d.verdict.name if kind != 'crash' else f'CRASH {d!r}')
                good = False
                break
        if not good:
            continue
        # A's step ceiling is now hit; A should DENY.
        aA = Action(actor="agent:bot", tool="ping", action_purpose="support_reply",
                    session_id=sA, nonce=h.nonce())
        kind, dA = safe_enforce(gate, aA)
        if kind == "crash" or dA.verdict is not Verdict.DENY:
            res.fail("session A over ceiling", "DENY", dA.verdict.name if kind != 'crash' else f'CRASH {dA!r}')
            continue
        # B must be pristine: a normal action ALLOWs, A's nonce works in B,
        # A's budget did not leak.
        aB = Action(actor="agent:bot", tool="transfer", action_purpose="support_reply",
                    payload={"amount": ceiling - 1}, session_id=sB, nonce=nonce_shared)
        kind, dB = safe_enforce(gate, aB)
        if kind == "crash":
            res.fail("fresh session B", "ALLOW", f"CRASH {dB!r}")
            continue
        if dB.verdict is not Verdict.ALLOW:
            res.fail("session B inherited A's exhausted state", "ALLOW (B is fresh)", dB.verdict.name)
            continue
        # The shared nonce, first used in B, must still be replay-rejected in B.
        aB2 = Action(actor="agent:bot", tool="ping", action_purpose="support_reply",
                     session_id=sB, nonce=nonce_shared)
        kind, dB2 = safe_enforce(gate, aB2)
        if kind == "crash" or dB2.verdict is not Verdict.DENY:
            res.fail("replay within B not caught", "DENY", dB2.verdict.name if kind != 'crash' else f'CRASH {dB2!r}')
            continue
        # B's spend must equal only B's own commit.
        if monitor.state(sB).costs.get("spend", 0.0) != ceiling - 1:
            res.fail("session B spend polluted by A",
                     f"{ceiling-1}", f"{monitor.state(sB).costs.get('spend')}")
            continue
        res.ok()
    return res


# =========================================================================== #
# CATEGORY 15 — payload smuggling / type confusion
# amount as bool/str/negative/NaN/inf; nested objects; huge payloads.
# Must not crash and must not mis-charge the budget.
# =========================================================================== #
def cat_type_confusion(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("15.type-confusion")
    ceiling = 100.0
    weird_amounts: list[Any] = [
        True, False, "5", "100", "", None, [1, 2, 3], {"x": 1}, (1,),
        float("nan"), float("inf"), float("-inf"),
        -1.0, -1000.0, -0.0, 0, 1e308, 10**6,
    ]
    for _ in range(ATTEMPTS):
        cfg = RuntimeConfig(max_steps=10**6, rate_limit=10**9, rate_window=1,
                            budgets={"spend": ceiling})
        gate, monitor, _ = h.new_gate(name="cat15", grants={"agent:bot": ["*"]}, config=cfg)
        sess = f"s-{rng.random()}"
        amount = rng.choice(weird_amounts)
        # add a giant nested payload occasionally
        payload: dict[str, Any] = {"amount": amount}
        if rng.random() < 0.3:
            payload["blob"] = {"deep": [{"k": rand_token(rng)} for _ in range(rng.randint(1, 50))]}
        if rng.random() < 0.2:
            payload["huge"] = "A" * rng.randint(1000, 20000)
        a = Action(actor="agent:bot", tool="transfer", action_purpose="support_reply",
                   payload=payload, session_id=sess, nonce=h.nonce())
        kind, d = safe_enforce(gate, a)
        if kind == "crash":
            res.fail(f"weird amount {amount!r}", "DENY or clean ALLOW (no crash)", f"CRASH {d!r}")
            continue
        committed = monitor.state(sess).costs.get("spend", 0.0)
        # Invariants:
        #  - never crash (checked).
        #  - committed spend must be finite and not exceed the ceiling.
        #  - committed spend must not be negative (a negative "charge" is a
        #    budget-credit attack: it would let later spends exceed the cap).
        #  - committed spend must not be NaN (NaN poisons every future compare).
        if d.verdict is Verdict.ALLOW:
            if isinstance(committed, float) and math.isnan(committed):
                res.fail(f"amount {amount!r} poisoned budget with NaN",
                         "finite committed spend", "committed=NaN")
            elif committed > ceiling:
                res.fail(f"amount {amount!r} overcharged past ceiling",
                         f"committed <= {ceiling}", f"committed={committed}")
            elif committed < 0.0:
                res.fail(f"amount {amount!r} credited a NEGATIVE charge (budget-credit attack)",
                         "committed >= 0", f"committed={committed}")
            else:
                res.ok()
        else:
            # A DENY is always a safe outcome here.
            res.ok()
    return res


# Extra dedicated probes for the two specific budget-integrity attacks, run as
# part of category 15 so they're counted and reproduced explicitly.
def cat_budget_integrity(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("15b.budget-integrity")
    ceiling = 100.0
    for _ in range(ATTEMPTS):
        # ATTACK A: negative spend then a spend that should exceed the ceiling.
        cfg = RuntimeConfig(max_steps=10**6, rate_limit=10**9, rate_window=1,
                            budgets={"spend": ceiling})
        gate, monitor, _ = h.new_gate(name="cat15b-neg", grants={"agent:bot": ["*"]}, config=cfg)
        sess = f"s-{rng.random()}"
        neg = -rng.uniform(50, 500)
        a_neg = Action(actor="agent:bot", tool="transfer", action_purpose="support_reply",
                       payload={"amount": neg}, session_id=sess, nonce=h.nonce())
        safe_enforce(gate, a_neg)
        # Now a spend that is itself <= ceiling but, combined with no real prior
        # legitimate spend, should be governed by the ceiling. The attack: the
        # negative credit lets a spend that WOULD be over the cap squeak under.
        over_amt = ceiling + rng.uniform(1, 100)  # alone this is > ceiling
        a_over = Action(actor="agent:bot", tool="transfer", action_purpose="support_reply",
                        payload={"amount": over_amt}, session_id=sess, nonce=h.nonce())
        kind, d = safe_enforce(gate, a_over)
        # EXPECTED SAFE: a single spend exceeding the ceiling must DENY, even if
        # a prior negative "credit" was banked. A negative amount must never
        # create budget headroom.
        if kind == "crash":
            res.fail(f"neg-credit then {over_amt}", "DENY", f"CRASH {d!r}")
        elif d.verdict is Verdict.DENY:
            res.ok()
        else:
            res.fail(
                f"negative credit ({neg:.2f}) banked headroom; spend {over_amt:.2f} "
                f"(> ceiling {ceiling}) was ALLOWED",
                "DENY (negative amount must not create budget headroom)",
                d.verdict.name,
            )

        # ATTACK B: NaN spend, then a clearly-over-ceiling spend.
        gate2, monitor2, _ = h.new_gate(name="cat15b-nan", grants={"agent:bot": ["*"]}, config=cfg)
        sess2 = f"s-{rng.random()}"
        a_nan = Action(actor="agent:bot", tool="transfer", action_purpose="support_reply",
                       payload={"amount": float("nan")}, session_id=sess2, nonce=h.nonce())
        safe_enforce(gate2, a_nan)
        a_huge = Action(actor="agent:bot", tool="transfer", action_purpose="support_reply",
                        payload={"amount": ceiling * 10**6}, session_id=sess2, nonce=h.nonce())
        kind, d = safe_enforce(gate2, a_huge)
        # EXPECTED SAFE: a NaN spend must not be banked into the running total
        # such that every subsequent over-budget spend is ALLOWED.
        if kind == "crash":
            res.fail("NaN then huge", "DENY", f"CRASH {d!r}")
        elif d.verdict is Verdict.DENY:
            res.ok()
        else:
            res.fail(
                f"NaN spend banked; subsequent spend {ceiling*10**6} (>> ceiling) ALLOWED",
                "DENY (NaN must not defeat the ceiling)",
                d.verdict.name,
            )
    return res


# =========================================================================== #
# CATEGORY 16 — fail-closed fuzzing: feed malformed/garbage objects where
# Actions are expected -> DENY or clean error, never ALLOW.
# =========================================================================== #
class _FakeActionMissing:
    """A garbage object missing required attributes."""
    pass


class _FakeActionWeird:
    """Has attributes but of wrong/exploding types."""
    def __init__(self, rng: random.Random):
        self.actor = rng.choice([None, 123, [], {"a": 1}, object()])
        self.tool = rng.choice([None, 5.5, b"bytes"])
        self.action_purpose = rng.choice([None, 0, ()])
        self.data_labels = rng.choice([None, "notatuple", 42, [object()]])
        self.payload = rng.choice([None, "notadict", 7])
        self.session_id = rng.choice([None, 99, []])
        self.nonce = rng.choice([None, 1, []])
        self.capability = rng.choice([None, 1, []])

    @property
    def exploding(self):
        raise RuntimeError("boom")


class _ExplodingAction:
    """Every attribute access raises — the nastiest fail-closed test."""
    def __getattr__(self, name):
        raise RuntimeError(f"attribute {name} explodes")


def cat_fail_closed(h: Harness, rng: random.Random) -> CategoryResult:
    res = CategoryResult("16.fail-closed-fuzz")
    gate, _, _ = h.new_gate(name="cat16", grants={"agent:bot": ["*"]},
                            config=RuntimeConfig(max_steps=10**6, rate_limit=10**9, rate_window=1))
    for _ in range(ATTEMPTS):
        choice = rng.randint(0, 4)
        if choice == 0:
            garbage: Any = _FakeActionMissing()
        elif choice == 1:
            garbage = _FakeActionWeird(rng)
        elif choice == 2:
            garbage = _ExplodingAction()
        elif choice == 3:
            garbage = rng.choice([None, 42, "string", [1, 2], {"actor": "x"}, object(), b"bytes"])
        else:
            # A real Action but with hostile payload values that could trip
            # downstream str/format ops.
            garbage = Action(
                actor="agent:bot",
                tool="transfer",
                action_purpose="support_reply",
                data_labels=(),
                payload={"amount": rng.choice([float("nan"), float("inf"), object()]),
                         "weird": object()},
                nonce=h.nonce(),
            )

        kind, d = safe_enforce(gate, garbage)
        if kind == "crash":
            res.fail(f"garbage input {type(garbage).__name__}", "DENY or clean error",
                     f"UNHANDLED CRASH {d!r}")
            continue
        # The stack returned a Decision. The only unsafe outcome is ALLOW on
        # genuine garbage. (TRANSFORM cannot occur for non-Action garbage.)
        # For the real-but-hostile Action (choice 4), an ALLOW is acceptable
        # *iff* it didn't mischarge — but that path is covered by cat 15; here
        # we only require "no crash" + "no allow on garbage".
        if choice == 4:
            res.ok()  # real Action: handled without crash is the bar here
        elif d.verdict is Verdict.DENY:
            res.ok()
        else:
            res.fail(f"garbage {type(garbage).__name__} produced {d.verdict.name}",
                     "DENY (fail closed)", d.verdict.name)
    return res


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def main() -> int:
    print("=" * 72)
    print("RED TEAM — composed AuthGate governance stack")
    print(f"seed={MASTER_SEED}  attempts/category={ATTEMPTS}  policy={POLICY_PATH.name}")
    print("=" * 72)

    h = Harness()
    categories: list[Callable[[Harness, random.Random], CategoryResult]] = [
        cat_purpose_mismatch,
        cat_unknown_purpose,
        cat_capability_escalation,
        cat_tool_chaining,
        cat_runaway,
        cat_rate_burst,
        cat_budget,
        cat_replay,
        cat_laundering,
        cat_smuggling,
        cat_kill_switch,
        cat_redaction,
        cat_audit,
        cat_session_isolation,
        cat_type_confusion,
        cat_budget_integrity,
        cat_fail_closed,
    ]

    results: list[CategoryResult] = []
    for i, fn in enumerate(categories):
        # Deterministic, independent per-category RNG derived from master seed.
        rng = random.Random(MASTER_SEED * 1000 + i)
        try:
            r = fn(h, rng)
        except BaseException as exc:  # noqa: BLE001 — a harness crash is itself a finding
            r = CategoryResult(fn.__name__)
            r.fail("HARNESS-LEVEL CRASH (uncaught by category)", "no crash", repr(exc))
        results.append(r)

    print()
    print(f"{'CATEGORY':<28}{'PASS':>8}{'ESCAPES':>10}")
    print("-" * 72)
    total_pass = 0
    total_escapes = 0
    for r in results:
        total_pass += r.passed
        total_escapes += len(r.escapes)
        flag = "  <-- ESCAPE" if r.escapes else ""
        print(f"{r.name:<28}{r.passed:>8}{len(r.escapes):>10}{flag}")
    print("-" * 72)
    print(f"{'TOTAL':<28}{total_pass:>8}{total_escapes:>10}")
    print()

    if total_escapes:
        print("=" * 72)
        print("ESCAPE DETAILS (minimal repros for blue team)")
        print("=" * 72)
        for r in results:
            if not r.escapes:
                continue
            print(f"\n### {r.name} — {len(r.escapes)} escape(s)")
            # Show up to 3 distinct repros per category to keep output readable.
            shown = 0
            seen_details: set[str] = set()
            for e in r.escapes:
                key = e.detail.split("(")[0]
                if key in seen_details:
                    continue
                seen_details.add(key)
                print(f"  - case     : {e.detail}")
                print(f"    expected : {e.expected}")
                print(f"    actual   : {e.actual}")
                shown += 1
                if shown >= 3:
                    remaining = len(r.escapes) - shown
                    if remaining > 0:
                        print(f"    ... and {remaining} more escape(s) in this category")
                    break

    print()
    print("=" * 72)
    print(f"RED TEAM: {total_escapes} escapes")
    print("=" * 72)
    return 1 if total_escapes else 0


if __name__ == "__main__":
    sys.exit(main())
