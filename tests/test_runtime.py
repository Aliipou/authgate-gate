"""Deterministic checks for the runtime/drift layer.

No framework needed: `python tests/test_runtime.py`.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from authgate import Action, Verdict
from authgate.runtime import RuntimeConfig, RuntimeLayer, RuntimeMonitor


def _layer(cfg: RuntimeConfig) -> RuntimeLayer:
    return RuntimeLayer(RuntimeMonitor(cfg))


def _act(session: str = "s1", nonce: str = "", purpose: str = "task",
         labels: tuple[str, ...] = (), amount: float | None = None) -> Action:
    payload = {} if amount is None else {"amount": amount}
    return Action(
        actor="agent:bot",
        tool="do_thing",
        action_purpose=purpose,
        data_labels=labels,
        payload=payload,
        session_id=session,
        nonce=nonce,
    )


# --------------------------------------------------------------------------- #
def test_runaway_loop_denied_past_max_steps() -> None:
    layer = _layer(RuntimeConfig(max_steps=3, rate_limit=999, rate_window=999))
    for i in range(3):
        d = layer.check(_act(nonce=f"n{i}"))
        assert d.verdict is Verdict.ALLOW, (i, d)
    d = layer.check(_act(nonce="n3"))
    assert d.verdict is Verdict.DENY, d
    assert "step budget" in d.reason


def test_rate_limit_trips() -> None:
    # At most 2 actions per window of 3 steps. Steps 1,2 allowed; step 3 would
    # make 3 actions inside the window [1,2,3] -> over the limit -> DENY.
    layer = _layer(RuntimeConfig(max_steps=999, rate_limit=2, rate_window=3))
    assert layer.check(_act(nonce="a")).verdict is Verdict.ALLOW   # step 1
    assert layer.check(_act(nonce="b")).verdict is Verdict.ALLOW   # step 2
    d = layer.check(_act(nonce="c"))                               # step 3 -> 3 in [1,2,3]
    assert d.verdict is Verdict.DENY, d
    assert "rate limit" in d.reason
    # Commit-on-allow: the denied burst attempt did not consume the window slot,
    # so retrying it is still denied (state is unchanged, deterministically).
    assert layer.check(_act(nonce="c2")).verdict is Verdict.DENY


def test_rate_window_slides_and_recovers() -> None:
    # limit 2 / window 2: the window holds exactly 2 ordinals, so a steady
    # cadence at full speed is *always* legal — proving the window slides and
    # capacity is recovered as old ordinals fall out the left.
    layer = _layer(RuntimeConfig(max_steps=999, rate_limit=2, rate_window=2))
    for i in range(20):
        d = layer.check(_act(nonce=f"r{i}"))
        assert d.verdict is Verdict.ALLOW, (i, d)
    # And a tighter cadence (limit 1 / window 1) likewise never blocks: each new
    # step's window contains only itself.
    layer2 = _layer(RuntimeConfig(max_steps=999, rate_limit=1, rate_window=1))
    for i in range(10):
        assert layer2.check(_act(nonce=f"t{i}")).verdict is Verdict.ALLOW, i


def test_budget_cumulative_denial_does_not_charge() -> None:
    layer = _layer(RuntimeConfig(max_steps=999, rate_limit=999, rate_window=999,
                                 budgets={"spend": 100.0}))
    assert layer.check(_act(nonce="a", amount=60.0)).verdict is Verdict.ALLOW
    assert layer.check(_act(nonce="b", amount=30.0)).verdict is Verdict.ALLOW  # total 90
    d = layer.check(_act(nonce="c", amount=20.0))                              # 110 > 100
    assert d.verdict is Verdict.DENY, d
    assert "budget" in d.reason
    # The over-budget action must NOT have been charged: a small spend still fits.
    assert layer.check(_act(nonce="d", amount=10.0)).verdict is Verdict.ALLOW  # 90+10=100 ok


def test_replay_nonce_denied_distinct_allowed() -> None:
    layer = _layer(RuntimeConfig(max_steps=999, rate_limit=999, rate_window=999))
    assert layer.check(_act(nonce="dup")).verdict is Verdict.ALLOW
    assert layer.check(_act(nonce="dup")).verdict is Verdict.DENY
    assert layer.check(_act(nonce="fresh")).verdict is Verdict.ALLOW
    # Empty nonce is allowed through repeatedly (opted out, never recorded).
    assert layer.check(_act(nonce="")).verdict is Verdict.ALLOW
    assert layer.check(_act(nonce="")).verdict is Verdict.ALLOW


def test_cross_step_laundering_denied() -> None:
    cfg = RuntimeConfig(
        max_steps=999, rate_limit=999, rate_window=999,
        sensitive_labels=frozenset({"customer_pii"}),
    )
    layer = _layer(cfg)
    # Step 1: read the sensitive label under "support_reply" -> ALLOW + bind.
    d1 = layer.check(_act(nonce="1", purpose="support_reply", labels=("customer_pii",)))
    assert d1.verdict is Verdict.ALLOW, d1
    # Same purpose again is fine.
    d2 = layer.check(_act(nonce="2", purpose="support_reply", labels=("customer_pii",)))
    assert d2.verdict is Verdict.ALLOW, d2
    # Later step: same label, different purpose -> laundering -> DENY.
    d3 = layer.check(_act(nonce="3", purpose="marketing", labels=("customer_pii",)))
    assert d3.verdict is Verdict.DENY, d3
    assert "taint" in d3.reason


def test_purpose_for_label_pins_from_first_use() -> None:
    cfg = RuntimeConfig(
        max_steps=999, rate_limit=999, rate_window=999,
        sensitive_labels=frozenset({"customer_pii"}),
        purpose_for_label={"customer_pii": "support_reply"},
    )
    layer = _layer(cfg)
    # First use under the WRONG purpose is denied immediately (pinned).
    d = layer.check(_act(nonce="1", purpose="marketing", labels=("customer_pii",)))
    assert d.verdict is Verdict.DENY, d
    # The pinned purpose is allowed.
    d2 = layer.check(_act(nonce="2", purpose="support_reply", labels=("customer_pii",)))
    assert d2.verdict is Verdict.ALLOW, d2


def test_session_isolation() -> None:
    layer = _layer(RuntimeConfig(max_steps=2, rate_limit=999, rate_window=999,
                                 budgets={"spend": 50.0}))
    # Burn session s1 to its step ceiling.
    assert layer.check(_act("s1", nonce="a", amount=50.0)).verdict is Verdict.ALLOW
    assert layer.check(_act("s1", nonce="b")).verdict is Verdict.ALLOW
    assert layer.check(_act("s1", nonce="c")).verdict is Verdict.DENY  # over steps
    # s2 is untouched: independent steps AND independent budget.
    assert layer.check(_act("s2", nonce="d", amount=50.0)).verdict is Verdict.ALLOW
    assert layer.check(_act("s2", nonce="e")).verdict is Verdict.ALLOW


def test_kill_switch_denies_everything() -> None:
    monitor = RuntimeMonitor(RuntimeConfig(max_steps=999, rate_limit=999, rate_window=999))
    layer = RuntimeLayer(monitor)
    assert layer.check(_act(nonce="a")).verdict is Verdict.ALLOW
    monitor.stop()
    for sess in ("s1", "s2", "other"):
        d = layer.check(_act(sess, nonce="x"))
        assert d.verdict is Verdict.DENY, d
        assert "kill-switch" in d.reason


def test_determinism_identical_state() -> None:
    cfg = RuntimeConfig(max_steps=999, rate_limit=999, rate_window=999)
    a = _layer(cfg).check(_act(nonce="z", amount=5.0))
    b = _layer(cfg).check(_act(nonce="z", amount=5.0))
    assert a.verdict == b.verdict
    assert a.reason == b.reason


def test_fail_closed_on_malformed_action() -> None:
    # A monitor whose cost_fn blows up must make the layer DENY, not crash/allow.
    def boom(_action: Action) -> dict[str, float]:
        raise RuntimeError("cost model exploded")

    monitor = RuntimeMonitor(
        RuntimeConfig(max_steps=999, rate_limit=999, rate_window=999, budgets={"spend": 1.0}),
        cost_fn=boom,
    )
    layer = RuntimeLayer(monitor)
    d = layer.check(_act(nonce="a", amount=1.0))
    assert d.verdict is Verdict.DENY, d
    assert "failing closed" in d.reason


def test_denied_action_does_not_consume_step() -> None:
    # A replay denial must not advance the step counter (commit-on-allow).
    layer = _layer(RuntimeConfig(max_steps=2, rate_limit=999, rate_window=999))
    assert layer.check(_act(nonce="a")).verdict is Verdict.ALLOW   # step 1
    # Replay 'a' several times — all denied, none should consume the budget.
    for _ in range(5):
        assert layer.check(_act(nonce="a")).verdict is Verdict.DENY
    # Still room for one more real step (only step 1 was committed).
    assert layer.check(_act(nonce="b")).verdict is Verdict.ALLOW   # step 2
    assert layer.check(_act(nonce="c")).verdict is Verdict.DENY    # step 3 > max


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
