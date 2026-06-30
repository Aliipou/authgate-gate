"""Runtime Control / Drift layer (Layer #3) — temporal governance over a session.

The capability layer and the purpose policy are *per-call*: each one rules on a
single `Action` in isolation. That is structurally blind to anything that only
becomes visible across a *trajectory* of calls in one session:

  * drift / runaway     — a single call looks fine, but the agent is looping or
                          has blown past a sane number of steps for the task.
  * rate / burst        — each call is permitted, but their *density* (N calls in
                          a short window of steps) is itself the attack/runaway.
  * cumulative budget   — every individual spend is small and legal, yet their
                          *sum* crosses a ceiling the principal never approved.
  * purpose-laundering  — sensitive data is read under a benign purpose at step 1
                          ("support_reply"), then re-used under a different
                          purpose at step 9 ("marketing"). No single call sees
                          both purposes; only a stateful monitor catches it.
  * replay              — the same `nonce` is presented twice in a session; a
                          per-call gate has no memory, so it can't reject a
                          replayed (or duplicated) effect.
  * fleet-stop          — an operator must be able to halt *every* session at
                          once (a global kill-switch) when something is wrong.

This layer keeps PER-SESSION state keyed by `Action.session_id` and enforces
those temporal/global invariants. It returns the same `Decision(Verdict.ALLOW |
Verdict.DENY, reason)` contract every other layer speaks.

Two safety-critical properties hold by construction:

  1. **Commit-on-allow only.** State (steps, budgets, nonces, taint) is mutated
     *only* on the ALLOW path. A DENIED action consumes nothing. This means an
     attacker cannot burn another session's (or even this session's) budget /
     step count / rate window by deliberately tripping a denial.
  2. **Fail closed.** Any internal/unexpected error while checking becomes DENY,
     never ALLOW. A monitor that cannot reason about safety must not permit.

stdlib only.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from .action import Action
from .policy import Decision, Verdict


# --------------------------------------------------------------------------- #
# Cost extraction
# --------------------------------------------------------------------------- #
def default_cost_fn(action: Action) -> dict[str, float]:
    """Default cost model: read a numeric ``payload["amount"]`` into key "spend".

    Domains plug their own `cost_fn` for richer models (tokens, kWh, API units).
    The default is deliberately conservative: a missing or non-numeric amount
    contributes 0.0 to "spend" (it cannot *reduce* a budget), and booleans —
    which are ``int`` subclasses in Python — are explicitly excluded so a stray
    ``amount=True`` cannot masquerade as a 1.0 charge.
    """
    amount = action.payload.get("amount")
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        return {"spend": 0.0}
    return {"spend": float(amount)}


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RuntimeConfig:
    """Static, declarative limits the runtime layer enforces per session.

    max_steps:
        Maximum number of ALLOWED actions a single session may take. The action
        whose committed step count would *exceed* this (> max_steps) is DENIED.
        This is the runaway / drift ceiling: a task that should take 5 steps but
        is on step 5000 is, by definition, no longer doing the task.

    rate_limit / rate_window:
        At most `rate_limit` allowed actions within any window of `rate_window`
        steps. The window is measured in *step ordinals*, NOT wall-clock time, so
        runs are perfectly reproducible (no flaky time-based tests). Catches
        bursts that each-call gates wave through.

    budgets:
        Named cumulative ceilings, e.g. {"spend": 1000.0, "tokens": 1_000_000}.
        The action whose cost would push the running total of a named budget
        ABOVE its ceiling is DENIED — and (commit-on-allow) does not add to the
        total. Defends against death-by-a-thousand-legal-cuts.

    sensitive_labels:
        Data labels that are "tainting": once such a label is seen in a session,
        it must not later flow into a *different* `action_purpose` than the one
        it was first used under. This is the cross-step purpose-laundering
        defense (the per-call purpose policy cannot see the earlier step).

    purpose_for_label:
        Optional pinning. If a sensitive label maps to a purpose here, that label
        may ONLY ever be used under that exact purpose, from its very first use.
        Labels absent from this map are pinned dynamically to whatever purpose
        they are first seen under (trust-on-first-use).
    """

    max_steps: int = 100
    rate_limit: int = 10
    rate_window: int = 10
    budgets: dict[str, float] = field(default_factory=dict)
    sensitive_labels: frozenset[str] = frozenset()
    purpose_for_label: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Per-session mutable state
# --------------------------------------------------------------------------- #
@dataclass
class _SessionState:
    """All temporal state for one ``session_id``. Mutated only on ALLOW."""

    steps: int = 0
    # Ordinals (1-based step numbers) of recent allowed actions, for the rate
    # window. A deque so old ordinals fall out the left as the window slides.
    recent_steps: deque[int] = field(default_factory=deque)
    costs: dict[str, float] = field(default_factory=dict)
    nonces_seen: set[str] = field(default_factory=set)
    # sensitive label -> the action_purpose it is bound to.
    label_purpose: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Monitor (state owner + global kill-switch)
# --------------------------------------------------------------------------- #
class RuntimeMonitor:
    """Owns per-session state and the global fleet kill-switch.

    The monitor is the single source of truth for "what has this session done so
    far". `RuntimeLayer` reads/commits through it. Splitting the monitor (state)
    from the layer (decision logic) keeps the decision function easy to reason
    about and lets an operator hold a handle to `stop()` the whole fleet.
    """

    def __init__(
        self,
        config: RuntimeConfig,
        cost_fn: Callable[[Action], dict[str, float]] | None = None,
    ) -> None:
        self._config = config
        self._cost_fn = cost_fn or default_cost_fn
        self._sessions: dict[str, _SessionState] = {}
        self._stopped = False

    # -- global kill-switch ------------------------------------------------- #
    def stop(self) -> None:
        """Trip the fleet-wide kill-switch. After this, EVERY session DENIES.

        This is irreversible by design: a runtime monitor exists to fail safe,
        and 're-arming' a tripped emergency stop should be an explicit operator
        action (construct a fresh monitor), not a method an injected instruction
        could call. Once stopped, no path through `check` can ALLOW.
        """
        self._stopped = True

    @property
    def stopped(self) -> bool:
        return self._stopped

    # -- state access ------------------------------------------------------- #
    def cost_of(self, action: Action) -> dict[str, float]:
        return self._cost_fn(action)

    def state(self, session_id: str) -> _SessionState:
        """Get (creating if needed) the mutable state for a session."""
        st = self._sessions.get(session_id)
        if st is None:
            st = _SessionState()
            self._sessions[session_id] = st
        return st


# --------------------------------------------------------------------------- #
# Layer (pure decision + commit-on-allow)
# --------------------------------------------------------------------------- #
class RuntimeLayer:
    """The temporal enforcement layer. ``.name == "runtime"``.

    `check(action)` returns ALLOW/DENY. It DENIES on ANY of:

        * global kill-switch tripped              (fleet-stop)
        * replayed nonce                          (replay)
        * step budget exceeded (> max_steps)      (runaway / drift)
        * rate exceeded in the window             (burst)
        * a named budget exceeded after this cost (cumulative budget)
        * cross-step taint / purpose-laundering   (laundering)

    Otherwise it ALLOWS and commits the state updates atomically. Anything
    unexpected becomes DENY (fail closed).
    """

    name = "runtime"

    def __init__(self, monitor: RuntimeMonitor, config: RuntimeConfig | None = None) -> None:
        self._monitor = monitor
        # Allow an explicit config, else reuse the monitor's.
        self._config = config or monitor._config

    def check(self, action: Action) -> Decision:
        try:
            return self._check(action)
        except Exception as exc:  # fail closed: any error -> DENY, never ALLOW.
            return Decision(Verdict.DENY, f"runtime: internal error, failing closed ({exc!r})")

    # ------------------------------------------------------------------ #
    def _check(self, action: Action) -> Decision:
        cfg = self._config

        # 0. Fleet-wide kill-switch. Highest priority — nothing runs once stopped.
        if self._monitor.stopped:
            return Decision(Verdict.DENY, "runtime: global kill-switch is engaged")

        st = self._monitor.state(action.session_id)

        # 1. Replay. An empty nonce is allowed through but NOT recorded (a packet
        #    that opted out of replay protection cannot collide with another
        #    empty one). A non-empty nonce already seen in this session is a
        #    replayed/duplicated effect -> DENY.
        nonce = action.nonce
        if nonce and nonce in st.nonces_seen:
            return Decision(
                Verdict.DENY,
                f"runtime: replayed nonce '{nonce}' in session '{action.session_id}'",
            )

        # 2. Step budget (runaway). This action would be step (steps + 1).
        prospective_step = st.steps + 1
        if prospective_step > cfg.max_steps:
            return Decision(
                Verdict.DENY,
                f"runtime: step budget exceeded "
                f"({prospective_step} > max_steps={cfg.max_steps}) "
                f"in session '{action.session_id}'",
            )

        # 3. Rate (burst). Count allowed actions whose ordinal is within the
        #    window ending at this prospective step, then add this one.
        if cfg.rate_window > 0 and cfg.rate_limit >= 0:
            window_start = prospective_step - cfg.rate_window + 1
            in_window = sum(1 for ordn in st.recent_steps if ordn >= window_start)
            if in_window + 1 > cfg.rate_limit:
                return Decision(
                    Verdict.DENY,
                    f"runtime: rate limit exceeded "
                    f"({in_window + 1} > {cfg.rate_limit} actions per "
                    f"{cfg.rate_window} steps) in session '{action.session_id}'",
                )

        # 4. Cumulative budgets. Compute this action's cost and check each named
        #    ceiling AFTER adding it. Over-budget -> DENY (and, by commit-on-allow,
        #    the cost is never added).
        cost = self._monitor.cost_of(action)
        new_costs = dict(st.costs)
        for key, amount in cost.items():
            value = float(amount)
            # Budget integrity. A non-finite cost (NaN/inf) cannot be compared to
            # a ceiling (NaN is unordered: every comparison is False), so for a
            # budgeted key it must fail closed rather than silently slip past.
            # A negative cost must never be able to "bank headroom" that defeats a
            # later over-budget call, so it is clamped to zero — a credit cannot
            # increase an outflow allowance. (Unbudgeted keys can't matter.)
            if not math.isfinite(value):
                if key in cfg.budgets:
                    return Decision(
                        Verdict.DENY,
                        f"runtime: non-finite cost {amount!r} for budget '{key}' "
                        f"in session '{action.session_id}'",
                    )
                value = 0.0
            elif value < 0.0:
                value = 0.0
            new_costs[key] = new_costs.get(key, 0.0) + value
        for key, ceiling in cfg.budgets.items():
            if new_costs.get(key, 0.0) > ceiling:
                return Decision(
                    Verdict.DENY,
                    f"runtime: budget '{key}' exceeded "
                    f"({new_costs.get(key, 0.0)} > {ceiling}) "
                    f"in session '{action.session_id}'",
                )

        # 5. Cross-step taint / purpose-laundering. For each sensitive label in
        #    this action, the purpose it must serve is either (a) pinned in
        #    config, or (b) the purpose it was first seen under in this session.
        #    Using it under any other purpose later is laundering -> DENY.
        new_bindings: dict[str, str] = {}
        for label in action.data_labels:
            if label not in cfg.sensitive_labels:
                continue
            bound = cfg.purpose_for_label.get(label) or st.label_purpose.get(label)
            if bound is None:
                # First sight, no pin: trust-on-first-use; record on commit.
                new_bindings[label] = action.action_purpose
            elif bound != action.action_purpose:
                return Decision(
                    Verdict.DENY,
                    f"runtime: cross-step taint — sensitive label '{label}' is "
                    f"bound to purpose '{bound}' but is now used under "
                    f"'{action.action_purpose}' in session '{action.session_id}'",
                )

        # ---- COMMIT (only reached on ALLOW) ------------------------------- #
        st.steps = prospective_step
        if nonce:
            st.nonces_seen.add(nonce)
        st.recent_steps.append(prospective_step)
        # Trim ordinals that have fallen out of the (now-current) window.
        if cfg.rate_window > 0:
            min_keep = prospective_step - cfg.rate_window + 1
            while st.recent_steps and st.recent_steps[0] < min_keep:
                st.recent_steps.popleft()
        st.costs = new_costs
        st.label_purpose.update(new_bindings)

        return Decision(
            Verdict.ALLOW,
            f"runtime: session '{action.session_id}' step {st.steps} within all limits",
        )
