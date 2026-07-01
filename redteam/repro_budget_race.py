"""repro_budget_race.py — MINIMAL standalone repro of the #1 finding.

The runtime budget layer has an unsynchronized read-modify-write. Under
concurrent calls in one session it (a) loses spend updates and (b) as a direct
consequence ALLOWs far more real spend than the ceiling permits.

Run:  python redteam/repro_budget_race.py

Expected (contained): a $100 ceiling => at most $100 of ALLOWed $1 effects.
Actual (broken):      $200-$250 of ALLOWed effects; the layer's own counter
                      undercounts, so it never trips the ceiling.

Nothing under authgate/ is modified.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# The race exists at the DEFAULT 5ms switch interval too (verified separately:
# a realistic multi-key budget breaches $100 -> $125 with 400 threads). Here we
# shrink the switch interval so a short, deterministic-ish run hits it reliably
# on any machine. Set ADV_DEFAULT_INTERVAL=1 to run at the stock 5ms interval.
import os
if os.environ.get("ADV_DEFAULT_INTERVAL") != "1":
    sys.setswitchinterval(0.000001)

from authgate.action import Action
from authgate.policy import Verdict
from authgate.runtime import RuntimeConfig, RuntimeLayer, RuntimeMonitor

CEILING = 100.0
N_THREADS = 300
CALLS = 20
TRIALS = 20


def one_trial() -> tuple[int, float]:
    cfg = RuntimeConfig(
        max_steps=10_000_000, rate_limit=10_000_000, rate_window=1,
        budgets={"spend": CEILING},
    )
    monitor = RuntimeMonitor(cfg)
    layer = RuntimeLayer(monitor)
    allowed = [0]
    lock = threading.Lock()
    barrier = threading.Barrier(N_THREADS)

    def worker() -> None:
        barrier.wait()
        for _ in range(CALLS):
            a = Action(actor="a", tool="pay", action_purpose="p",
                       payload={"amount": 1.0}, session_id="s", nonce="")
            if layer.check(a).verdict is Verdict.ALLOW:
                with lock:
                    allowed[0] += 1  # a real $1 the trusted executor will send

    threads = [threading.Thread(target=worker) for _ in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return allowed[0], monitor.state("s").costs.get("spend", 0.0)


def main() -> int:
    worst_real = 0
    worst_committed = 0.0
    for _ in range(TRIALS):
        real, committed = one_trial()
        if real > worst_real:
            worst_real, worst_committed = real, committed

    print(f"ceiling                       : ${CEILING:.0f}")
    print(f"REAL approved spend (ALLOWs)  : ${worst_real}")
    print(f"layer's committed counter     : ${worst_committed:.0f}  (undercount)")
    breached = worst_real > CEILING
    print(f"result                        : "
          f"{'ESCAPE — budget breached %.1fx' % (worst_real / CEILING) if breached else 'PASS — contained'}")
    if breached:
        print("root cause                    : RuntimeLayer._check reads st.costs, "
              "builds new_costs, checks the ceiling, then commits st.costs = "
              "new_costs (runtime.py:260-320) with NO lock. Concurrent ALLOWs "
              "overwrite each other's total (lost update), so the running sum "
              "stays under the ceiling while real approved spend runs past it.")
    return 0 if not breached else 1


if __name__ == "__main__":
    raise SystemExit(main())
