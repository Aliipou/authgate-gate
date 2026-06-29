"""Autonomy gate (layer: fdk). Building on authgate is ALLOWED (fdk -> authgate).

This import crosses a layer boundary but is *not* forbidden, so the checker
must stay silent about it — proving it distinguishes allowed from forbidden.
"""

import authgate.core  # allowed: fdk is built on top of authgate


def decide(intent) -> str:
    return authgate.core.check(intent)
