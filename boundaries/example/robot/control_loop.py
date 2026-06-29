"""Robotics control loop (layer: robotics).

This file deliberately violates the policy to demonstrate the checker:
a safety-critical control path must never reach into quantum research.
"""

import quantum.qkd  # <-- FORBIDDEN: no quantum on a real-time safety path


def step():
    return quantum.qkd.sample()
