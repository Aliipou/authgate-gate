# Security Policy

AuthGate is a security-enforcement component: a deterministic, fail-closed gate
that decides whether an autonomous agent's tool call may run. Treat any defect
that lets a call **execute when it should have been denied** — or that makes a
layer **crash instead of denying** — as a security issue.

## Threat model (what this defends)

- **Unauthorized execution** — an actor invoking a capability it was never granted.
- **Purpose violation** — data collected for one purpose flowing into another.
- **Temporal / drift attacks** — runaway loops, rate bursts, cumulative-budget
  exhaustion, cross-step purpose-laundering, and effect replay within a session.
- **Identifier smuggling** — case / Unicode (NFKC) / zero-width tricks intended to
  split one logical token into two and slip past a layer.
- **Audit tampering** — retroactive edit / insert / delete / reorder of decision
  records (detected via the hash chain).

## Out of scope (stated honestly — see `CRITICAL_RESEARCH.md`)

AuthGate is **decision-gating, not execution confinement**: it does not sandbox or
sandbox-escape-proof the executor (use seccomp / WASM / a real sandbox below it).
The audit chain is **tamper-evident in-process**, not tamper-proof against an
attacker who owns the process — anchor `entry_hash` externally (WORM store /
notary) for that. It does not solve ground-truth of `data_labels`, semantic
intent-hijacking, or multi-agent coordination attacks.

## Reporting a vulnerability

Please report privately rather than opening a public issue. Open a
[GitHub security advisory](https://github.com/Aliipou/authgate-gate/security/advisories/new)
or contact the maintainer. Include a minimal reproduction (an `Action` or sequence,
the expected decision, and the actual one). We aim to acknowledge within a few days.

## Verifying your build

```bash
pip install -e ".[dev]"
pytest -q                              # unit suite
python redteam/red_team_components.py  # per-component adversarial battery
python redteam/red_team.py             # whole-system adversarial battery
```

Any red-team escape is a hard failure; all three must pass.
