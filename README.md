# AuthGate — a governance gate for autonomous-agent tool calls

A small, **deterministic, fail-closed** gate that sits between an autonomous agent
and its tools. For every tool call the agent wants to make, the gate runs three
ordered checks — **capability → purpose-binding → runtime/drift** — decides
**ALLOW / DENY / TRANSFORM**, and writes a **tamper-evident** audit record.

> **Can do ≠ May do.** Authorization asks "is this actor allowed to call this
> tool?" Purpose-binding asks the harder question: "may *this data*, collected
> for *that purpose*, be used for *this action*?" The runtime layer asks the one
> a per-call gate can't: "is the session's behavior *over time* still valid?"

> **Legitimacy ⊥ Authority — this repo is the *authority* side.** AuthGate answers
> "does this actor hold the capability?" A separate, upstream *legitimacy* gate
> (the FDK / `freedom-policy` role) answers "should this happen at all?" and may
> only **DENY**. **Invariant:** legitimacy never grants authority; AuthGate never
> overrides a legitimacy denial. The two compose through a JSON seam
> (`fdk_kernel.authgate_bridge`), not shared code — a proposed architecture, not a
> proven paradigm.

**North star: correctness = containment, not truth.** The goal is to fail safe
under a present attacker, not to be philosophically correct. Every layer converts
internal errors to `DENY`; nothing is trusted to be well-formed.

### What this is — and is not

It **is** a stdlib-only Python **policy decision point (PDP)** with two genuine
differentiators over classic authorization engines (OPA/Cedar/OpenFGA):
**data-purpose-binding** and a **per-session temporal monitor**. It **is not** an
operating system, a kernel, or a sandbox — it does not *confine* execution; a
`DENY` is honored by a cooperating caller. Read [`CRITICAL_RESEARCH.md`](CRITICAL_RESEARCH.md)
for the unsparing gap analysis before relying on it.

## Architecture

```
        Agent  (intent generator — never executes)
          │   emits an Action { actor, tool, action_purpose, data_labels,
          │                     payload, session_id, nonce, capability }
          ▼
     ┌─────────────────────── ControlledGate ───────────────────────┐
     │  1. capability  — may this actor request this at all?  (DENY) │
     │  2. purpose     — may this data flow into this action? (DENY / │
     │                   TRANSFORM: redact + continue)               │
     │  3. runtime     — is behavior over the session still valid?   │
     │                   steps · rate · budget · replay · cross-step │
     │                   taint · process-wide kill-switch     (DENY) │
     └───────────────────────────┬──────────────────────────────────┘
            first DENY wins        │ all permit
                                   ▼
        Execution (dumb executor)        Audit (hash-chained, every decision)
```

Hard rules (enforced, not hoped for):
- **No AI inside the gate.** Decisions are deterministic and explainable.
- **No analytics in the critical path.** The audit log only observes.
- **Default deny** at every layer. Unknown actor/capability/purpose → refused.
- **Fail closed.** Any error in any layer becomes `DENY`, never an allow.
- **Layers stay separate** (capability ≠ purpose ≠ runtime); the architecture
  boundary is a CI gate (`boundaries/`).

## Quickstart

```python
from authgate import Action, CapabilityRegistry, RuntimeConfig, build_gate

reg = CapabilityRegistry()
reg.grant_tool("agent:support-bot", "send_email")          # default-deny otherwise

gate, monitor = build_gate(
    policy_path="policies/purpose_policy.json",
    registry=reg,
    runtime_config=RuntimeConfig(budgets={"spend": 100.0},
                                 sensitive_labels=frozenset({"customer_support"})),
    audit_path="audit/decisions.jsonl",
)

action = Action("agent:support-bot", "send_email", "support_reply",
                data_labels=("customer_support",), payload={"body": "hi"},
                session_id="s1", nonce="n1")

result = gate.dispatch(action, tools={"send_email": lambda p: send(p)})
# result.executed / result.decision.verdict in {ALLOW, DENY, TRANSFORM}

monitor.stop()   # process-wide emergency stop: every subsequent call DENIES
```

Run the end-to-end demo:

```bash
python examples/controlled_gate_demo.py   # full stack: every layer + audit verify
python examples/prompt_injection_demo.py  # the legacy single-layer gate
```

## The Action Packet ABI — one logic, many worlds

Every domain speaks the same canonical `Action` (`authgate/action.py`). A
`DomainAdapter` maps a raw domain event to/from it, so the **same** enforcement
logic governs different technologies without changing the core:

| Adapter | Domain | Raw event → Action |
|---|---|---|
| `AIToolAdapter` | cloud AI agents / MCP tool calls | tool + arguments + purpose |
| `FinanceAdapter` | transactions | operation + amount (kept numeric for the budget layer) |
| `QuantumJobAdapter` | **classical** control plane gating quantum jobs (around the QPU, not on it) | job + backend + shots |

Tokens (actor/tool/purpose/label/capability) are **normalized at the boundary**
(`normalize.py`: NFKC + drop control/format chars + casefold), closing
case / Unicode look-alike / zero-width smuggling bypasses.

## Tamper-evident audit

`HashChainedAudit` writes append-only JSONL where each record is hash-chained to
the previous one; `verify()` detects any edit / insert / delete / reorder. This is
**tamper-evident in-process**, not tamper-proof against an attacker who owns the
process — anchor `entry_hash` externally (WORM / notary) for that. See
[`SECURITY.md`](SECURITY.md).

## Testing, red team, CI

```bash
pip install -e ".[dev]"
ruff check authgate ; mypy authgate ; pytest -q   # lint, types, 75 unit tests
python redteam/red_team_components.py              # per-component adversarial battery
python redteam/red_team.py                         # whole-system adversarial battery
python boundaries/check_boundaries.py authgate --policy boundaries/policy.json
```

CI (`.github/workflows/ci.yml`) runs all of the above on every push; **a red-team
escape fails the build.** The red teams generate hundreds of seeded, reproducible
adversarial variants per category (injection, purpose-laundering, capability
escalation, runaway/rate/budget, replay, unicode/zero-width, kill-switch, audit
tampering, fail-closed fuzzing). Override depth with `REDTEAM_ATTEMPTS=1000`.

> Two real vulnerability classes the whole-system red team found and that are now
> fixed + regression-guarded: **budget integrity** (negative/`NaN`/`inf` amounts
> defeating a ceiling) and **fail-closed on non-`Action` input** (crash → DENY).

## Honest limitations (see `CRITICAL_RESEARCH.md`)

- **Ground truth (G2):** the gate decides on the `data_labels`/`action_purpose`
  *attached to the packet*, not verified facts. An attacker who controls labeling
  can mislabel to pass. There is no trusted provenance authority here.
- **Taint is coarse (G3):** cross-step taint pins a *label* to a purpose; it does
  not track sensitive *content* laundered through an LLM that sheds the label.
  Sound information-flow through a model is an open research problem (cf. CaMeL).
- **Decision-gating, not confinement (G4):** a `DENY` is advice to a cooperating
  caller. There is no seccomp/WASM/OS isolation; irreversible effects (money,
  motion) are gone the instant a trusted executor runs them.
- **In-process trust (G5) / single process (G6):** audit chain, capability
  registry, and runtime state live in memory; "fleet kill-switch" and budgets are
  **per-process**. A multi-host control plane needs shared, consistent state.
- **"Formally verified" is NOT claimed for this repo** — the Lean/Kani/TLA work
  lives in a separate kernel and is not wired into this Python.

## Intentionally excluded from v1

Economic modeling, governance/philosophy layers, blockchain, FDK/ML inside the
runtime decision, model-based decisions in the gate. Each is how this project
would die early; they come later, behind a hard interface, or never.

## License

PolyForm Noncommercial 1.0.0 — see [`LICENSE`](LICENSE). Noncommercial use is
permitted with attribution; commercial use is reserved (dual-licensing available).
