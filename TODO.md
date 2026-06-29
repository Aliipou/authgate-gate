# AuthGate — TODO & Roadmap

Industry-grounded plan. Positioning: **"OPA/Cedar for AI agents — a formally-verified
policy decision point with MCP-native enforcement."** Lead with the verified core; it is
the moat, not overhead (cf. AWS Cedar verified in Lean, seL4).

Category map (the names buyers/reviewers recognize):
- AuthGate = **PEP + PDP** (Policy Enforcement + Decision Point, XACML/NIST).
- Audit log = **PIP/observer**, never a control path.
- Threat model = **OWASP LLM Top 10**: LLM06 Excessive Agency, LLM07 Insecure Tooling,
  prompt-injection → unauthorized tool calls.

---

## NORTH STAR: correctness = containment, not truth

Direction chosen (2026-06-30): **engineering-grade agent runtime, not abstract research.**
The success criterion is **fail-safe under a present attacker** — "even assuming everything is
compromised, no catastrophe." Security comes from **isolation · capability restriction · minimal
trust · runtime containment** — NOT from getting the philosophy "right."

The fallacy to kill: *"if I define legitimacy correctly, the system is safe."* False in a real
runtime. So:
- **FDK is downgraded** from "moral judge / authority" → **pre-execution constraint compiler**:
  a low-trust pre-filter that prunes before execution, holds **no** authority, needs **no** moral
  ground truth. (Consistent with the kernel rule: no philosophy in the enforcement path.)
- **AuthGate = the hard security boundary** (high trust).
- **Runtime containment = the dominant safety layer.**
- Go wrong here and FDK becomes a *false sense of safety* and the whole thing fails on a
  philosophical assumption.

### Full runtime stack (build order)
```
(0) Epistemic / Trust & Signal layer     ← MISSING; hardest; don't fake it
(1) Intent + Agent Runtime
(2) FDK  — legitimacy PRE-FILTER (low trust, no authority)
(3) Policy / ranking (constraints, utility)
(4) AuthGate — capability enforcement (hard boundary)
(5) Execution sandbox (isolated)
(6) Safety watchdog — independent, kernel-level monitor
(7) Incident log + rollback
```

### The critical missing piece: Layer #3 — Runtime Control & Drift Layer (TEMPORAL)
The deepest gap. FDK + AuthGate cover **decision** + **execution**; neither covers **behavior over
time**. You're building a *decision system*; the missing layer makes it a *control system*.

```
   FDK            AuthGate          Runtime Control Layer  ← missing
   "is it         "may it           "is the system's BEHAVIOR over time
    legitimate?"   execute now?"     still valid?"
   static          local/per-call    dynamic / temporal
```

What it adds (none of the other layers can see this):
1. **Drift detection** — after N steps, is the trajectory still inside the allowed space? Catches
   goal-bypass, *soft* policy bypass, reward hacking — each step legal, the *path* illegitimate.
2. **Multi-step consequence tracking** — FDK sees one action; this sees step 10. Without it you
   never see the slow constraint-bypass that's built from individually-allowed steps.
3. **Mid-execution capability scoping** — *"everything is a capability, including reasoning."*
   Constrain the action space *before the agent reasons into it*, not just deny the output.

This is real, named work — not philosophy: **runtime verification · control barrier functions
(robotics) · adversarial-ML monitoring · agent trajectory supervision · OS safety kernel**. In OS
terms: FDK = law, AuthGate = syscall permission, **Runtime Layer = kernel watchdog + anomaly
detection** (stack slots 6–7).

**Build-order discipline:** this is the *destination*, not the next step. It consumes the Action
Packet stream — so the **Action Packet ABI (decided next step) is exactly step 1 toward it.** Don't
build the drift layer before packets flow.

### Honest coverage with the 3rd layer (numbers are non-linear — adversarial)
| Layer stack | system-behavior safety | reliable control of dangerous systems |
|---|---|---|
| FDK only | 20–40% | ~30–40% |
| FDK + AuthGate | 20–40% | ~45–60% |
| + Runtime Layer | 60–80% | ~65–80% |

Never 100% — the system is adversarial and not fully closeable. **Even with all 3 layers, still
unsolved:** semantic intent-hijacking · unknown-unknowns / emergent behavior · multi-agent
coordination attacks · specification gaming (bypass without formally violating a rule). No current
architecture (Google/OpenAI/AWS included) solves these either — say so, don't oversell.

### Target decision: **AI agents in cloud first** (not robotics)
The runtime/AuthGate design forks hard between cloud-AI and physical/robotics. Pick **cloud AI**:
software-only (no hardware/real-time/physical-liability), a market exists today (MCP tool-calls),
matches the existing stack. **Robotics = a later adapter**, once cloud works — its irreversibility
(see coverage map ~30–50%) is exactly what a gate handles worst.

## Architecture principle: "One logic, many worlds" (lock this)

The keystone decision — get it wrong and it becomes "a philosophy engine with APIs":

```
   FDK Core        (pure legitimacy logic — FIXED, provable, never per-domain)
       │           consent · coercion/boundary · ALLOW/DENY/DEFER · legitimacy ≠ utility ≠ capability
       ▼
   Capability Kernel (AuthGate — binary enforce: may execute or not; no semantics)
       │
       ├──► AI-agent Adapter   (action = tool call;  risk = data leakage)
       ├──► Robotics Adapter   (action = physical cmd; risk = irreversibility)
       └──► Finance Adapter    (action = transaction;  risk = loss/fraud)
```

- **FIXED core, do NOT fork per domain:** consent/coercion/boundary defs, ALLOW/DENY/DEFER,
  legitimacy-predicate structure. Forking these = fragmentation → unverifiable → dead.
- **Vary only the adapter:** `boundary model · consent model · threat/risk model` per domain.
  Same logic, different world — not a new ethics per world.
- **Adapter ABI** (the standard every domain implements):
  ```
  normalize(input)        -> Action          # domain event → canonical Action
  denormalize(result)     -> output          # decision/result → domain shape
  map_capabilities(Action)-> Capabilities    # what authority this needs
  risk_profile(Action)    -> RiskVector      # domain-specific risk
  ```
- This keeps the FDK↔AuthGate **`PolicyDecision` JSON contract** intact (already in memory):
  FDK = "is it legitimate?", AuthGate = "may this actor execute it?", adapter = "what does this
  domain's event mean?". No shared code across the seam.

## Next concrete step — DECIDED: (1) Action Packet spec (ABI) first

The three options were: (1) Action Packet/Intent ABI · (2) Domain Adapter SDK · (3) Execution
sandbox / "real OS kernel". **Do #1 now.** Why:
- It's the **keystone both others depend on** — adapters and the sandbox both consume the packet.
- Cheapest, highest leverage; makes the gate **drop-in + MCP-native** (the adoption surface).
- It's the cleanest **portfolio artifact**.
- **Defer #2 (SDK):** building an SDK for 3 domains before *one* works = the over-universalization
  trap. Do exactly **one** AI-agent adapter after the packet, not an SDK.
- **Defer #3 (sandbox):** it's the real confinement moat, but high-effort + env-blocked here
  (Linux/WASM; partial sandbox already exists in `authgate-kernel`). Do it when there's a Linux
  env *and* a user. Don't let "design the real OS kernel" pull v1 into scope creep.

## Two more layers/rules the feedback converged on (record, don't build yet)

**Missing Layer #0 — World Model / ground-truth / observability** (this *is* stack-slot 0).
FDK decides on *a story about the world*, not the world. Its inputs — consent, coercion, ownership
— are assumed complete; in reality they're ambiguous, multi-layered (data/model/inference), and
coercion is often *unobservable*. Without observable, machine-checkable definitions, FDK is an
**interpretation layer, not a deterministic decision.** The 20% that decides "real system" vs
"beautiful philosophy-engineering" = **world-model + observability + semantics grounding.** Hardest
layer; don't fake it. (Honest: no one — Google/OpenAI/AWS — has solved this either.)

**Hard rule — never merge FDK and AuthGate** (God-object anti-pattern). Merging legitimacy reasoning
+ capability check + crypto enforcement → undebuggable, multiplied attack surface, and the worst
outcome: *ambiguity leaks into the enforcement layer*. Keep them separate across the JSON
`PolicyDecision` seam, no shared code. (Same as the kernel invariant: **AuthGate depends on
nothing**; no philosophy in enforcement.)

**AuthGate scope honesty (put in README):** AuthGate is **necessary, not sufficient.** It stops a
*dangerous action*; it does **not** stop a *wrong-but-allowed decision* — and the agent problem is
exactly the second. Full conceptual stack: Goal-formation (research/unknown) → FDK (legitimacy
filter) → Planner → AuthGate (capability enforcement) → Execution → Ledger/audit/crypto. AuthGate is
the **lowest hard safety boundary before execution** — own that, claim no more.

## BUILD STATUS (2026-06-30) — governance-OS skeleton, parallel team

Goal: drive *modeled* attacks to contained (red-team bypasses → 0) with fail-closed
defense-in-depth; honest that semantic/unknown-unknown gaps never reach 100%.

- [x] **ABI contract** (`action.py`, `normalize.py`) — Action Packet v1, RiskVector,
      Layer/DomainAdapter protocols, trust-boundary token normalization. Committed `20584cc`.
- [~] **Capability layer** (`capability.py`) — default-deny actor→capability, wildcard admin,
      fail-closed. *(agent building)*
- [~] **Runtime/Drift layer** (`runtime.py`, Layer #3 temporal) — per-session steps/rate/budget,
      replay-nonce, cross-step taint laundering, fleet kill-switch. *(agent building)*
- [~] **Domain adapters** (`adapter.py`) — AI (reference) + Finance + Quantum-job, proving
      "one logic, many worlds". *(agent building)*
- [~] **Tamper-evident audit** (`audit_chain.py`) — hash-chained JSONL + `verify()`. *(agent building)*
- [ ] **Compose `ControlledGate`** — capability → purpose → runtime, first DENY wins, TRANSFORM
      carries forward; audit every decision with the deciding layer. *(me, after layers land)*
- [ ] **Brutal red team** (`redteam/red_team.py`) — N adversaries × categories (injection,
      purpose-laundering, capability-escalation, tool-chaining, runaway, budget-exhaustion,
      replay, unicode/zero-width, kill-switch-bypass, audit-tamper). Any escape = hard fail.
- [ ] **Iterate** red-team → fix bypasses → rerun until 0. Then commit + push.

## Now (v1 — make the wedge undeniable)

- [ ] **Positioning README pass.** Add one-line pitch + a competitor table
      (OPA, AWS Cedar, OpenFGA, Okta Auth-for-GenAI, Anthropic MCP auth) and the
      PDP/PEP framing. Drop every "OS/kernel/world-system" word.
- [ ] **60-second demo is the product.** `prompt_injection_demo.py` must show
      ALLOW / DENY / TRANSFORM in one screen, copy-pasteable. Record an asciinema/gif.
- [ ] **Make the FDK boundary a tested invariant,** not a convention: a test that fails
      if anything analytics/non-deterministic touches the decision path.
- [ ] **Sign the audit log** (hash-chain each record) → SOC2/ISO-27001/EU-AI-Act story.
- [ ] **Latency budget check:** assert decision overhead < 5–10 ms in tests.

## Next (differentiator — the verified core)

- [ ] **Wire the formal core to the gate.** Reuse `authgate-kernel` (Rust TCB / Kani /
      Lean / TLA) so the decision logic is *provably* the one that runs — pitch:
      "provably correct authorization, not best-effort."
- [ ] **MCP-native enforcement.** Map the Intent schema to MCP tool-call shape so the gate
      drops in front of any MCP server.
- [ ] **Policy: stay declarative + deterministic** (OPA/Cedar lineage). DSL only when a
      real policy outgrows the flat JSON map — not before.

## Honest coverage map (what this actually solves — put in README)

The one-line truth: **this constrains agent _power_; it does not make agents _decide correctly_.**
It solves a real slice well, and is honest about the rest. Don't sell the rest.

Solves well (the real wins — lead with these):
- **Unauthorized execution** ~90% — no action without a capability; kills a large bug class.
- **Policy inconsistency** ~80% — one rule set across domains, no contradictory policies.
- **System/architecture drift** ~85% — clean domain separation + dependency graph.
- **Auditability** — who/what/why/when; the compliance (finance/health) sell.

Does NOT solve (state plainly; over-claiming here is how it loses credibility):
- **Ground truth** ~20–30% — can't tell real consent/intent from manipulation/social-engineering.
  It checks what it was *given*, not the truth. A wrapper over the trust problem.
- **Adversarial / model deception** ~40% — if the agent itself is compromised, the gate sees
  inputs, not reality.
- **Reward hacking / goal misgeneralization** — "legal but dangerous" actions still get found.
- **Physical irreversibility (robotics)** ~30–50% — a wrong action that passes is already done;
  a gate is not an OS-level guarantee.
- **Specification completeness** — boundary/consent/coercion/ownership are ambiguous in the real
  world; you can't fully enumerate them.

## Honest threat boundary (state it, don't oversell it)

What this is: a **capability-based authorization kernel** (decision gating).
What it is **not**: an *adversarial-complete* security system or full execution isolation.
The real gap is **before the gate** — controlling agent behavior up to the point it emits
an intent. State this plainly in the README; reviewers respect a stated boundary.

Real hardening path (upgrades, not illusions — do later, in order):
- [ ] **Decision gating → execution confinement.** Don't just deny; make the forbidden
      action *impossible to execute*: seccomp / SELinux / **WASM host isolation**.
- [ ] **OS-level boundary enforcement** so a bypass outside the TCB can't reach tools.
- [ ] **Semantic/provenance layer** (hard): provenance tracking + causal graph of agent
      decisions. Research-grade; scope carefully.
- [ ] **Adversarial sim at scale:** today ~231 scenarios → fuzzing + model-based attack
      generation (orders of magnitude more). This is what turns "deterministic" into "hard".
- [ ] Decide which parts are **publishable research** vs **engineering polish** — don't
      confuse the two.

## Decision gate (settle before scaling effort)

- [ ] **Portfolio play vs product play — pick one.** Portfolio = lead with verified core
      as credibility (matches strengths). Product = drive the wedge to first paying niche.
      Don't run both at full effort. *Leaning portfolio.*

---

## Missing / deferred (don't forget — revisit, do not delete)

- [ ] **GitHub: re-auth + create repo + first push.** Token is dead (`Bad credentials`).
      Run `gh auth login -h github.com`, then `gh repo create Aliipou/authgate-gate
      --private --source=. --push`. (This repo is not yet on GitHub.)
- [ ] **Multi-agent control plane** (per-agent identity, scheduling, resource arbitration,
      coordination, kill-switch). Real OS-like needs — but call it *Agent Runtime / Control
      Plane*, never "OS". Future, behind a hard interface.
- [ ] **Intent normalization layer** (typed intent schema; agent never emits raw actions).
      Strong add, not v1.
- [ ] **PQC key handling** — checkbox for post-quantum, not a product. Defer.
- [ ] **Quantum / AGI framing** — keep as one future-fit paragraph only. Not a build target.
- [ ] **FDK analytics UI / anomaly detection** — offline observer only, after v1 ships.
- [ ] **Cross-repo:** let `boundary-guard` enforce "AuthGate depends on nothing" across the
      stack; confirm the FDK↔AuthGate `PolicyDecision` JSON contract (not shared code).

---

## Explicitly NOT doing in v1 (kept from README — restated so it doesn't creep back)

Economic modeling · governance/philosophy layer · blockchain · FDK in runtime ·
model-based / AI decisions inside the gate. Each is how this dies early.
