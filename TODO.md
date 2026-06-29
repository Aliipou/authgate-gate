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
