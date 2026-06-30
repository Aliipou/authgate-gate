# CRITICAL_RESEARCH.md — Falsification-first gap analysis of the AuthGate governance stack

Scope: the repo at `D:\جافکری\authgate-gate` as it stands on 2026-06-30. Method:
read every artifact, run the suite, and try to **kill** the project's central claim —
that this is a "governance OS / safety-kernel for autonomous technologies." Evidence is
cited to specific files/functions. No code was modified. Tests run green (65 passed),
demo runs.

The verdict up front: this is a **clean, deterministic, well-factored policy decision
point (PDP) with a per-session temporal monitor and a tamper-evident log** — and that is
genuinely good, small-surface engineering. It is **not** an OS, a kernel, a containment
system, or a solution to the agent-safety problem. The gap between what is built and what
the framing claims is large, and the single composed artifact the whole pitch rests on
(`ControlledGate`) is **untested and unused by the demo**.

---

## 1. What it genuinely is (and is not)

**Is:** a stdlib-only, ~1,400-LOC Python library that, for one `Action` packet
(`authgate/action.py`), runs three deterministic, fail-closed checks in order —
capability (`capability.py`), purpose-binding + redaction (`policy.py`), and a
per-session temporal monitor for steps/rate/budget/replay/cross-step-taint
(`runtime.py`) — composed in `controlled_gate.py`, with a hash-chained JSONL audit log
(`audit_chain.py`) and three domain adapters (`adapter.py`). The token-normalization
boundary (`normalize.py`: NFKC + drop Unicode "C" categories + casefold) is a real and
well-chosen defense against look-alike/zero-width capability-token smuggling. Every layer
genuinely fails closed (each `check` wraps its body and converts exceptions to `DENY`).
Commit-on-allow in `runtime.py` (`_check` mutates state only past the final ALLOW) is a
correct and non-obvious design that stops an attacker from burning a victim's budget by
deliberately tripping denials. This is the honest core, and it is solid.

**Is not:** an operating system, a kernel, a sandbox, or an enforcement boundary in any
OS sense. Nothing here confines execution. The gate returns a `Decision`; a cooperating
caller is trusted to honor it (`controlled_gate.py::dispatch` only declines to *call*
`tool()`). There is no process isolation, no seccomp/WASM/SELinux, no syscall boundary,
no out-of-process trust. The formal verification the TODO leans on as "the moat" (Rust
TCB / Kani / Lean / TLA) lives in a **different repo** (`authgate-kernel`) and **none of
it is wired into this code** — the decision logic that actually runs here is ordinary,
unverified Python. The README's own "Intentionally excluded" section is accurate; the
TODO's "governance-OS skeleton" framing is not.

---

## 2. Real gaps, ranked by how fatal

### G0 — The composed product is untested and the demo doesn't use it *(unbuilt; fatal to credibility, trivially fixable)*
`ControlledGate` — the entire "fail-closed defense-in-depth stack" that the pitch sells —
has **zero tests**. `grep` for `ControlledGate|build_gate` across `tests/` and `examples/`
returns nothing. The 65 passing tests exercise the four layers *in isolation*; the
*composition* — DENY-short-circuit order, TRANSFORM-carry-forward into the runtime layer,
audit-tagging per layer — is unverified. Worse, the headline demo
(`examples/prompt_injection_demo.py:19,36`) and the only gate-level test
(`tests/test_gate.py:11,16`) import and use the **legacy single-layer `AuthGate`**
(`gate.py`, purpose-only), **not** `ControlledGate`. So the artifact a reviewer runs is
the *old* gate; the *new* composed stack the README architecture diagram describes is
dead code from the test suite's point of view. This is the most damaging finding because
it is the cheapest to weaponize against the project: "your flagship object has no tests
and your demo doesn't call it." **Hard-but-trivial to fix** (write `test_controlled_gate.py`,
repoint the demo). Until then, claims about the composed stack are unsubstantiated.

### G1 — The red-team that is the *stated* validation strategy does not exist *(unbuilt; fatal to the central success claim)*
The TODO's North Star is "drive *modeled* attacks to contained (red-team bypasses → 0)"
and lists `redteam/red_team.py` with ten attack categories as the gate to "commit + push."
**There is no `redteam/` directory and no `red_team.py`.** The project's own definition of
"working" has not been executed. Every coverage number in the TODO (60–80% with the runtime
layer, etc.) is therefore an *estimate with no adversarial measurement behind it*. The
honest status is: defense-in-depth *designed*, never *attacked*. **Unbuilt, solvable, and
the highest-leverage next move** (see §5).

### G2 — World-model / ground-truth gap: whoever writes `data_labels` owns the policy *(fundamentally unsolvable in this architecture)*
The entire purpose-binding engine (`policy.py::evaluate`) decides on
`action.data_labels` and `action.action_purpose` — *assertions attached to the packet*,
not verified facts about the world. The adapters take them **verbatim from the raw event**
(`adapter.py::AIToolAdapter.normalize:147-148` does `raw.get("purpose")` /
`raw.get("data_labels")`; finance and quantum adapters do the same). If the prompt-injected
or compromised agent is the thing constructing the raw event — which is *exactly* the threat
model in the demo — it simply mislabels: send the customer dump with
`action_purpose="support_reply"` and `data_labels=("customer_support",)` and the gate
ALLOWs it, because those labels *do* permit that purpose
(`policies/purpose_policy.json:5`). The demo's prompt-injection is only caught because the
attacker is assumed to *honestly self-label as marketing*. A real attacker lies about the
label. There is no provenance, no taint *derivation*, no check that the body actually
matches the declared purpose. The gate "checks what it was given, not the truth" — the
TODO admits this (~20-30%), but it is more fatal than a percentage suggests: it voids the
flagship prompt-injection defense against any adversary who controls labeling. **Not
solvable without an out-of-band, trusted provenance/labeling authority the agent cannot
forge** — which this architecture does not have and arguably cannot have while the agent
emits the packet.

### G3 — Taint propagation is coarse and unsound through an LLM *(hard-but-unsolvable to full soundness; this is the IFC frontier)*
The cross-step taint defense (`runtime.py:272-290`) pins a *sensitive label* to the first
`action_purpose` it is seen under and denies later reuse under a different purpose. That is
purpose-pinning on a **string label**, not information-flow control. It cannot track that
sensitive *content* read at step 1 was paraphrased, summarized, or embedded into a payload
at step 9 that no longer carries the label — the LLM laundered the *data* while shedding the
*label*. Sound IFC through a model is an open research problem (this is what DeepMind's CaMeL
/ dual-LLM work attacks, and even they don't close it). The available choices are
**over-block** (taint everything downstream of a sensitive read → the agent becomes useless)
or **under-block** (track labels → laundering through the model's text output is invisible).
This repo chose under-block at label granularity. Honest, but it means the laundering
defense is defeated by the model doing its normal job. **Hard; not fully solvable here.**

### G4 — Irreversibility: this gates decisions, it does not confine execution *(unbuilt; partially unsolvable)*
`RiskVector` (`action.py:76`) computes a `reversibility` score, and adapters mark money
(0.10) and hardware-calibration (0.20) as near-irreversible — but **nothing consumes that
score to change enforcement.** It is computed and discarded; `ControlledGate.enforce`
never reads a `RiskVector`. More fundamentally, a `DENY` is advice. If a bypass occurs
anywhere outside the cooperating caller — a second code path to the tool, a bug, a
compromised executor — the gate cannot stop the effect; there is no seccomp/WASM/OS
boundary (the TODO concedes this and defers it as "env-blocked"). For irreversible domains
(finance, robotics, the calibrate/reset quantum jobs) a wrong-but-allowed action is *done*
the instant the trusted caller executes it. A decision gate is structurally the wrong tool
for irreversibility. **The confinement layer is unbuilt; the residual is unsolvable by
gating alone.**

### G5 — In-process trust boundary: own the process, own the chain *(hard-but-solvable; needs external anchoring)*
`audit_chain.py` is honest in its own docstring (lines 33-36): it is "the in-process half"
and "cannot *prevent* tampering — an attacker who can rewrite the file can also recompute
the whole chain." That is exactly right and exactly the problem. The hash chain detects
*third-party* edits to a file the attacker can't fully recompute; it does **nothing**
against the adversary in this threat model (a compromised agent/process), who holds the
write handle and the hash function and can forge a perfectly valid alternate chain, or
simply never call `record`. The same in-process fragility hits the `CapabilityRegistry`
(`capability.py`, an in-memory `dict`) and `RuntimeMonitor` state (`runtime.py`, in-memory
`dict` of sessions): no persistence, no integrity boundary. Whoever owns the process owns
grants, budgets, and the audit. **Solvable** with external anchoring (notary / WORM bucket
/ periodic published `entry_hash`, transparency-log style) and out-of-process state — but
none of it is here, so today the tamper-evidence claim is only true against an attacker who
is *not* the one in the threat model.

### G6 — Distribution: state is per-process; there is no control plane *(unbuilt; the "N agents" claim is unsupported)*
`RuntimeMonitor._sessions` and the `_stopped` kill-switch (`runtime.py:149-161`) are a
single in-memory dict in one process. The `stop()` docstring says "EVERY session DENIES"
and `build_gate` markets the returned monitor as a "fleet kill-switch" — but the *fleet* is
one process. Two gate instances (two machines, two workers, even two processes on one box)
share **no** state: step budgets, cumulative spend budgets, replay-nonce sets, and the
kill-switch are all local. Run the same agent across two workers and the budget ceiling is
2×, the replay defense is per-worker (a nonce replayed on worker B is unseen), and
`stop()` on one leaves the other live. There is no shared/consistent control plane, no
distributed counter, no consensus on "has this nonce been spent." For any real multi-agent
or horizontally-scaled deployment the temporal guarantees **silently degrade to per-process
best-effort.** The TODO lists "multi-agent control plane" as deferred; correct — but the
current copy ("fleet") overclaims what the per-process monitor delivers. **Unbuilt; solvable
but it is a distributed-systems project of its own.**

### G7 — Operational gaps for infra-grade *(unbuilt; mostly solvable plumbing)*
- **No persistence / HA:** registry + runtime state die with the process; a restart resets
  every budget and the kill-switch (`runtime.py`, `capability.py` — pure in-memory).
- **No runtime policy versioning/rollback:** `PolicyEngine.from_file` (`policy.py:46`) loads
  JSON once at construction; there is no reload, no version pinning per decision, no
  rollback. The policy carries a `version` field that nothing enforces or records.
- **No formal proofs in *this* repo:** the Lean/Kani/TLA moat is in `authgate-kernel`; the
  Python here is unverified and not generated from any verified spec.
- **Performance/latency unmeasured:** the TODO's own "assert < 5–10 ms" item is unchecked;
  there is no benchmark. Likely fine (it's dict lookups), but it is asserted, not measured.
- **Composition correctness unproven** (see G0).

---

## 3. Honest coverage (with code evidence)

What it covers *well*, and the evidence:
- **Unauthorized execution (~high):** default-deny capability gate
  (`capability.py::CapabilityRegistry.allows` returns False on empty grant set); an actor
  with no grant is denied everything. Real and clean.
- **Self-honest purpose violations (~moderate):** `policy.py::evaluate` correctly denies a
  *truthfully-labeled* cross-purpose flow and redacts unneeded fields. This is the demo's
  win — but it is conditional on truthful labels (see G2).
- **Mechanical temporal abuse (~moderate):** runaway steps, bursts, cumulative budget,
  intra-session nonce replay (`runtime.py:213-308`) are correctly enforced *within one
  process* (see G6 for the distribution caveat).
- **Token-smuggling bypasses (~high):** `normalize.py` genuinely closes case/NFKC/zero-width
  capability splitting; this is well done.
- **Tamper-evidence vs an external editor (~conditional):** `audit_chain.verify_detail`
  detects edit/insert/delete/reorder by anyone who *cannot* recompute the chain (see G5).

The **irreducible remainder** — and the gate provably cannot touch it because the code that
would is absent or structurally impossible: ground-truth/label honesty (G2), semantic
intent-hijacking, specification gaming ("legal but dangerous" — every individual `Decision`
is ALLOW yet the goal is harmful), emergent/unknown-unknown behavior, sound cross-model
taint (G3), execution confinement & irreversibility (G4), in-process compromise (G5), and
cross-machine coordination (G6).

Net honest read: against the *full* "dangerous autonomous systems" problem, this is a
**single necessary layer** — the lowest hard authorization boundary before a *cooperating*
executor — and it covers maybe the unauthorized-execution and honest-purpose slice well
while leaving the hard majority (semantics, ground truth, confinement, distribution)
untouched. The TODO's "60–80%" is an unmeasured estimate that also silently assumes
truthful labels and a single process; under the real threat model (lying, multi-process
adversary) the *adversarial* coverage is far lower until G0–G2 are addressed. The README's
own coverage map is the most honest document in the repo; trust it over the TODO's numbers.

---

## 4. As a product vs as an "OS"

**As a product** (PDP/PEP for AI agents) it is *defensible and the right framing.* The
nearest incumbents and the honest delta:
- **OPA / OpenFGA / AWS Cedar:** mature, declarative authorization engines. They answer
  "may this actor do this?" extremely well. AuthGate's **only** genuine differentiators are
  (a) **purpose-binding** (data-purpose → action-purpose flow control, `policy.py`), which
  classic RBAC/ReBAC/Cedar don't model natively, and (b) the **per-session temporal monitor**
  (`runtime.py`) — drift/rate/budget/replay across a trajectory, which a stateless PDP has
  no concept of. Those two are real and worth leading with. Everything else (capability
  check, audit) OPA/Cedar already do better and at scale. Note Cedar is *actually* verified
  in Lean today; AuthGate's verification is in another repo and unwired, so "formally
  verified" must **not** be claimed for this codebase yet.
- **DeepMind CaMeL / dual-LLM:** these attack the part AuthGate *cannot* (G2/G3) — keeping
  untrusted model output from corrupting privileged actions via capability/taint at the
  data-flow level. AuthGate's coarse label-pinning is a weaker cousin; it does not add
  over CaMeL on the laundering problem, and should cite it as the harder, complementary
  approach rather than imply parity.
- **seL4:** the confinement/kernel reference. AuthGate adds **nothing** here — it has no
  isolation. Any "kernel/OS" framing invites this comparison and loses it instantly.

**As an "OS" / "safety-kernel for autonomous technologies"** it **overclaims, badly.** No
process model, no scheduling, no resource arbitration, no isolation, no syscall boundary,
no execution confinement — the things that make a kernel a kernel. The TODO itself says
"Drop every 'OS/kernel/world-system' word"; that instruction is correct and should be
obeyed everywhere, because the gap between the word "kernel" and a `Decision`-returning
Python function is the easiest thing for a hostile reviewer to exploit. **Defensible
framing: "OPA/Cedar for agents, plus purpose-binding and a trajectory monitor."
Indefensible framing: anything with "OS," "kernel," or "containment" in it.**

---

## 5. The 5 things that would most increase real-world credibility (ordered)

1. **Build and run the red-team (`redteam/red_team.py`), and make G0 disappear first.**
   Write `test_controlled_gate.py` and repoint the demo at `ControlledGate`; then build the
   ten-category adversarial suite the TODO already specifies, *including an attacker who
   lies about `data_labels`/`action_purpose`* (the G2 case the current demo dodges). Publish
   the bypass count. This converts every estimated coverage number into a measured one and
   removes the most damaging "your flagship isn't tested" attack.
2. **Make taint about content provenance, not just labels — or state loudly that it isn't.**
   At minimum, derive taint from *which prior reads fed this payload* rather than trusting a
   self-attached label; cite CaMeL and scope honestly. Closing G3 fully is research; making
   the limit explicit and tightening the easy cases is engineering.
3. **Anchor the audit chain out-of-process** (transparency-log / WORM / periodic notarized
   `entry_hash`) so tamper-evidence holds against the in-threat-model attacker (G5). The
   in-process chain is necessary plumbing but currently proves nothing against the adversary
   it names.
4. **Externalize and share runtime state** (persistent, consistent store for grants,
   budgets, nonce-sets, kill-switch) so the "fleet" claim becomes true across processes/
   machines (G6) and survives restart (G7). Until then, cap the marketing to "single
   process."
5. **Wire one real verified property end-to-end, or stop saying "verified."** Either
   generate/extract the decision logic from the `authgate-kernel` proofs so the running code
   *is* the verified one, or strike "formally verified" from this repo's pitch. A measured
   latency benchmark (the TODO's own unchecked item) is a cheap companion win.

---

## 6. Falsification verdict

**The single most likely reason this fails to become real infrastructure:** it solves the
*easy, already-served* half of the problem (authorization, which OPA/Cedar do better and at
scale) while its two genuine differentiators — purpose-binding and the trajectory monitor —
**both collapse under the exact adversary the project names.** Purpose-binding is defeated by
an attacker who lies about `data_labels` (G2), and the trajectory monitor degrades to
per-process best-effort the moment there is more than one worker (G6) and proves nothing once
the process is owned (G5). The project's own success test (red-team → 0 bypasses) has never
been run, and its flagship composed object is untested and unused by the demo (G0–G1). So the
falsification is not "the idea is wrong" — purpose-binding + temporal monitoring is a *real,
under-served idea* — it is that **the implementation's hard guarantees are exactly the ones
that evaporate against a present attacker, which is the one threat model the README adopts.**
Until G0, G1, G2, and G5/G6 are addressed, an honest reviewer concludes: a tidy
purpose-aware PDP with a single-process rate-limiter and an append-only log — useful as a
portfolio artifact and as one layer in someone else's stack, but not, on its own,
infrastructure, and not a kernel.

What is genuinely well-built and should be defended: the fail-closed discipline (every
`check` converts errors to DENY), commit-on-allow (`runtime.py`), the normalization boundary
(`normalize.py`), the clean adapter ABI proving "one logic, many worlds" (`adapter.py`), and
the intellectual honesty of the README's coverage map. The engineering is good. The framing
is two sizes too big, and the validation that would back the framing isn't written yet.
