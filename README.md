# AuthGate — agent-gate (MVP)

A small, deterministic **purpose-bound authorization gate** that sits between an
AI agent and its tools. For every tool call the agent wants to make, the gate
decides **ALLOW / DENY / TRANSFORM** and writes an audit record.

> **Can do ≠ May do.** Authorization asks "is this actor allowed to call this
> tool?" Purpose-binding asks the harder question: "may *this data*, collected
> for *that purpose*, be used for *this action*?" That second question is what
> stops a prompt-injected agent from emailing your support data to a marketing
> list — even though it is technically allowed to send email.

## Architecture

```
        Agent  (intent generator — never executes)
          │   emits Intent { actor, tool, action_purpose, data_labels, payload }
          ▼
       AuthGate  (authority — deterministic, low-latency)
          │   ALLOW · DENY · TRANSFORM
          ▼
       Execution  (dumb executor — the tool)
          │
          ▼
       Audit log  (observer — who/what/why/decision/when; never a control path)
```

Hard rules this MVP keeps:
- **No AI inside the gate.** Decisions are deterministic and explainable.
- **No analytics in the critical path.** The audit log only observes.
- **Default deny.** Unknown data purposes are refused, not guessed.

## Run it

```bash
python examples/prompt_injection_demo.py   # see ALLOW / DENY / TRANSFORM in action
python tests/test_gate.py                  # deterministic checks
```

The demo runs five agent intents — including a prompt-injection that tries to
funnel `customer_support` data into a `marketing` email. The gate denies it and
logs why, while letting the legitimate calls through (and redacting an SSN that
a support reply did not need).

## Policy

`policies/purpose_policy.json` — a flat, versioned, human-readable map of which
data purposes may flow into which action purposes, plus redaction rules for data
minimization. No DSL yet; that is the next layer, not v1.

## Intentionally excluded from v1

Economic modeling, governance, blockchain, FDK in runtime, model-based decisions.
Each of those is how this project would die early. They come later, behind a hard
interface, or never.
