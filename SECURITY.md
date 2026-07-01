# Security Policy

This document states, without marketing, what this gate defends against, what it
does not, and why the residual gaps are architectural rather than bugs. Every
claim points at code or at the red-team report (`redteam/ADVERSARY_FINDINGS.md`).

## 1. Threat model and trust boundary

AuthGate is a **capability-based authorization gate** for agent tool execution.
It is composed of three per-session enforcement layers — capability, purpose
policy, and a runtime/temporal monitor — plus a hash-chained audit log.

Two properties are load-bearing:

- **Fail-closed.** Any internal error, non-finite budget, or unreasoned state
  becomes `DENY`, never `ALLOW` (`authgate/runtime.py:229-232`, `:304-310`).
- **Correctness = CONTAINMENT, not truth.** The gate does not decide whether an
  action is *good*. It decides whether an action is *permitted by policy* and
  keeps a tamper-evident record. A correct verdict is one that does not let a
  disallowed effect through — not one that is morally or factually right.

The critical distinction is **where the attacker sits**:

- **Out-of-process attacker** (a compromised or injected *agent* that must call
  the gate to act): this is the case the gate is built to CONTAIN. If the agent
  can only cause effects by going through `check()`, the layers bound what it can
  do — capability, purpose, budget, step, rate, replay.
- **In-process attacker** (code that OWNS the gate process): this is the hard
  case, and it is only partially addressable in library code. An attacker holding
  the process holds the write handles and the hash function; several guarantees
  become deployment properties, not code properties (Sections 3 and 4).

Everything below is scoped by which of these two attackers it addresses.

## 2. What is enforced / fixed

The prior suite (`redteam/red_team.py`) reported 0 escapes / 3700 cases, but only
**single-threaded** and only against the **out-of-process** attacker. A deeper
red team (`redteam/ADVERSARY_FINDINGS.md`) drove that to **8 escapes / 13
attacks** by testing concurrency, in-process forgery, and lying-label
exfiltration. The following were closed, taking the score to **2 remaining**.

- **Concurrency temporal guarantees are now lock-protected.** The budget-ceiling
  lost-update (#1), step overshoot (#1b), and nonce double-accept (#1c) were
  genuine unsynchronized read-check-commit races. The read, the ceiling checks,
  and the commit now run inside a **per-session lock** so they are atomic against
  concurrent ALLOWs in the same session, while distinct sessions still check in
  parallel (`authgate/runtime.py:136` lock field, `:251-252` critical section,
  `:344-355` commit; get-or-create is itself locked at `:192-199`). This restores
  the budget, step, and replay ceilings under real multi-threaded load.

- **Redaction is recursive and content-based** (#4). The old redaction was a
  shallow top-level field-name replace, bypassed by nesting (`meta.ssn`),
  aliasing (`ssn_copy`), or echoing the secret into free text (`body`).
  Redaction now (a) recurses to any depth and collects the redacted values
  (`authgate/policy.py:23-49`), then (b) scrubs those values wherever else they
  appear (`authgate/policy.py:78-100`). A short-value floor (`_MIN_SCRUB_LEN = 4`,
  `authgate/policy.py:20`) avoids absurd over-redaction of trivial values.

- **`session_id` is normalized** (#10). It was previously only `.strip()`'d, so a
  zero-width or look-alike variant forked a *fresh* session with untouched
  ceilings (and let a spent nonce replay in the twin). It now runs through
  `normalize_token` like every other identifier (`authgate/action.py:70`),
  collapsing cosmetic variants to one key.

- **Lying-label exfiltration is screened by content** (#2), as a **floor, not a
  proof.** A compromised agent can attach a policy-blessed
  `action_purpose`/`data_labels` pair and hide a real secret (an SSN) in an
  unnamed field. Purpose-binding alone trusts the self-attached label as ground
  truth. A redaction rule may now declare `redact_patterns` (regexes) that screen
  by **value** anywhere in the payload, independent of the label
  (`authgate/policy.py:52-75`, `:181-184`). Stated honestly: this catches
  **known formats** (e.g. SSN/PAN shapes). An obfuscated or encoded secret still
  slips. It raises the bar; it does not make egress of unknown-shaped sensitive
  data safe. True closure requires an out-of-band trusted labeling authority the
  agent cannot forge, which this library does not provide.

### Fixed vs residual summary

| # | Finding | Class | Status |
|---|---------|-------|--------|
| 1  | Budget ceiling breach (lost update) | code bug | **Fixed** — per-session lock |
| 1b | Step ceiling overshoot | code bug | **Fixed** — per-session lock |
| 1c | Nonce double-accept (replay) | code bug | **Fixed** — per-session lock |
| 4  | Secret survives TRANSFORM (nested/alias/echo) | code bug | **Fixed** — recursive + value scrub |
| 10 | `session_id` look-alike splits state | code bug | **Fixed** — `normalize_token` |
| 2  | Lying-label exfiltration | architectural | **Mitigated (floor)** — content screen, known formats only |
| 3  | In-process audit forgery | architectural | **Residual** — needs out-of-process trust root |
| 3b | Audit omission (bypass the gate) | architectural | **Residual** — needs mandatory mediation |

## 3. Residual limits (stated honestly)

Two escapes remain. They are **architectural**, not bugs — they cannot be closed
by any in-process code change, because they are defeats *by* the in-process
attacker.

### #3 — In-process audit forgery

An attacker who owns the process holds the log's write handle **and** the hash
function (`audit_chain._canonical_hash` is public and deterministic). They can
drop the damning record, recompute every `entry_hash`/`prev_hash`, and a fresh
`HashChainedAudit.verify()` returns `True`. **No in-process verifier can
out-compute an attacker who has the same primitives.** The module docstring
already admits this (`authgate/audit_chain.py:33-36`).

The only real remedy is an **out-of-process trust root** that retains the chain
head somewhere the attacker cannot rewrite. The shipped seam:

- `HashChainedAudit.head()` returns `(seq, entry_hash)` — the single value to
  publish out of band (`authgate/audit_chain.py:117-124`).
- An optional `anchor` sink is called after each durable write, so an operator
  can push the head to an external witness (`authgate/audit_chain.py:99`,
  `:179-185`).
- `verify_against_anchor(expected_hash, expected_seq)` re-verifies the chain AND
  checks that its head matches an externally-retained one; a truncation/rewrite
  past the anchored point diverges provably even when `verify()` alone returns
  `True` (`authgate/audit_chain.py:188-217`).

`authgate/notary.py` implements that external witness as a **separate process**
holding an append-only, per-chain-monotonic ledger of published heads. A
submission whose `seq` is not strictly greater than the last recorded is REJECTED
— a rollback announces itself (`authgate/notary.py:116-136`).

This is a **partial** remedy, and only holds under a real condition:

- **It buys nothing in the same trust domain.** If the notary runs as the same OS
  user on the same box as the compromised gate, that user can kill it or rewrite
  its ledger. The notary only helps when it runs where the gate's attacker cannot
  reach: **different user, different host, or append-only storage**
  (`authgate/notary.py:24-31`). The code supports this (plain TCP, separate
  ledger file); the **deployment** must actually separate them.
- **Single notary is a SPOF.** One notary is a single point of failure for
  availability. The HMAC (`AUTHGATE_NOTARY_KEY`) only stops an *unrelated*
  process from injecting bogus heads; it does not authenticate the gate against
  its own attacker, who holds the key too (`authgate/notary.py:36-39`).
  **Quorum, multiple witnesses, and a transparency log are later stages**
  (Section 4).

### #3b — Audit omission

An attacker who **never calls the gate** leaves no trace. The gate is advisory: a
caller that owns the process can perform the effect directly and never call
`record()`, and `verify()` is happily `True` on a log that never saw the crime.
**You cannot prove something was never logged**, and no notary closes this — the
notary sees nothing if nothing is submitted (`authgate/notary.py:32-34`).

The only real closure is **mandatory mediation**: make the gate the SOLE holder
of the effect's credential, so an effect is *impossible* without going through
it. For example, `ALLOW` mints a one-time token that the executor verifies, and
the gate holds the only API key. Then bypassing the gate means having no
credential to act with. **This is a deployment property, not library code** — it
depends on how the executor and secrets are wired, which is outside this repo.

## 4. Hardening roadmap

This is the intended path, presented as staged work — not as done. Two stages are
implemented in code; the rest are not.

1. **Anchor interface** — `head()` / `anchor` sink / `verify_against_anchor`. **[done, code]**
2. **Independent notary process** — `authgate/notary.py`, append-only, monotonic.
   **[done in code; needs real deployment separation to mean anything]**
3. **TLS / transport auth** between gate and notary. *[not done]*
4. **Ed25519-signed heads** (sign the published head, not just HMAC it). *[not done]*
5. **Append-only Merkle log** (inclusion/consistency proofs, not just a scalar head). *[not done]*
6. **Multiple witnesses / quorum** (remove the single-notary SPOF). *[not done]*
7. **Transparency protocol** (gossip / public verifiability of the log). *[not done]*
8. **Offline verification** (an auditor verifies against retained proofs without a live notary). *[not done]*
9. **Hardware / remote root of trust** — the ceiling. Remote append-only / immutable
   storage, a signing key in a **TPM/HSM** the process cannot extract, **Secure Boot**
   + **remote attestation** of the notary host. Only this tier survives an attacker
   who holds full OS-level control of the gate's *and* notary's machine. *[not done]*

### Honest integrity grade

Audit-log integrity, graded strictly:

| | Against an **out-of-process** attacker | Against an **in-process / full-machine** attacker |
|---|---|---|
| Hash chain alone (before) | detected | **defeated** (forger recomputes the chain) |
| + external anchor + independent notary (now) | detected | detected **iff** the notary is in a trust domain the attacker cannot reach |

This raises audit integrity from roughly **7/10 to ~8–8.5/10**. It does **not** reach
9.5+: if the notary runs as the same OS user on the same host, `kill notary; forge
gate` still wins. Closing that gap is stage 9 — a hardware/remote root of trust,
which is out of scope for a stdlib library and belongs to the deployment. This
change makes the security *model* more correct; it does not make the system
impenetrable, and must not be described as a complete fix.

## 5. Running the notary and wiring an anchor

Set the same shared HMAC key in both the gate's environment and the notary's:

```bash
export AUTHGATE_NOTARY_KEY=<shared-secret>   # both processes must share it
```

Run the notary **in a separate trust domain** (ideally a different user/host):

```bash
python -m authgate.notary --host 127.0.0.1 --port 8931 --ledger notary_ledger.jsonl
```

Wire the anchor into the gate's audit log so every recorded head is published:

```python
from authgate.audit_chain import HashChainedAudit
from authgate.notary import NotaryClient, make_anchor

client = NotaryClient(host="notary-host", port=8931)   # key from AUTHGATE_NOTARY_KEY
anchor = make_anchor(client, chain="prod-gate-1")
audit = HashChainedAudit("audit.jsonl", anchor=anchor)
```

`make_anchor` is **fail-closed**: if the notary rejects a head (seq regression) or
is unreachable, the anchor callback raises, so an operator who wired an anchor
learns immediately rather than silently losing tamper-evidence
(`authgate/notary.py:247-260`). An auditor later compares local and notary heads
via `verify_against_anchor`. **Reminder from Section 3:** this only provides
tamper-evidence if the notary runs where the gate's attacker cannot reach it.

## 6. Reporting a vulnerability

Please report privately rather than opening a public issue. Open a
[GitHub security advisory](https://github.com/Aliipou/authgate-gate/security/advisories/new)
or contact the maintainer. Include a minimal reproduction (an `Action` or
sequence, the expected decision, and the actual one). Any red-team escape is a
hard failure; a runnable exploit is worth more than a description.
