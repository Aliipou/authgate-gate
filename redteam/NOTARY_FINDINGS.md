# Notary Red-Team Findings — `authgate/notary.py`

Falsification-first audit of the new out-of-process audit-head notary.
Harness: `redteam/notary_redteam.py` (stdlib-only, spins the server on an
ephemeral port in a thread, one runnable exploit per attack).

Repro: `python redteam/notary_redteam.py`

**Result: 11 attacks, 5 ESCAPES.**

The three already-documented limits (same-OS-user can kill/rewrite the ledger;
single-notary SPOF; omission is unprovable) were deliberately NOT tested — they
are honest, known, and out of scope.

Legend: **CODE-BUG** = a defect fixable in this file; **INHERENT-LIMIT** = a
property of a shared-key single witness that no code change in this file closes.

---

## RANKED FINDINGS

### 1. [ESCAPE — CODE-BUG — HIGH] `bool` accepted where `int` seq is required → targeted pre-emption + ledger type corruption
- **Attack:** A3 (`attack_bool_seq_confusion`)
- **Root cause:** `authgate/notary.py:192` — `isinstance(seq, int)` accepts
  `bool` because `bool` is a subclass of `int`. The same hole exists at
  `authgate/notary.py:207` (the `at` op).
- **Repro:** `python redteam/notary_redteam.py` (attack A3), or:
  ```python
  L = NotaryLedger(p); L.submit('c', 0, 'h0'); L.submit('c', True, 'hTrue')
  L.submit('c', 1, 'real1')  # -> (False, "seq regression ... already recorded True")
  ```
- **Expected:** a non-integer `seq` (JSON `true`) is rejected as malformed.
- **Actual:** `seq: true` is accepted (`True == 1`), persisted to the append-only
  ledger as the JSON literal `"seq": true` (corrupting the file's type schema),
  and — because `True == 1` — it **permanently blocks the honest gate from ever
  recording its real `seq = 1`** (refused as a "rollback/replay"), while the
  notary now vouches for the attacker's forged `hTrue` at that position.
- **Why it matters (the central question):** the docstring concedes a key-holder
  can *append monotonic heads*. This is **worse**: with one crafted boolean the
  attacker (who holds the shared key by design) silently **pre-empts a specific
  low seq the honest gate has not yet reached**, poisons that head, and turns the
  gate's fail-closed anchor into a self-inflicted DoS. On reload, `_recover`'s
  `int(rec["seq"])` (`notary.py:109`) coerces `true → 1`, masking that a
  non-integer ever entered the "append-only" record.
- **Fix:** `type(seq) is int` (reject `bool`) at both `:192` and `:207`.

### 2. [ESCAPE — CODE-BUG — HIGH] Recovery silently accepts a CONFLICTING hash at an already-recorded `(chain, seq)`, and desynchronizes `head()` vs `at()`
- **Attack:** A4 (`attack_recover_conflicting_hash`)
- **Root cause:** `authgate/notary.py:102-114` — `_recover` has **no conflict
  check**. For a duplicate `(chain, seq)` it blindly overwrites
  `self._at[(chain, seq)] = h` (last line wins) while `self._heads` only updates
  when `seq > last[0]` (first-seen-at-that-seq effectively wins for the head).
- **Repro:** ledger file with two lines `{"chain":"c","seq":5,"hash":"AAAA"}`
  and `{...,"hash":"BBBB"}`, then `NotaryLedger(path)`:
  - `head("c")  -> (5, "AAAA")`
  - `at("c", 5) -> "BBBB"`
- **Expected:** two different hashes claimed for the same `(chain, seq)` is
  *prima facie* evidence of tampering/crash and must be detected/refused.
- **Actual:** accepted silently, AND the notary's two internal indexes now
  **disagree about the hash at seq 5** — the auditor gets a different answer from
  `verify_against_anchor` (which compares the *head*) than from a point query
  `at()`. A rewrite of the "append-only" ledger that appends a second, forged
  line for an existing seq is thus laundered into an internally-inconsistent but
  non-erroring notary.
- **Fix:** in `_recover`, if `(chain, seq)` already in `self._at` with a
  different hash → raise (append-only invariant violated). `submit()` already
  can't create this at runtime (monotonic), but recovery is the trust boundary
  after a crash/rewrite and must be as strict as `HashChainedAudit._load_existing`.

### 3. [ESCAPE — CODE-BUG — MEDIUM] Torn last line (crash mid-append) bricks the notary on restart (availability)
- **Attack:** A5 (`attack_recover_partial_line`)
- **Root cause:** `authgate/notary.py:108` — `_recover` does `json.loads(line)`
  with no per-line guard. A partially-written final line (the exact crash the
  `fsync` at `:133` is meant to survive) raises `JSONDecodeError` from the
  constructor.
- **Repro:** ledger whose last line is `{"chain":"c","seq":1,"ha` (no newline),
  then `NotaryLedger(path)` → `JSONDecodeError('Unterminated string ...')`.
- **Expected:** a torn tail (append not yet completed) recovers to the last
  *complete* head; the notary restarts.
- **Actual:** the constructor raises; the notary **cannot start** until an
  operator hand-edits the ledger. `submit` fsyncs each record durably, but the
  writer can still die mid-`f.write` (the newline is written after the JSON), so
  a torn tail is a normal crash outcome — and it is unrecoverable without manual
  intervention. Note this is *distinct* from the documented SPOF limit: here the
  notary kills itself on its own valid crash state.
- **Fix:** wrap the per-line `json.loads` in try/except; a torn *final* line
  should be tolerated (truncate to last complete record); a torn *interior* line
  should still raise (genuine corruption). Writing `\n`+JSON atomically, or a
  length/CRC framing, also closes it.

### 4. [ESCAPE — CODE-BUG — MEDIUM] No per-request size cap → unbounded memory per connection
- **Attack:** A7 (`attack_huge_line_dos`)
- **Root cause:** `authgate/notary.py:155` — `for raw in self.rfile` reads until
  a newline with **no maximum line length**. One connection can stream arbitrary
  bytes (test sends 8 MiB in a single un-terminated "line") and the server
  buffers all of it in memory before parsing.
- **Repro:** send `{"op":"head","chain":"` + `"A"*8MiB` + `"}\n`; server accepts
  and buffers the whole line.
- **Expected:** oversized requests are rejected past a sane cap (heads are tiny:
  chain name + int + 64-hex hash + 64-hex MAC ≈ <300 bytes).
- **Actual:** no cap; N connections each streaming large lines = N × unbounded
  RAM. Cheap memory-exhaustion DoS from *any* client that can reach the port
  (the MAC gate is checked only *after* the full line is buffered and parsed).
- **Fix:** read with a bounded `readline(MAX_LINE)` and reject if no newline
  within the cap.

### 5. [ESCAPE — CODE-BUG — MEDIUM] No socket/read timeout → slow-loris pins worker threads indefinitely
- **Attack:** A8 (`attack_slowloris`)
- **Root cause:** `authgate/notary.py:165` — `NotaryServer` (ThreadingTCPServer)
  sets no `timeout` and the handler sets no per-socket read timeout. A client
  that opens a connection and never sends a newline holds its handler thread
  forever (`for raw in self.rfile` blocks in `recv`).
- **Repro:** open a socket, send `{"op":"head","chain":"c"` (no newline), hold.
  Other clients are still served (threaded), but the held thread never releases.
- **Expected:** idle/incomplete connections time out so worker threads and file
  descriptors are bounded.
- **Actual:** `server.timeout is None`; K idle connections pin K threads/fds
  until the OS or ulimit intervenes. Not a full outage (threaded), but an
  unbounded-resource DoS distinct from the documented "single notary is a SPOF"
  availability caveat.
- **Fix:** set a per-connection read timeout (e.g. `self.connection.settimeout`
  in `setup`, or `NotaryServer.timeout`), and drop connections that stall.

---

## CONTAINED (no escape) — what actually held

- **A1 MAC forgery / empty / missing MAC** — rejected by `hmac.compare_digest`
  (`notary.py:195`). Constant-time compare; forged/empty/None all → `ok:false`.
- **A2 MAC framing collision** — the collision is **real** (`_mac` joins fields
  with `\n`, so `("a",1,"b\n2\nQ")` and `("a\n1\nb",2,"Q")` share a MAC,
  `notary.py:62-65`) but is **NOT exploitable**: `dispatch` recomputes `expected`
  from the *submitted* fields, so a MAC only ever authenticates the exact tuple
  it was sent with. Latent canonicalization smell (length-prefix the fields to
  remove it), not a privilege escape. **Downgraded from a false-positive ESCAPE
  after review — flagged here for honesty.**
- **A6 concurrency** — `submit` is fully serialized under `self._lock`
  (`notary.py:122`). 12 threads × 60 racing seqs: no duplicate seq accepted,
  `head == max(accepted)`, monotonic invariant intact. No lost updates, no
  accepted regression.
- **A9 key-holder pre-empts a FUTURE seq** — the attacker CAN pin a forged hash
  at a higher seq (`submit('c',5,'FORGED5')` accepted), and the honest gate's
  later real seq 5 is then refused. This is **INHERENT-LIMIT**, not a code bug:
  the docstring (`notary.py:37-39`) states the HMAC does not authenticate the
  gate against its own attacker who holds the key. Crucially the notary stays
  **consistently monotonic** (post-pre-empt lower seqs 3,4 are correctly refused
  as regressions) and the gate's fail-closed `anchor` (`notary.py:255-258`)
  RAISES on the refused honest submit — the divergence *announces itself*, which
  is exactly the designed witness property. Contained by design.
- **A10 chain-name newline injection** — `json.dumps` escapes the newline in the
  ledger value (`notary.py:131`); no phantom record forged on replay.
- **A11 fail-open probe** — every malformed body (non-dict, missing fields,
  string seq, int hash, empty, non-JSON) → `ok:false` before reaching the ledger;
  ledger stays empty. Type guards + MAC gate (`notary.py:188-210`) hold.

---

## SUMMARY TABLE

| # | Attack | Verdict | Class | Severity |
|---|--------|---------|-------|----------|
| A3 | bool seq type-confusion | ESCAPE | CODE-BUG | HIGH |
| A4 | recovery conflicting hash / index desync | ESCAPE | CODE-BUG | HIGH |
| A5 | torn last line bricks restart | ESCAPE | CODE-BUG | MEDIUM |
| A7 | unbounded line memory DoS | ESCAPE | CODE-BUG | MEDIUM |
| A8 | slow-loris pins threads | ESCAPE | CODE-BUG | MEDIUM |
| A1 | MAC forgery | PASS | — | — |
| A2 | MAC framing collision | PASS (latent) | CODE-SMELL | LOW |
| A6 | concurrency race | PASS | — | — |
| A9 | key-holder future-seq pre-empt | PASS | INHERENT-LIMIT | — |
| A10 | chain-name injection | PASS | — | — |
| A11 | fail-open bodies | PASS | — | — |

**Most damaging: A3.** A single boolean `seq` (which the gate's own key-holding
attacker can send) both corrupts the append-only ledger's type schema and
silently pre-empts/DoSes a specific integer seq the honest gate has not yet
reached — a monotonic-witness bypass the design is explicitly meant to prevent,
fixed by one line (`type(seq) is int`).
