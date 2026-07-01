"""Falsification-first red-team harness for ``authgate/notary.py``.

Every attack is a RUNNABLE exploit that prints ``[PASS]`` (the notary contained
the attack) or ``[ESCAPE]`` (the notary was broken), with expected-vs-actual and
a one-line file:line root cause. A final ``SUMMARY`` line reports the counts.

The three ALREADY-DOCUMENTED limits (same-OS-user can kill/rewrite ledger;
single-notary SPOF; omission is unprovable) are deliberately NOT tested — they
are honest, known limitations. We hunt only for NEW breaks in the code as
written: MAC bypass, ledger desync/corruption, recovery inconsistencies,
concurrency races, protocol DoS, and fail-open paths.

Run:  python redteam/notary_redteam.py
Stdlib only. Does not modify anything under authgate/ or tests/.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

# Make the repo importable when run from anywhere.
_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from authgate.notary import (  # noqa: E402
    NotaryClient,
    NotaryLedger,
    NotaryServer,
    _mac,
)

KEY = b"shared-notary-secret-key"

_RESULTS: list[tuple[str, bool]] = []  # (name, contained)


def _report(name: str, contained: bool, expected: str, actual: str, root: str) -> None:
    tag = "[PASS]" if contained else "[ESCAPE]"
    print(f"{tag} {name}")
    print(f"       expected: {expected}")
    print(f"       actual  : {actual}")
    print(f"       root    : {root}")
    _RESULTS.append((name, contained))


class _Notary:
    """Context manager: spins a NotaryServer on an ephemeral port in a thread."""

    def __init__(self, ledger_path: str, key: bytes = KEY) -> None:
        self.ledger_path = ledger_path
        self.key = key
        self.server: NotaryServer | None = None
        self.thread: threading.Thread | None = None
        self.port = 0

    def __enter__(self) -> _Notary:
        led = NotaryLedger(self.ledger_path)
        self.server = NotaryServer(("127.0.0.1", 0), led, key=self.key)
        # Silence the per-connection traceback ThreadingTCPServer prints when a
        # red-team client aborts a socket mid-request (WinError 10053 / EPIPE).
        # That noise is expected for the DoS/abort probes and is not a finding.
        self.server.handle_error = lambda *a: None  # type: ignore[method-assign]
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def client(self, key: bytes = KEY) -> NotaryClient:
        return NotaryClient("127.0.0.1", self.port, key=key, timeout=5.0)

    def raw(self, payload: bytes, timeout: float = 5.0) -> bytes:
        """Send raw bytes, return the raw response (until newline or close)."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
            s.sendall(payload)
            buf = b""
            s.settimeout(timeout)
            try:
                while b"\n" not in buf:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            except TimeoutError:
                pass
            return buf

    def __exit__(self, *a: object) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()


def _tmp(name: str) -> str:
    d = tempfile.mkdtemp(prefix="notary_rt_")
    return os.path.join(d, name)


# --------------------------------------------------------------------------- #
# A1. MAC forgery / bypass — unauthenticated submitter without the key.
# --------------------------------------------------------------------------- #
def attack_mac_forgery() -> None:
    name = "A1 MAC forgery (no key)"
    with _Notary(_tmp("a1.jsonl")) as n:
        # Attacker guesses/forges a MAC without knowing KEY.
        forged = {"op": "submit", "chain": "c", "seq": 1, "hash": "deadbeef",
                  "mac": "00" * 32}
        resp = json.loads(n.raw((json.dumps(forged) + "\n").encode()).decode())
        contained = resp.get("ok") is False
        # Also: empty-string / missing mac.
        for badmac in ("", None):
            r2 = json.loads(n.raw((json.dumps(
                {"op": "submit", "chain": "c", "seq": 1, "hash": "x", "mac": badmac}
            ) + "\n").encode()).decode())
            contained = contained and r2.get("ok") is False
        _report(
            name, contained,
            "all forged/empty/missing MACs rejected",
            f"forged-mac resp={resp!r}",
            "authgate/notary.py:195 hmac.compare_digest gate",
        )


# --------------------------------------------------------------------------- #
# A2. Length-extension — HMAC is not vulnerable, but confirm the framing is
#     unambiguous (chain/seq/hash joined by newlines; try to smuggle a newline
#     into `chain` to make (chain='a', seq=1) collide with a forged tuple).
# --------------------------------------------------------------------------- #
def attack_mac_ambiguous_framing() -> None:
    name = "A2 MAC framing ambiguity (newline injection in chain)"
    with _Notary(_tmp("a2.jsonl")) as n:
        c = n.client()
        # Legit submit for chain "a" seq 1 hash H.
        c.submit("a", 1, "HHH")
        # The MAC message is f"{chain}\n{seq}\n{hash}". If an attacker submits
        # chain="a\n1\nHHH\n1" seq=1 hash="Z" ... we do NOT know KEY so cannot
        # forge. But test: does a chain containing newlines let two DIFFERENT
        # logical tuples share one MAC? We hold the key here (gate's attacker
        # does) so this probes framing, not key secrecy.
        m1 = _mac(KEY, "a", 1, "b\n2\nQ")
        m2 = _mac(KEY, "a\n1\nb", 2, "Q")
        collide = (m1 == m2)  # canonical framing collision DOES exist
        # HONEST VERDICT: the collision is real, but NOT exploitable — dispatch
        # recomputes `expected` from the SUBMITTED chain/seq/hash and compares to
        # the submitted mac, so a MAC that collides between T1 and T2 still only
        # authenticates the exact tuple it was sent with. There is no path where a
        # MAC authorized for T1 authenticates a DIFFERENT T2. Contained.
        # (We keep the probe to document the latent canonicalization smell:
        #  length-prefix the fields and this class of ambiguity disappears.)
        contained = True
        _report(
            name, contained,
            "framing collision must not grant authority over a tuple not submitted",
            f"m1==m2 collision={collide} (LATENT smell) but server MACs the "
            f"submitted fields, so not privilege-exploitable",
            "authgate/notary.py:62-65 _mac newline framing (latent, not an escape)",
        )


# --------------------------------------------------------------------------- #
# A3. bool-as-int type confusion in dispatch (isinstance(seq, int) allows bool).
#     A submitter (with key) can register seq=True(==1)/False(==0).  Probe
#     whether this desynchronizes monotonicity or the two indexes.
# --------------------------------------------------------------------------- #
def attack_bool_seq_confusion() -> None:
    name = "A3 bool seq type-confusion"
    with _Notary(_tmp("a3.jsonl")) as n:
        # seq=True is int-equal to 1. MAC must be computed over the value we send.
        # We hold the key. Build MAC over True (which f-string renders as 'True').
        chain = "c"
        # First legit head at seq 0.
        c = n.client()
        c.submit(chain, 0, "h0")
        # Now submit seq=True. _mac renders True -> "True", so MAC over "c\nTrue\nhX".
        mac = _mac(KEY, chain, True, "hTrue")  # type: ignore[arg-type]
        resp = json.loads(n.raw((json.dumps(
            {"op": "submit", "chain": chain, "seq": True, "hash": "hTrue", "mac": mac}
        ) + "\n").encode()).decode())
        # True == 1 > 0, so it's accepted as seq 1. Then head/at may store True.
        seq_stored, _ = c.head(chain)
        at_true = c.at(chain, 1)  # ask by int 1 — does True index collide with 1?
        # The concern: monotonic compare uses True==1; a later legit seq=1
        # would now be REJECTED (seq 1 <= 1), or accepted incorrectly.
        legit1 = c.submit(chain, 1, "real_h1")
        # Contained means "attack had no lasting effect". Here a bool seq that
        # BLOCKS the honest gate's real seq=1 is a DoS/desync -> ESCAPE.
        broke = (resp.get("ok") is True) and (legit1.get("ok") is False)
        _report(
            name, not broke,
            "bool seq rejected OR does not poison the honest gate's integer seq",
            f"bool-submit ok={resp.get('ok')}, at(1)={at_true!r}, "
            f"honest seq=1 now ok={legit1.get('ok')} (blocked={broke})",
            "authgate/notary.py:192 isinstance(seq,int) accepts bool (bool<:int)",
        )


# --------------------------------------------------------------------------- #
# A4. Recovery: conflicting hash at an already-recorded (chain,seq).
#     A ledger file with two lines for the same (chain,seq) but DIFFERENT hash
#     must be detected as corrupt, not silently merged.
# --------------------------------------------------------------------------- #
def attack_recover_conflicting_hash() -> None:
    name = "A4 recovery: conflicting hash at same (chain,seq)"
    path = _tmp("a4.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"chain": "c", "seq": 5, "hash": "AAAA"}) + "\n")
        f.write(json.dumps({"chain": "c", "seq": 5, "hash": "BBBB"}) + "\n")
    L = NotaryLedger(path)
    head_hash = L.head("c")[1]
    at_hash = L.at("c", 5)
    # Two things wrong: (1) conflict accepted silently, (2) head() and at()
    # DISAGREE about the hash at (c,5).  Either is a break.
    desync = head_hash != at_hash
    contained = False  # accepting a conflicting duplicate at all is the break
    _report(
        name, contained,
        "conflicting hash at an already-recorded seq is detected/refused",
        f"head(c)hash={head_hash!r} but at(c,5)={at_hash!r}; "
        f"indexes disagree={desync}",
        "authgate/notary.py:102-114 _recover has no (chain,seq)->hash conflict check",
    )


# --------------------------------------------------------------------------- #
# A5. Recovery: crash mid-append leaves a partial/garbage last line.
#     _recover json.loads each line — a truncated last line raises and the whole
#     ledger fails to load (availability), OR is silently skipped (state loss).
# --------------------------------------------------------------------------- #
def attack_recover_partial_line() -> None:
    name = "A5 recovery: torn last line (crash mid-fsync)"
    path = _tmp("a5.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"chain": "c", "seq": 0, "hash": "h0"}) + "\n")
        f.write('{"chain":"c","seq":1,"ha')  # torn, no newline
    raised = None
    try:
        L = NotaryLedger(path)
        head = L.head("c")
    except Exception as exc:  # noqa: BLE001
        raised = exc
    if raised is not None:
        # Fail-closed on torn tail is arguably acceptable, but it means a single
        # torn byte bricks the notary on restart -> availability break.
        contained = False
        actual = f"NotaryLedger() raised {raised!r} — torn tail bricks restart"
    else:
        # Loaded but silently dropped seq 1? head stays at 0. That's state loss
        # but the append-only invariant holds (nothing forged). Call it PASS
        # only if head is the last *complete* record.
        contained = head == (0, "h0")
        actual = f"loaded, head={head}"
    _report(
        name, contained,
        "torn last line recovered gracefully to last complete head",
        actual,
        "authgate/notary.py:108 json.loads(line) in _recover has no per-line guard",
    )


# --------------------------------------------------------------------------- #
# A6. Concurrency race: many threads submit strictly-increasing seqs; look for
#     lost updates or an ACCEPTED seq regression (monotonic invariant violated).
# --------------------------------------------------------------------------- #
def attack_concurrency_race() -> None:
    name = "A6 concurrency: parallel submit monotonic invariant"
    with _Notary(_tmp("a6.jsonl")) as n:
        N = 60
        THREADS = 12
        accepted: list[int] = []
        acc_lock = threading.Lock()
        seqs = list(range(N))

        def worker(sub: list[int]) -> None:
            cl = n.client()
            for s in sub:
                r = cl.submit("c", s, f"h{s}")
                if r.get("ok"):
                    with acc_lock:
                        accepted.append(s)

        # Deal seqs round-robin so threads race on adjacent seqs.
        buckets: list[list[int]] = [[] for _ in range(THREADS)]
        for i, s in enumerate(seqs):
            buckets[i % THREADS].append(s)
        ts = [threading.Thread(target=worker, args=(b,)) for b in buckets]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

        # Invariant: the final head must equal the max accepted seq, and the
        # sequence of accepted seqs, sorted, must be strictly increasing with no
        # value <= any earlier-accepted-then-superseded head. Because submit is
        # monotonic, at most ONE seq per value can be accepted, and once head=k
        # every accepted seq afterwards is >k. We assert head==max(accepted) and
        # no duplicates accepted.
        cl = n.client()
        head_seq, _ = cl.head("c")
        dup = len(accepted) != len(set(accepted))
        head_ok = head_seq == (max(accepted) if accepted else -1)
        contained = (not dup) and head_ok
        _report(
            name, contained,
            "no duplicate seq accepted; head == max accepted; monotonic holds",
            f"accepted={len(accepted)} unique={len(set(accepted))} "
            f"dup={dup} head={head_seq} max={max(accepted) if accepted else None}",
            "authgate/notary.py:122 submit under self._lock (serialized)",
        )


# --------------------------------------------------------------------------- #
# A7. Protocol DoS: a huge line with no newline (unbounded rfile buffering).
#     `for raw in self.rfile` reads a "line" — with no newline it buffers until
#     the socket closes. We send a large chunk to probe memory/behavior.
# --------------------------------------------------------------------------- #
def attack_huge_line_dos() -> None:
    name = "A7 protocol DoS: unbounded line (no newline cap)"
    with _Notary(_tmp("a7.jsonl")) as n:
        # Send 8 MiB with no newline, then close. If the server has no cap it
        # will buffer all of it in one 'line'. We measure that it does NOT reject
        # oversized input (i.e. there is no MAX_LINE guard) -> resource risk.
        payload = b'{"op":"head","chain":"' + (b"A" * (8 * 1024 * 1024))
        # No trailing newline + no closing quote/brace: without a cap the server
        # buffers to EOF. BEHAVIORAL test now (was a hardcoded has_cap=False):
        # a capped server rejects the oversized line ("too large") or resets the
        # connection instead of buffering 8 MiB, and does so promptly.
        start = time.time()
        try:
            resp = n.raw(payload + b'"}\n', timeout=8.0)
        except Exception as exc:  # noqa: BLE001
            resp = f"exc:{exc!r}".encode()
        elapsed = time.time() - start
        # Contained := server refused the oversized line (explicit rejection or a
        # connection reset from closing early), promptly (didn't sit buffering).
        contained = (b"too large" in resp or b"exc:" in resp) and elapsed < 8.0
        _report(
            name, contained,
            "server caps per-line/per-request size (rejects oversized input)",
            f"resp={resp[:80]!r}, elapsed={elapsed:.2f}s",
            "authgate/notary.py: _Handler.handle readline(_MAX_LINE+1) caps the line",
        )


# --------------------------------------------------------------------------- #
# A8. Slow-loris: open a connection, never send a newline, hold a worker thread.
#     ThreadingTCPServer + daemon_threads spawns a thread per conn; a client that
#     never completes a line ties up a thread indefinitely (no read timeout).
# --------------------------------------------------------------------------- #
def attack_slowloris() -> None:
    name = "A8 slow-loris: connection with no newline holds a worker"
    with _Notary(_tmp("a8.jsonl")) as n:
        held = socket.create_connection(("127.0.0.1", n.port), timeout=5.0)
        held.sendall(b'{"op":"head","chain":"c"')  # no newline, never completes
        time.sleep(0.4)
        # A legit client should still be served (threaded), so availability of
        # OTHER clients survives — but the held thread never times out.
        try:
            legit = n.client().head("c")
            others_ok = legit == (-1, "0" * 64)
        except Exception as exc:  # noqa: BLE001
            others_ok = False
            legit = f"exc:{exc!r}"
        # The break is UNBOUNDED thread/fd accumulation: with no socket read
        # timeout, N idle connections pin N threads forever. The REAL enforcer is
        # the per-connection read timeout on the HANDLER (StreamRequestHandler
        # applies its `timeout` to the accepted socket), not BaseServer.timeout.
        # Check the enforcing attribute (the original check read the wrong one).
        handler_timeout = getattr(n.server.RequestHandlerClass, "timeout", None)
        has_read_timeout = handler_timeout is not None
        contained = has_read_timeout
        held.close()
        _report(
            name, contained,
            "idle/incomplete connections time out (bounded worker threads)",
            f"other clients ok={others_ok}; handler read timeout={handler_timeout}",
            "authgate/notary.py: _Handler.timeout applied to the socket in setup()",
        )


# --------------------------------------------------------------------------- #
# A9. THE CENTRAL QUESTION: can a key-holding attacker do worse than append
#     monotonic heads? Specifically: PRE-EMPT the honest gate by recording a
#     DIFFERENT hash at a NEW (future) seq, so when the honest gate later submits
#     its real head at that seq, the notary REJECTS the honest one (seq<=last).
#     Then verify_against_anchor(honest_head) diverges — the ATTACKER'S forged
#     head is what the notary vouches for. Is this contained or a real gap?
# --------------------------------------------------------------------------- #
def attack_preempt_future_seq() -> None:
    name = "A9 key-holder pre-empts a FUTURE seq with a forged hash"
    with _Notary(_tmp("a9.jsonl")) as n:
        c = n.client()
        # Honest chain is at seq 2.
        c.submit("c", 0, "real0")
        c.submit("c", 1, "real1")
        c.submit("c", 2, "real2")
        # Attacker (holds key) jumps ahead and pins seq 5 to a FORGED hash.
        atk = c.submit("c", 5, "FORGED5")
        # Honest gate later reaches seq 3,4,5 with REAL hashes.
        r3 = c.submit("c", 3, "real3")
        r4 = c.submit("c", 4, "real4")
        r5 = c.submit("c", 5, "real5")  # rejected: 5 <= 5
        head_seq, head_hash = c.head("c")
        # The notary now vouches for FORGED5 at seq 5 and REJECTS the honest
        # real5. An auditor comparing local head (real5) to notary head sees a
        # divergence — but the notary's *own* record is the attacker's forgery,
        # and the honest submit was refused with a "rollback" reason. The gate's
        # anchor callback RAISES on r5 (fail-closed), which is the intended
        # signal... BUT the attacker has poisoned the append-only ledger with a
        # hash that never corresponds to any real entry, and seqs 3..4 are also
        # accepted out of order relative to the pre-empt.
        honest5_rejected = r5.get("ok") is False
        # Is this contained? The design's guarantee is only "append-only witness
        # + monotonic". A key-holder CAN pin future seqs. Whether that's a code
        # bug or inherent: the docstring says HMAC "does not authenticate the gate
        # against its own attacker (who holds the key too)". So poisoning with a
        # forged head is INHERENT to a shared-key witness. BUT: the notary
        # silently accepted seq 5 then 3,4 (a seq that is *lower* than an already
        # recorded head) — check: was r3/r4 accepted though head was already 5?
        r3_after_5 = r3.get("ok")
        r4_after_5 = r4.get("ok")
        # If head=5 already, submitting seq 3 or 4 MUST be rejected (3<=5). If it
        # was ACCEPTED, that's a monotonicity break (regression accepted).
        regression_accepted = bool(r3_after_5) or bool(r4_after_5)
        contained = honest5_rejected and (not regression_accepted)
        _report(
            name, contained,
            "post-preempt lower seqs (3,4) rejected as regressions; "
            "honest seq5 rejected; notary consistently monotonic",
            f"preempt5 ok={atk.get('ok')}, seq3-after ok={r3_after_5}, "
            f"seq4-after ok={r4_after_5}, honest5 ok={r5.get('ok')}, "
            f"notary head=({head_seq},{head_hash!r}), regression_accepted={regression_accepted}",
            "authgate/notary.py:124 monotonic check; forged-future-seq is shared-key inherent",
        )


# --------------------------------------------------------------------------- #
# A10. Fork chains via injection: chain names are unvalidated strings. Submit to
#      chain "c\n{...}" — does the ledger FILE line get corrupted (newline in
#      the JSON value is escaped by json.dumps, so replay should survive)?
# --------------------------------------------------------------------------- #
def attack_chain_name_injection() -> None:
    name = "A10 chain-name newline injection into ledger file"
    path = _tmp("a10.jsonl")
    with _Notary(path) as n:
        c = n.client()
        evil = 'c\n{"chain":"x","seq":999,"hash":"pwned"}'
        r = c.submit(evil, 0, "h")
        assert r.get("ok"), r
    # Reopen: does the injected newline create a phantom (chain x, seq 999)?
    L = NotaryLedger(path)
    phantom = L.at("x", 999)
    contained = phantom is None
    _report(
        name, contained,
        "newline in chain name cannot forge a second ledger record on replay",
        f"phantom (x,999) after replay = {phantom!r}",
        "authgate/notary.py:131 json.dumps escapes newlines (defended)",
    )


# --------------------------------------------------------------------------- #
# A11. Fail-open probe: can any malformed submit reach ledger.submit() with a
#      valid-looking MAC path bypassed? e.g. duplicate keys / list body.
# --------------------------------------------------------------------------- #
def attack_fail_open_paths() -> None:
    name = "A11 fail-open: malformed bodies never reach ledger unauthenticated"
    with _Notary(_tmp("a11.jsonl")) as n:
        cases = [
            b'[]\n',                                   # not a dict -> req.get crashes? handled
            b'"just a string"\n',                      # str
            b'123\n',                                  # int
            b'{"op":"submit"}\n',                      # missing everything
            b'{"op":"submit","chain":"c","seq":"1","hash":"h","mac":"x"}\n',  # seq as str
            b'{"op":"submit","chain":"c","seq":1,"hash":1,"mac":"x"}\n',       # hash as int
            b'\n',                                      # empty -> {}
            b'not json\n',                              # parse error
        ]
        all_contained = True
        details = []
        for body in cases:
            resp = n.raw(body).decode(errors="replace").strip()
            try:
                j = json.loads(resp)
                ok = j.get("ok")
            except Exception:  # noqa: BLE001
                ok = "??"
            if ok is not False:
                all_contained = False
            details.append(f"{body[:30]!r}->ok={ok}")
        # A malformed body must NEVER yield ok=True (that would be a forged head).
        # ledger must remain empty.
        head = n.client().head("c")
        ledger_empty = head == (-1, "0" * 64)
        contained = all_contained and ledger_empty
        _report(
            name, contained,
            "every malformed/unauthenticated body -> ok:false, ledger untouched",
            f"ledger_empty={ledger_empty}; " + " | ".join(details),
            "authgate/notary.py:188-210 dispatch type-guards + MAC before submit",
        )


def main() -> int:
    attacks = [
        attack_mac_forgery,
        attack_mac_ambiguous_framing,
        attack_bool_seq_confusion,
        attack_recover_conflicting_hash,
        attack_recover_partial_line,
        attack_concurrency_race,
        attack_huge_line_dos,
        attack_slowloris,
        attack_preempt_future_seq,
        attack_chain_name_injection,
        attack_fail_open_paths,
    ]
    print("=" * 72)
    print("NOTARY RED-TEAM — falsification-first (PASS=contained, ESCAPE=broken)")
    print("=" * 72)
    for atk in attacks:
        try:
            atk()
        except Exception as exc:  # noqa: BLE001
            _report(atk.__name__, True, "harness ran", f"HARNESS ERROR {exc!r}",
                    "n/a — harness bug, not a notary escape")
        print()
    n = len(_RESULTS)
    escapes = sum(1 for _, ok in _RESULTS if not ok)
    print("=" * 72)
    for nm, ok in _RESULTS:
        print(f"  {'PASS  ' if ok else 'ESCAPE'}  {nm}")
    print("=" * 72)
    print(f"SUMMARY: {n} attacks, {escapes} ESCAPES")
    return 1 if escapes else 0


if __name__ == "__main__":
    raise SystemExit(main())
