"""Independent audit-head notary — the out-of-process trust root for #3.

`HashChainedAudit` proves *tamper-detection* only against an attacker outside its
process: an in-process forger who owns the log file recomputes every hash and
`verify()` passes (see `audit_chain.verify_against_anchor` for why an external
head is required). This module is that external head, made real: a **separate
process** that keeps an **append-only ledger of published chain heads**.

The security argument, stated honestly:

  * The gate process, on every recorded entry, submits its new head
    ``(chain, seq, entry_hash)`` to the notary (via the `anchor` sink of
    `HashChainedAudit`).
  * The notary appends it durably and enforces **monotonic seq per chain**: a
    submission whose ``seq`` is not strictly greater than the last it recorded
    is REJECTED (a rollback/truncation attempt announces itself).
  * An auditor later asks the notary for the head it holds and compares it to
    the local chain (`verify_against_anchor`). An attacker who truncated or
    rewrote the local log to drop entry *k* cannot also remove seq *k*'s head
    from the notary's append-only ledger → the divergence is provable.

What this **does not** do — and why (do not oversell it):

  * **Same trust domain defeats it.** If the notary runs as the *same OS user*
    on the *same box* as a compromised gate, that user can kill it or rewrite
    its ledger file. The notary only buys anything when it runs in a trust
    domain the gate's attacker cannot reach (different user / host / append-only
    storage). The code supports that (plain TCP, separate ledger file); the
    deployment must actually separate them.
  * **Availability is single-point.** One notary is a SPOF. Quorum / multiple
    witnesses / a transparency log are later stages, not this one.
  * **Omission is still unprovable.** If the attacker never calls
    ``record()``/never anchors, the notary sees nothing. You cannot prove a
    thing was never logged. That is the #3b limit and no notary closes it.

Authentication is an HMAC over each submission with a shared key: it stops an
*unrelated* process from injecting bogus heads. It does **not** authenticate the
gate against its own attacker (who holds the key too) — that is not its job; the
append-only witness property is.

Stdlib only: ``socket``/``socketserver``, ``hmac``, ``hashlib``, ``json``,
``threading``, ``pathlib``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import socketserver
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

GENESIS_PREV_HASH = "0" * 64
_ENV_KEY = "AUTHGATE_NOTARY_KEY"
# A head submission is ~200 bytes; cap a single protocol line generously so a
# client cannot force the server to buffer an unbounded line (memory DoS).
_MAX_LINE = 64 * 1024
# Per-connection idle/read timeout: an incomplete (slow-loris) connection is
# dropped rather than pinning a worker thread + fd indefinitely.
_CONN_TIMEOUT = 10.0


def _is_seq(value: Any) -> bool:
    """A valid seq is a *plain* int. ``bool`` is an int subclass in Python, so
    ``isinstance(x, int)`` would accept ``True``/``False`` — which then compare
    as ``1``/``0`` and can pre-empt/poison a real integer seq. Reject it."""
    return type(value) is int


def _mac(key: bytes, chain: str, seq: int, entry_hash: str) -> str:
    """Deterministic HMAC-SHA256 over a submission's identifying tuple."""
    msg = f"{chain}\n{seq}\n{entry_hash}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _resolve_key(key: bytes | str | None) -> bytes:
    """Resolve the shared HMAC key from arg or the AUTHGATE_NOTARY_KEY env."""
    if key is None:
        env = os.environ.get(_ENV_KEY)
        if not env:
            raise ValueError(
                f"no notary key: pass one or set ${_ENV_KEY} (both gate and "
                f"notary must share it)"
            )
        key = env
    return key.encode("utf-8") if isinstance(key, str) else key


# --------------------------------------------------------------------------- #
# Ledger — append-only head store (the durable trust root state)
# --------------------------------------------------------------------------- #
class NotaryLedger:
    """Append-only, per-chain-monotonic store of published audit heads.

    Thread-safe (the server is threaded). Durable: every accepted head is
    ``fsync``'d before it is acknowledged. Recoverable: on construction the
    existing ledger file is replayed to rebuild in-memory state.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # chain -> (last_seq, last_hash); and (chain, seq) -> hash for point queries.
        self._heads: dict[str, tuple[int, str]] = {}
        self._at: dict[tuple[str, int], str] = {}
        if self._path.exists():
            self._recover()

    def _recover(self) -> None:
        lines = self._path.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (ValueError, TypeError):
                # Only the FINAL line can be legitimately torn — a crash mid-append,
                # which is exactly the window fsync bounds. A corrupt EARLIER line is
                # tampering/corruption: refuse to resume (mirrors HashChainedAudit).
                if idx == len(lines) - 1:
                    continue
                raise ValueError(f"corrupt notary ledger at line {idx}: not JSON") from None
            chain, seq, h = rec["chain"], rec["seq"], rec["hash"]
            if not _is_seq(seq):
                raise ValueError(f"corrupt notary ledger at line {idx}: seq is not a plain int")
            # An append-only witness must never hold two DIFFERENT hashes at the
            # same (chain, seq); silently loading both would desync head()/at()
            # and launder a forged head. Refuse.
            prior = self._at.get((chain, seq))
            if prior is not None and prior != h:
                raise ValueError(
                    f"conflicting notary ledger: chain '{chain}' seq {seq} "
                    f"recorded with two different hashes"
                )
            last = self._heads.get(chain)
            # The ledger is append-only; on replay the highest seq wins as head.
            if last is None or seq > last[0]:
                self._heads[chain] = (seq, h)
            self._at[(chain, seq)] = h

    def submit(self, chain: str, seq: int, entry_hash: str) -> tuple[bool, str]:
        """Record a head. Enforces strictly-increasing seq per chain.

        Returns ``(accepted, reason)``. A non-increasing seq is refused — that is
        the signal of a rollback/truncation attempt, not a normal event.
        """
        if not _is_seq(seq):
            return False, "seq must be a plain int (bool/other refused)"
        with self._lock:
            last = self._heads.get(chain)
            if last is not None and seq <= last[0]:
                return False, (
                    f"seq regression for chain '{chain}': got {seq}, "
                    f"already recorded {last[0]} (rollback/replay refused)"
                )
            rec = {"chain": chain, "seq": seq, "hash": entry_hash}
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._heads[chain] = (seq, entry_hash)
            self._at[(chain, seq)] = entry_hash
            return True, "ok"

    def head(self, chain: str) -> tuple[int, str]:
        """Latest recorded ``(seq, hash)`` for a chain; ``(-1, GENESIS)`` if none."""
        with self._lock:
            return self._heads.get(chain, (-1, GENESIS_PREV_HASH))

    def at(self, chain: str, seq: int) -> str | None:
        """Recorded hash for a specific ``(chain, seq)``, or None."""
        with self._lock:
            return self._at.get((chain, seq))


# --------------------------------------------------------------------------- #
# Server — a separate process speaking newline-delimited JSON
# --------------------------------------------------------------------------- #
class _Handler(socketserver.StreamRequestHandler):
    # Per-connection read timeout: StreamRequestHandler.setup() applies this to
    # the accepted socket, so a slow-loris/incomplete connection cannot pin a
    # worker thread and fd forever. This handler attribute is the REAL enforcer.
    timeout = _CONN_TIMEOUT

    def handle(self) -> None:
        server: NotaryServer = self.server  # type: ignore[assignment]
        try:
            while True:
                # Bounded read: readline(_MAX_LINE + 1) buffers at most that many
                # bytes, so an un-terminated/huge line can't exhaust memory.
                raw = self.rfile.readline(_MAX_LINE + 1)
                if not raw:
                    return  # EOF
                if len(raw) > _MAX_LINE:
                    self._respond({"ok": False, "reason": "request line too large"})
                    return
                try:
                    req = json.loads(raw.decode("utf-8").strip() or "{}")
                    resp = server.dispatch(req)
                except Exception as exc:  # noqa: BLE001 — never crash the connection.
                    resp = {"ok": False, "reason": f"bad request: {exc!r}"}
                self._respond(resp)
        except (TimeoutError, ConnectionError, OSError):
            return  # drop slow/broken connections cleanly

    def _respond(self, resp: dict[str, Any]) -> None:
        self.wfile.write((json.dumps(resp) + "\n").encode("utf-8"))
        self.wfile.flush()


class NotaryServer(socketserver.ThreadingTCPServer):
    """Threaded TCP notary. Run it in its own process/trust domain.

    Protocol (one JSON object per line, one JSON response per line):
      submit: {"op":"submit","chain":s,"seq":i,"hash":s,"mac":hex}
              -> {"ok":true,"seq":i,"hash":s} | {"ok":false,"reason":s}
      head:   {"op":"head","chain":s}   -> {"ok":true,"seq":i,"hash":s}
      at:     {"op":"at","chain":s,"seq":i} -> {"ok":true,"hash":s|null}
    """

    allow_reuse_address = True
    daemon_threads = True
    # Mirror the handler's read timeout at the server level too, so the value is
    # discoverable from the server object. (Enforcement is the handler socket
    # timeout above; this is the visible knob.)
    timeout = _CONN_TIMEOUT

    def __init__(
        self,
        server_address: tuple[str, int],
        ledger: NotaryLedger,
        key: bytes | str | None = None,
    ) -> None:
        super().__init__(server_address, _Handler)
        self.ledger = ledger
        self._key = _resolve_key(key)

    def dispatch(self, req: dict[str, Any]) -> dict[str, Any]:
        op = req.get("op")
        if op == "submit":
            chain, seq, h, mac = req.get("chain"), req.get("seq"), req.get("hash"), req.get("mac")
            if not isinstance(chain, str) or not _is_seq(seq) or not isinstance(h, str):
                return {"ok": False, "reason": "submit: missing/typed chain|seq|hash"}
            expected = _mac(self._key, chain, seq, h)
            if not isinstance(mac, str) or not hmac.compare_digest(expected, mac):
                return {"ok": False, "reason": "submit: bad MAC (unauthenticated submitter)"}
            ok, reason = self.ledger.submit(chain, seq, h)
            return {"ok": ok, "seq": seq, "hash": h} if ok else {"ok": False, "reason": reason}
        if op == "head":
            chain = req.get("chain")
            if not isinstance(chain, str):
                return {"ok": False, "reason": "head: missing chain"}
            seq, h = self.ledger.head(chain)
            return {"ok": True, "seq": seq, "hash": h}
        if op == "at":
            chain, seq = req.get("chain"), req.get("seq")
            if not isinstance(chain, str) or not _is_seq(seq):
                return {"ok": False, "reason": "at: missing/typed chain|seq"}
            return {"ok": True, "hash": self.ledger.at(chain, seq)}
        return {"ok": False, "reason": f"unknown op {op!r}"}


# --------------------------------------------------------------------------- #
# Client — used by the gate (submit) and auditors (head/at)
# --------------------------------------------------------------------------- #
class NotaryClient:
    """Minimal synchronous client. One short-lived connection per call."""

    def __init__(self, host: str, port: int, key: bytes | str | None = None, timeout: float = 5.0) -> None:
        self._addr = (host, port)
        self._key = _resolve_key(key)
        self._timeout = timeout

    def _rpc(self, req: dict[str, Any]) -> dict[str, Any]:
        with socket.create_connection(self._addr, timeout=self._timeout) as s:
            s.sendall((json.dumps(req) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        return json.loads(buf.decode("utf-8").strip() or "{}")

    def submit(self, chain: str, seq: int, entry_hash: str) -> dict[str, Any]:
        mac = _mac(self._key, chain, seq, entry_hash)
        return self._rpc({"op": "submit", "chain": chain, "seq": seq, "hash": entry_hash, "mac": mac})

    def head(self, chain: str) -> tuple[int, str]:
        r = self._rpc({"op": "head", "chain": chain})
        return int(r.get("seq", -1)), r.get("hash", GENESIS_PREV_HASH)

    def at(self, chain: str, seq: int) -> str | None:
        return self._rpc({"op": "at", "chain": chain, "seq": seq}).get("hash")


def make_anchor(client: NotaryClient, chain: str) -> Callable[[int, str], None]:
    """Build an ``anchor`` sink for ``HashChainedAudit(path, anchor=...)``.

    Fail-closed: if the notary rejects the head (seq regression) or is
    unreachable, the callback RAISES, so an opt-in operator who wired an anchor
    learns immediately rather than silently losing tamper-evidence.
    """

    def _anchor(seq: int, entry_hash: str) -> None:
        resp = client.submit(chain, seq, entry_hash)
        if not resp.get("ok"):
            raise RuntimeError(f"notary rejected head seq={seq}: {resp.get('reason')}")

    return _anchor


def _main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Run the AuthGate audit-head notary.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8931)
    ap.add_argument("--ledger", default="notary_ledger.jsonl")
    ap.add_argument("--key", default=None, help=f"shared HMAC key (or ${_ENV_KEY})")
    args = ap.parse_args(argv)
    server = NotaryServer((args.host, args.port), NotaryLedger(args.ledger), key=args.key)
    print(f"notary listening on {args.host}:{args.port}, ledger={args.ledger}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
