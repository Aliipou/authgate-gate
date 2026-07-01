"""Deterministic checks for the independent audit-head notary (authgate/notary.py).

Stdlib only, no external deps. Each test starts its own NotaryServer on an
ephemeral port (0) in a daemon thread and tears it down in a finally block.
Ledger paths use tempfile.mkdtemp(), matching tests/test_audit_chain.py style.

    python -m pytest -q tests/test_notary.py
"""

from __future__ import annotations

import json
import pathlib
import socket
import sys
import tempfile
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from authgate.action import Action
from authgate.audit_chain import GENESIS_PREV_HASH, HashChainedAudit, _canonical_hash
from authgate.notary import (
    NotaryClient,
    NotaryLedger,
    NotaryServer,
    _mac,
    make_anchor,
)
from authgate.policy import Decision, Verdict

_KEY = "shared-test-key-0123456789"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _tmp_ledger() -> pathlib.Path:
    return pathlib.Path(tempfile.mkdtemp()) / "nested" / "notary_ledger.jsonl"


def _tmp_log() -> pathlib.Path:
    return pathlib.Path(tempfile.mkdtemp()) / "nested" / "audit_chain.jsonl"


def _allow(reason: str = "ok") -> Decision:
    return Decision(Verdict.ALLOW, reason)


def _h(tag: str) -> str:
    """A deterministic, distinct 64-hex 'hash' for ledger tests."""
    import hashlib

    return hashlib.sha256(tag.encode()).hexdigest()


class _RunningServer:
    """Context manager: a NotaryServer bound to an ephemeral port on a thread."""

    def __init__(self, ledger_path: pathlib.Path, key: str = _KEY) -> None:
        self._ledger_path = ledger_path
        self._key = key

    def __enter__(self) -> NotaryServer:
        self.server = NotaryServer(
            ("127.0.0.1", 0), NotaryLedger(self._ledger_path), key=self._key
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.server

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


def _client(server: NotaryServer, key: str = _KEY) -> NotaryClient:
    return NotaryClient("127.0.0.1", server.server_address[1], key=key)


def _raw_rpc(port: int, req: dict) -> dict:
    """Send one JSON line to the server bypassing NotaryClient (to craft bad requests)."""
    with socket.create_connection(("127.0.0.1", port), timeout=5.0) as s:
        s.sendall((json.dumps(req) + "\n").encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.decode("utf-8").strip() or "{}")


# --------------------------------------------------------------------------- #
# Ledger
# --------------------------------------------------------------------------- #
def test_ledger_submit_accepts_increasing_seq() -> None:
    ledger = NotaryLedger(_tmp_ledger())
    ok, reason = ledger.submit("c", 0, _h("a"))
    assert ok is True, reason
    ok, reason = ledger.submit("c", 1, _h("b"))
    assert ok is True, reason
    ok, reason = ledger.submit("c", 5, _h("c"))  # gaps allowed, just strictly-increasing
    assert ok is True, reason


def test_ledger_rejects_seq_regression() -> None:
    ledger = NotaryLedger(_tmp_ledger())
    assert ledger.submit("c", 3, _h("a"))[0] is True
    ok, reason = ledger.submit("c", 2, _h("b"))
    assert ok is False
    assert "regression" in reason


def test_ledger_rejects_equal_seq() -> None:
    ledger = NotaryLedger(_tmp_ledger())
    assert ledger.submit("c", 3, _h("a"))[0] is True
    ok, reason = ledger.submit("c", 3, _h("different-hash"))
    assert ok is False
    assert "regression" in reason


def test_ledger_head_returns_latest() -> None:
    ledger = NotaryLedger(_tmp_ledger())
    ledger.submit("c", 0, _h("a"))
    ledger.submit("c", 1, _h("b"))
    ledger.submit("c", 7, _h("z"))
    assert ledger.head("c") == (7, _h("z"))


def test_ledger_at_point_lookup() -> None:
    ledger = NotaryLedger(_tmp_ledger())
    ledger.submit("c", 0, _h("a"))
    ledger.submit("c", 1, _h("b"))
    assert ledger.at("c", 0) == _h("a")
    assert ledger.at("c", 1) == _h("b")
    assert ledger.at("c", 99) is None


def test_ledger_unknown_chain_head_is_genesis() -> None:
    ledger = NotaryLedger(_tmp_ledger())
    assert ledger.head("never-seen") == (-1, GENESIS_PREV_HASH)
    assert ledger.at("never-seen", 0) is None


def test_ledger_recovery_rebuilds_head_and_at() -> None:
    path = _tmp_ledger()
    first = NotaryLedger(path)
    first.submit("c", 0, _h("a"))
    first.submit("c", 1, _h("b"))
    first.submit("c", 4, _h("e"))
    first.submit("other", 0, _h("o0"))

    # Fresh ledger over the same file: state must be replayed from disk.
    recovered = NotaryLedger(path)
    assert recovered.head("c") == (4, _h("e"))
    assert recovered.at("c", 0) == _h("a")
    assert recovered.at("c", 1) == _h("b")
    assert recovered.at("c", 4) == _h("e")
    assert recovered.head("other") == (0, _h("o0"))
    # And it still enforces monotonicity relative to the recovered head.
    ok, reason = recovered.submit("c", 4, _h("dup"))
    assert ok is False and "regression" in reason
    assert recovered.submit("c", 5, _h("f"))[0] is True


def test_ledger_recovery_highest_seq_wins_as_head() -> None:
    # If the file (append-only) somehow records seqs out of order, replay must
    # pick the highest seq as head, not the last line.
    path = _tmp_ledger()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write(json.dumps({"chain": "c", "seq": 9, "hash": _h("nine")}) + "\n")
        f.write(json.dumps({"chain": "c", "seq": 3, "hash": _h("three")}) + "\n")
    ledger = NotaryLedger(path)
    assert ledger.head("c") == (9, _h("nine"))
    assert ledger.at("c", 3) == _h("three")


# --------------------------------------------------------------------------- #
# Server / protocol
# --------------------------------------------------------------------------- #
def test_server_submit_with_correct_mac_accepted() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        c = _client(server)
        resp = c.submit("c", 0, _h("a"))
        assert resp["ok"] is True
        assert resp["seq"] == 0 and resp["hash"] == _h("a")
        assert c.head("c") == (0, _h("a"))


def test_server_submit_wrong_mac_rejected() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        port = server.server_address[1]
        # Correct tuple but a MAC computed with the WRONG key.
        bad_mac = _mac(b"the-wrong-key", "c", 0, _h("a"))
        resp = _raw_rpc(port, {"op": "submit", "chain": "c", "seq": 0, "hash": _h("a"), "mac": bad_mac})
        assert resp["ok"] is False
        assert "MAC" in resp["reason"]
        # Nothing got recorded.
        c = _client(server)
        assert c.head("c") == (-1, GENESIS_PREV_HASH)


def test_server_submit_missing_mac_rejected() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        port = server.server_address[1]
        resp = _raw_rpc(port, {"op": "submit", "chain": "c", "seq": 0, "hash": _h("a")})
        assert resp["ok"] is False
        assert "MAC" in resp["reason"]


def test_server_submit_mistyped_fields_rejected_cleanly() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        port = server.server_address[1]
        # seq as a string, hash missing, chain as int — must not crash the server.
        for req in (
            {"op": "submit", "chain": "c", "seq": "0", "hash": _h("a"), "mac": "x"},
            {"op": "submit", "chain": 123, "seq": 0, "hash": _h("a"), "mac": "x"},
            {"op": "submit", "chain": "c", "seq": 0, "mac": "x"},  # missing hash
            {"op": "submit"},  # everything missing
        ):
            resp = _raw_rpc(port, req)
            assert resp["ok"] is False
            assert "missing/typed" in resp["reason"], resp
        # Server is still alive and functional afterward.
        c = _client(server)
        assert c.submit("c", 0, _h("a"))["ok"] is True


def test_server_head_op() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        c = _client(server)
        assert c.head("c") == (-1, GENESIS_PREV_HASH)
        c.submit("c", 0, _h("a"))
        c.submit("c", 1, _h("b"))
        assert c.head("c") == (1, _h("b"))


def test_server_head_missing_chain_rejected() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        port = server.server_address[1]
        resp = _raw_rpc(port, {"op": "head"})
        assert resp["ok"] is False and "missing chain" in resp["reason"]


def test_server_at_op() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        c = _client(server)
        c.submit("c", 0, _h("a"))
        c.submit("c", 1, _h("b"))
        assert c.at("c", 0) == _h("a")
        assert c.at("c", 1) == _h("b")
        assert c.at("c", 42) is None  # unknown seq -> null


def test_server_at_mistyped_rejected() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        port = server.server_address[1]
        resp = _raw_rpc(port, {"op": "at", "chain": "c", "seq": "notanint"})
        assert resp["ok"] is False and "missing/typed" in resp["reason"]


def test_server_unknown_op_rejected() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        port = server.server_address[1]
        resp = _raw_rpc(port, {"op": "frobnicate"})
        assert resp["ok"] is False and "unknown op" in resp["reason"]


def test_server_garbage_line_does_not_crash() -> None:
    # A non-JSON line must yield a clean error, not tear down the connection/server.
    with _RunningServer(_tmp_ledger()) as server:
        port = server.server_address[1]
        with socket.create_connection(("127.0.0.1", port), timeout=5.0) as s:
            s.sendall(b"this is not json\n")
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        resp = json.loads(buf.decode("utf-8").strip())
        assert resp["ok"] is False and "bad request" in resp["reason"]
        # Server still serves.
        c = _client(server)
        assert c.submit("c", 0, _h("a"))["ok"] is True


def test_server_seq_regression_over_wire_rejected() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        c = _client(server)
        assert c.submit("c", 5, _h("a"))["ok"] is True
        resp = c.submit("c", 5, _h("b"))  # equal seq
        assert resp["ok"] is False and "regression" in resp["reason"]
        resp = c.submit("c", 2, _h("c"))  # lower seq
        assert resp["ok"] is False and "regression" in resp["reason"]


# --------------------------------------------------------------------------- #
# Client + make_anchor (end-to-end)
# --------------------------------------------------------------------------- #
def test_make_anchor_end_to_end_head_matches() -> None:
    chain = "gate-A"
    with _RunningServer(_tmp_ledger()) as server:
        c = _client(server)
        log = HashChainedAudit(_tmp_log(), anchor=make_anchor(c, chain))
        for i in range(4):
            log.record(Action("agent:bot", "send_email", "support", ("cs",)), _allow(f"e{i}"))
        local_seq, local_hash = log.head()
        notary_seq, notary_hash = c.head(chain)
        assert (notary_seq, notary_hash) == (local_seq, local_hash)
        assert notary_seq == 3
        # And each intermediate head is retrievable by point-lookup.
        assert c.at(chain, 0) is not None
        assert c.at(chain, 3) == local_hash


def test_make_anchor_fail_closed_on_notary_rejection() -> None:
    chain = "gate-B"
    with _RunningServer(_tmp_ledger()) as server:
        c = _client(server)
        anchor = make_anchor(c, chain)
        # Pre-seed the notary with a HIGHER seq so the gate's next submit regresses.
        assert c.submit(chain, 100, _h("planted"))["ok"] is True
        log = HashChainedAudit(_tmp_log(), anchor=anchor)
        raised = False
        try:
            log.record(Action("a", "t", "p"), _allow())  # seq 0 -> regression vs 100
        except RuntimeError as e:
            raised = True
            assert "notary rejected" in str(e)
        assert raised is True, "make_anchor must fail-closed on notary rejection"


def test_make_anchor_fail_closed_when_unreachable() -> None:
    chain = "gate-C"
    # Start then immediately stop a server to obtain a dead port.
    rs = _RunningServer(_tmp_ledger())
    server = rs.__enter__()
    dead_port = server.server_address[1]
    rs.__exit__()
    # Bind a client to the now-closed port.
    c = NotaryClient("127.0.0.1", dead_port, key=_KEY, timeout=1.0)
    anchor = make_anchor(c, chain)
    log = HashChainedAudit(_tmp_log(), anchor=anchor)
    raised = False
    try:
        log.record(Action("a", "t", "p"), _allow())
    except OSError:
        raised = True
    except RuntimeError:
        raised = True
    assert raised is True, "make_anchor must raise when the notary is unreachable"


# --------------------------------------------------------------------------- #
# Headline integration: in-process forgery caught by the notary head
# --------------------------------------------------------------------------- #
def test_forged_local_log_verifies_but_diverges_from_notary() -> None:
    chain = "gate-forge"
    with _RunningServer(_tmp_ledger()) as server:
        c = _client(server)
        path = _tmp_log()
        log = HashChainedAudit(path, anchor=make_anchor(c, chain))
        log.record(Action("a", "t", "p"), _allow("innocuous"))
        log.record(Action("a", "t", "p"), _allow("WIRED $10M TO ATTACKER"))
        log.record(Action("a", "t", "p"), _allow("also innocuous"))

        notary_seq, notary_hash = c.head(chain)  # the externally-retained head

        # Forge: drop the damning record and recompute EVERY hash locally.
        entries = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        kept = [e for e in entries if "ATTACKER" not in e["reason"]]
        prev = GENESIS_PREV_HASH
        forged = []
        for seq, e in enumerate(kept):
            e = dict(e, seq=seq, prev_hash=prev)
            e.pop("entry_hash", None)
            e["entry_hash"] = _canonical_hash(e)
            prev = e["entry_hash"]
            forged.append(e)
        path.write_text("".join(json.dumps(e) + "\n" for e in forged), encoding="utf-8")

        reader = HashChainedAudit(path)
        # In-process verify() passes — the forgery is internally consistent.
        assert reader.verify() is True
        # But the notary's retained head betrays the truncation.
        ok, reason = reader.verify_against_anchor(notary_hash, notary_seq)
        assert ok is False, "notary head must expose the forged/truncated log"
        assert "diverges" in reason


# --------------------------------------------------------------------------- #
# Multi-chain isolation
# --------------------------------------------------------------------------- #
def test_multi_chain_isolation() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        c = _client(server)
        c.submit("alpha", 0, _h("a0"))
        c.submit("beta", 0, _h("b0"))
        c.submit("alpha", 1, _h("a1"))
        # beta at a LOW seq must not be blocked by alpha's higher seq.
        assert c.submit("beta", 1, _h("b1"))["ok"] is True

        assert c.head("alpha") == (1, _h("a1"))
        assert c.head("beta") == (1, _h("b1"))
        assert c.at("alpha", 0) == _h("a0")
        assert c.at("beta", 0) == _h("b0")
        # A regression on alpha does not touch beta.
        assert c.submit("alpha", 0, _h("x"))["ok"] is False
        assert c.head("beta") == (1, _h("b1"))


def test_two_anchored_logs_on_distinct_chains_do_not_interfere() -> None:
    with _RunningServer(_tmp_ledger()) as server:
        c = _client(server)
        log1 = HashChainedAudit(_tmp_log(), anchor=make_anchor(c, "chain-1"))
        log2 = HashChainedAudit(_tmp_log(), anchor=make_anchor(c, "chain-2"))
        log1.record(Action("a", "t", "p"), _allow())
        log2.record(Action("a", "t", "p"), _allow())
        log2.record(Action("a", "t", "p"), _allow())
        assert c.head("chain-1") == log1.head()
        assert c.head("chain-2") == log2.head()
        assert c.head("chain-1")[0] == 0
        assert c.head("chain-2")[0] == 1


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:  # noqa: BLE001
                failures += 1
                print(f"ERROR {name}: {e!r}")
    print(f"\n{'all passed' if not failures else f'{failures} failed'}")
    sys.exit(1 if failures else 0)
