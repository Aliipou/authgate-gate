"""Deterministic checks for the hash-chained audit log.

No framework needed: `python tests/test_audit_chain.py`.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from authgate_gate.action import Action
from authgate_gate.audit_chain import HashChainedAudit
from authgate_gate.intent import Intent
from authgate_gate.policy import Decision, Verdict


def _tmp_log() -> pathlib.Path:
    return pathlib.Path(tempfile.mkdtemp()) / "nested" / "audit_chain.jsonl"


def _allow(reason: str = "ok") -> Decision:
    return Decision(Verdict.ALLOW, reason)


def _seed(log: HashChainedAudit, n: int = 3) -> None:
    for i in range(n):
        log.record(
            Action("agent:bot", "send_email", "support_reply", ("customer_support",)),
            _allow(f"entry {i}"),
            layer="capability",
        )


def test_record_actions_then_verify_true() -> None:
    log = HashChainedAudit(_tmp_log())
    _seed(log, 5)
    assert log.verify() is True
    ok, reason = log.verify_detail()
    assert ok is True, reason


def test_seq_is_monotonic_from_zero() -> None:
    path = _tmp_log()
    log = HashChainedAudit(path)
    e0 = log.record(Action("a", "t", "p"), _allow())
    e1 = log.record(Action("a", "t", "p"), _allow())
    assert e0["seq"] == 0 and e1["seq"] == 1
    assert e0["prev_hash"] == "0" * 64
    assert e1["prev_hash"] == e0["entry_hash"]


def test_backcompat_intent_record() -> None:
    log = HashChainedAudit(_tmp_log())
    # Intent has no session_id — must be tolerated.
    entry = log.record(
        Intent("agent:bot", "send_email", "support_reply", ("customer_support",)),
        _allow("legacy intent"),
    )
    assert entry["session_id"] == "default"
    assert log.verify() is True


def test_layer_and_verdict_recorded() -> None:
    log = HashChainedAudit(_tmp_log())
    entry = log.record(
        Action("a", "t", "marketing", ("customer_support",)),
        Decision(Verdict.DENY, "purpose mismatch"),
        layer="purpose",
    )
    assert entry["verdict"] == "deny"
    assert entry["layer"] == "purpose"
    assert log.verify() is True


def test_head_tracks_last_entry() -> None:
    path = _tmp_log()
    log = HashChainedAudit(path)
    assert log.head() == (-1, "0" * 64)  # empty chain
    e0 = log.record(Action("a", "t", "p"), _allow())
    assert log.head() == (0, e0["entry_hash"])
    e1 = log.record(Action("a", "t", "p"), _allow())
    assert log.head() == (1, e1["entry_hash"])


def test_anchor_sink_receives_each_head() -> None:
    seen: list[tuple[int, str]] = []
    log = HashChainedAudit(_tmp_log(), anchor=lambda seq, h: seen.append((seq, h)))
    e0 = log.record(Action("a", "t", "p"), _allow())
    e1 = log.record(Action("a", "t", "p"), _allow())
    assert seen == [(0, e0["entry_hash"]), (1, e1["entry_hash"])]


def test_verify_against_anchor_catches_in_process_forgery() -> None:
    # An in-process forger who rewrites the whole file passes verify() — but an
    # externally-retained head detects the truncation.
    from authgate_gate.audit_chain import GENESIS_PREV_HASH, _canonical_hash

    path = _tmp_log()
    retained: list[tuple[int, str]] = []
    log = HashChainedAudit(path, anchor=lambda seq, h: retained.append((seq, h)))
    log.record(Action("a", "t", "p"), _allow("innocuous"))
    log.record(Action("a", "t", "p"), _allow("WIRED $10M TO ATTACKER"))
    anchor_seq, anchor_hash = retained[-1]

    # Forge: drop the damning record, recompute every hash (attacker has _canonical_hash).
    entries = [__import__("json").loads(ln) for ln in _lines(path) if ln.strip()]
    kept = [e for e in entries if "ATTACKER" not in e["reason"]]
    prev = GENESIS_PREV_HASH
    forged = []
    for seq, e in enumerate(kept):
        e = dict(e, seq=seq, prev_hash=prev)
        e.pop("entry_hash", None)
        e["entry_hash"] = _canonical_hash(e)
        prev = e["entry_hash"]
        forged.append(e)
    path.write_text("".join(__import__("json").dumps(e) + "\n" for e in forged), encoding="utf-8")

    reader = HashChainedAudit(path)
    assert reader.verify() is True  # in-process forgery is internally consistent
    ok, reason = reader.verify_against_anchor(anchor_hash, anchor_seq)
    assert ok is False and "diverges" in reason  # ...but the retained head betrays it


def _lines(path: pathlib.Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _write_lines(path: pathlib.Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_tamper_edit_reason_detected() -> None:
    path = _tmp_log()
    _seed(HashChainedAudit(path), 5)
    lines = _lines(path)
    # Flip a character in the reason of a middle line.
    mid = 2
    assert "entry 2" in lines[mid]
    lines[mid] = lines[mid].replace("entry 2", "entry X")
    _write_lines(path, lines)

    log = HashChainedAudit.__new__(HashChainedAudit)  # avoid resume-validation raise
    log._path = path
    log._last_hash = "0" * 64
    log._next_seq = 0
    assert log.verify() is False
    ok, reason = log.verify_detail()
    assert ok is False and "line 2" in reason, reason


def test_tamper_delete_middle_line_detected() -> None:
    path = _tmp_log()
    _seed(HashChainedAudit(path), 5)
    lines = _lines(path)
    del lines[2]
    _write_lines(path, lines)

    log = HashChainedAudit.__new__(HashChainedAudit)
    log._path = path
    assert log.verify() is False


def test_tamper_reorder_detected() -> None:
    path = _tmp_log()
    _seed(HashChainedAudit(path), 5)
    lines = _lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    _write_lines(path, lines)

    log = HashChainedAudit.__new__(HashChainedAudit)
    log._path = path
    assert log.verify() is False


def test_tamper_append_forged_line_detected() -> None:
    import json

    path = _tmp_log()
    _seed(HashChainedAudit(path), 3)
    lines = _lines(path)
    last = json.loads(lines[-1])
    # Forge a plausible entry: correct seq/prev_hash, but a wrong (fabricated)
    # entry_hash that does not match the canonical content.
    forged = {
        "seq": last["seq"] + 1,
        "ts": "2026-06-30T00:00:00+00:00",
        "actor": "attacker",
        "tool": "exfiltrate",
        "action_purpose": "theft",
        "data_labels": [],
        "session_id": "default",
        "verdict": "allow",
        "reason": "totally legit",
        "layer": "",
        "prev_hash": last["entry_hash"],
        "entry_hash": "f" * 64,  # plausible-looking but wrong
    }
    lines.append(json.dumps(forged))
    _write_lines(path, lines)

    log = HashChainedAudit.__new__(HashChainedAudit)
    log._path = path
    assert log.verify() is False


def test_reopen_continues_chain_and_verifies() -> None:
    path = _tmp_log()
    first = HashChainedAudit(path)
    _seed(first, 3)
    last_hash_before = first._last_hash

    # Reopen on the same path: should validate, then continue the chain.
    second = HashChainedAudit(path)
    assert second._next_seq == 3
    assert second._last_hash == last_hash_before

    entry = second.record(Action("a", "t", "p"), _allow("after reopen"))
    assert entry["seq"] == 3
    assert entry["prev_hash"] == last_hash_before
    assert second.verify() is True

    # And a brand-new reader over the now-longer file still verifies.
    assert HashChainedAudit(path).verify() is True


def test_corrupt_truncated_json_line_returns_false_not_raise() -> None:
    path = _tmp_log()
    _seed(HashChainedAudit(path), 3)
    lines = _lines(path)
    # Truncate a line to invalid JSON.
    lines[1] = lines[1][: len(lines[1]) // 2]
    _write_lines(path, lines)

    log = HashChainedAudit.__new__(HashChainedAudit)
    log._path = path
    # Must return False, must not raise.
    assert log.verify() is False
    ok, reason = log.verify_detail()
    assert ok is False, reason


def test_resume_tampered_chain_raises() -> None:
    path = _tmp_log()
    _seed(HashChainedAudit(path), 3)
    lines = _lines(path)
    lines[1] = lines[1].replace("entry 1", "entry Z")
    _write_lines(path, lines)
    raised = False
    try:
        HashChainedAudit(path)
    except ValueError:
        raised = True
    assert raised is True


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
