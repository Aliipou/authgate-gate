"""Tamper-evident, hash-chained audit log — the SOC2/compliance evidence layer.

The plain :class:`authgate.audit.AuditLog` is append-only and human-readable, but
it offers no *integrity* guarantee: anyone with write access to the file can edit a
past line, drop a line, insert a forged one, or reorder entries, and nothing in the
record itself would betray the change. For compliance evidence that is not enough —
the auditor needs to know the log they are reading is the log that was written.

:class:`HashChainedAudit` closes that gap with a Merkle-style hash chain (a
"blockchain of one file"). Each entry carries:

  * ``entry_hash`` — sha256 over the canonical JSON of the entry itself, computed
    over every field *except* ``entry_hash``. Canonicalization uses
    ``json.dumps(..., sort_keys=True, separators=(",", ":"))`` so the bytes hashed
    are reproducible regardless of key order or whitespace.
  * ``prev_hash`` — the ``entry_hash`` of the entry immediately before it (or 64
    hex zeros for the genesis entry).

Because each ``entry_hash`` is folded into the next entry's ``prev_hash``, the
chain is a tamper-evident sequence:

  * EDIT   — changing any field of entry *i* changes its ``entry_hash``; entry
             *i+1*'s ``prev_hash`` no longer matches → break detected.
  * INSERT — a spliced-in line breaks the prev/next linkage on both sides, and its
             own ``entry_hash``/``seq`` will not line up.
  * DELETE — removing entry *i* leaves *i+1* pointing at a ``prev_hash`` that is no
             longer present, and creates a ``seq`` gap.
  * REORDER— swapping two lines breaks the linear ``prev_hash`` linkage and the
             monotonic ``seq`` ordering.

Detection is via :meth:`verify` (re-reads the whole file and recomputes every
link) and :meth:`verify_detail` (same, but reports the first break). Neither can
*prevent* tampering — an attacker who can rewrite the file can also recompute the
whole chain — but the moment the log is anchored externally (a periodically
published ``entry_hash``, a WORM bucket, a notary), any divergence becomes
provable. This module is the in-process half of that story.

Stdlib only: ``hashlib``, ``json``, ``datetime``, ``pathlib``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# The genesis entry has no predecessor; its prev_hash is a fixed sentinel.
GENESIS_PREV_HASH = "0" * 64

# Fields every well-formed persisted entry must contain (entry_hash included).
_REQUIRED_FIELDS = (
    "seq",
    "ts",
    "actor",
    "tool",
    "action_purpose",
    "data_labels",
    "session_id",
    "verdict",
    "reason",
    "layer",
    "prev_hash",
    "entry_hash",
)


def _canonical_hash(entry: dict[str, Any]) -> str:
    """Return the hex sha256 of ``entry`` excluding its own ``entry_hash``.

    The hash is taken over the canonical JSON encoding (sorted keys, no
    whitespace) so that the same logical entry always hashes to the same value,
    independent of how the dict was constructed or serialized.
    """
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class HashChainedAudit:
    """Append-only JSONL audit log whose entries are cryptographically chained.

    Drop-in shaped like :class:`authgate.audit.AuditLog`: constructed with a
    ``path`` (parent directory is created) and recorded to with ``record(...)``.
    Unlike the simple log, every line is linked to the previous one so any
    retroactive edit, insert, delete, or reorder is detectable with
    :meth:`verify`.

    On construction, if the file already exists it is read and the chain is
    continued from the last line — and validated first, so reopening a tampered
    log raises rather than silently extending a broken chain.
    """

    def __init__(
        self,
        path: str | Path,
        anchor: Callable[[int, str], None] | None = None,
    ) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash: str = GENESIS_PREV_HASH
        self._next_seq: int = 0
        # Optional EXTERNAL-ANCHOR sink (default off). Called with
        # (seq, entry_hash) after each entry is durably written, so an operator
        # can publish the chain head to an out-of-process trust root (a WORM
        # bucket, a notary, a separate signer). This is the "external half" the
        # module docstring promises: in-process verify() cannot catch a forger
        # who rebuilt the whole file, but a head retained OUTSIDE this process
        # can — see verify_against_anchor(). Defaults to None so existing
        # behaviour and callers are completely unchanged.
        self._anchor = anchor
        if self._path.exists():
            self._load_existing()

    def head(self) -> tuple[int, str]:
        """Return ``(last_seq, last_entry_hash)`` — the current chain head.

        This is the single value an operator retains/publishes out of band to
        get real tamper-*evidence* (not just in-process tamper-detection). For
        an empty chain returns ``(-1, GENESIS_PREV_HASH)``.
        """
        return (self._next_seq - 1, self._last_hash)

    def _load_existing(self) -> None:
        """Resume an existing chain: validate it, then adopt its tail state.

        Raises ValueError if the on-disk chain does not verify — we refuse to
        extend a chain we cannot vouch for, since doing so would launder a break
        into the "trusted" in-memory state.
        """
        ok, reason = self.verify_detail()
        if not ok:
            raise ValueError(f"cannot resume tampered/corrupt audit chain: {reason}")
        last_entry: dict[str, Any] | None = None
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_entry = json.loads(line)
        if last_entry is not None:
            self._last_hash = last_entry["entry_hash"]
            self._next_seq = int(last_entry["seq"]) + 1

    def record(self, action: Any, decision: Any, layer: str = "") -> dict[str, Any]:
        """Append one chained audit entry for ``action`` / ``decision``.

        ``action`` may be a modern :class:`authgate.action.Action` or the older
        :class:`authgate.intent.Intent`; only the shared attributes are read
        (``actor, tool, action_purpose, data_labels``), and ``session_id`` is
        tolerated as missing (defaults to ``"default"``). ``decision`` must
        expose ``verdict`` (an enum with ``.value``) and ``reason``.

        The entry is hashed and linked to the previous entry before being written
        as a single JSON line. Returns the full entry dict (including hashes).
        """
        entry: dict[str, Any] = {
            "seq": self._next_seq,
            "ts": datetime.now(UTC).isoformat(),
            "actor": action.actor,
            "tool": action.tool,
            "action_purpose": action.action_purpose,
            "data_labels": list(action.data_labels),
            "session_id": getattr(action, "session_id", "default"),
            "verdict": decision.verdict.value,
            "reason": decision.reason,
            "layer": layer,
            "prev_hash": self._last_hash,
        }
        entry["entry_hash"] = _canonical_hash(entry)

        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        self._last_hash = entry["entry_hash"]
        self._next_seq += 1

        # Publish the new head to the external anchor, if any. Called AFTER the
        # local write so the durable log is the source of truth; an anchor sink
        # that raises is allowed to propagate (an opt-in operator wants their
        # anchor to be fail-closed), and cannot leave the in-memory chain state
        # inconsistent because it runs last.
        if self._anchor is not None:
            self._anchor(entry["seq"], entry["entry_hash"])
        return entry

    def verify_against_anchor(
        self, expected_hash: str, expected_seq: int | None = None
    ) -> tuple[bool, str]:
        """Verify the chain AND that its head matches an externally-retained one.

        Plain :meth:`verify` cannot catch an in-process forger who rewrote the
        whole file: they recompute every ``entry_hash`` too, so the chain is
        internally consistent. But any TRUNCATION or REWRITE changes the *head*
        hash. An auditor who kept the last known-good head out of band (via
        :meth:`head` / the ``anchor`` sink) passes it here; a divergence is then
        provable even though :meth:`verify` alone returns True. This is the piece
        that actually closes in-process audit forgery — provided the anchor lives
        somewhere the attacker cannot rewrite.
        """
        ok, reason = self.verify_detail()
        if not ok:
            return False, reason
        last_seq, last_hash = self.head()
        if last_hash != expected_hash:
            return False, (
                f"head hash diverges from anchor "
                f"(local {last_hash[:12]}…, anchor {expected_hash[:12]}…) "
                f"— truncation/rewrite past the anchored point"
            )
        if expected_seq is not None and last_seq != expected_seq:
            return False, (
                f"head seq diverges from anchor "
                f"(local {last_seq}, anchor {expected_seq}) — entries dropped/added"
            )
        return True, "ok"

    def verify(self) -> bool:
        """Re-read the file and confirm the whole chain is intact.

        Returns True only if every entry is well-formed, its ``entry_hash``
        recomputes correctly, its ``prev_hash`` matches the previous entry's
        ``entry_hash`` (genesis = 64 zeros), and ``seq`` is gap-free from 0.
        Returns False on ANY problem — including a corrupt/truncated JSON line —
        and never raises.
        """
        return self.verify_detail()[0]

    def verify_detail(self) -> tuple[bool, str]:
        """Like :meth:`verify`, but also report the first break.

        Returns ``(True, "ok")`` for an intact chain, otherwise
        ``(False, "<reason at line/index N>")``. Designed for tests and
        debugging; like :meth:`verify`, it never raises on bad input.
        """
        try:
            if not self._path.exists():
                # No file yet == empty, intact chain.
                return True, "ok"

            prev_hash = GENESIS_PREV_HASH
            expected_seq = 0
            saw_any = False

            with self._path.open("r", encoding="utf-8") as f:
                for idx, raw in enumerate(f):
                    raw = raw.strip()
                    if not raw:
                        # Tolerate a trailing blank line only if nothing follows.
                        continue
                    saw_any = True

                    try:
                        entry = json.loads(raw)
                    except (ValueError, TypeError):
                        return False, f"line {idx}: corrupt/un-parseable JSON"
                    if not isinstance(entry, dict):
                        return False, f"line {idx}: entry is not a JSON object"

                    for field in _REQUIRED_FIELDS:
                        if field not in entry:
                            return False, f"line {idx}: missing field '{field}'"

                    if entry["seq"] != expected_seq:
                        return False, (
                            f"line {idx}: seq gap/disorder "
                            f"(expected {expected_seq}, got {entry['seq']!r})"
                        )

                    if entry["prev_hash"] != prev_hash:
                        return False, (
                            f"line {idx}: prev_hash mismatch "
                            f"(chain broken — edit/insert/delete/reorder)"
                        )

                    recomputed = _canonical_hash(entry)
                    if recomputed != entry["entry_hash"]:
                        return False, (
                            f"line {idx}: entry_hash mismatch "
                            f"(content was modified)"
                        )

                    prev_hash = entry["entry_hash"]
                    expected_seq += 1

            if not saw_any:
                # File exists but is empty/blank — an intact (zero-length) chain.
                return True, "ok"
            return True, "ok"
        except Exception as exc:  # noqa: BLE001 — verify must never raise.
            return False, f"unexpected error during verify: {exc!r}"
