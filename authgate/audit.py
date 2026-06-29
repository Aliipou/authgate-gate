from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .intent import Intent
from .policy import Decision


class AuditLog:
    """Append-only, one JSON object per line. Every decision is traceable:
    who, what, why, the ruling, and when. This is the observability anchor —
    but it never feeds back into a decision (no control path here).
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, intent: Intent, decision: Decision) -> dict[str, Any]:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": intent.actor,
            "tool": intent.tool,
            "action_purpose": intent.action_purpose,
            "data_labels": list(intent.data_labels),
            "verdict": decision.verdict.value,
            "reason": decision.reason,
        }
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry
