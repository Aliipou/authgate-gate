"""Token normalization at the trust boundary.

Every purpose/label/tool/capability string is normalized the moment an Action
Packet is built, so no two enforcement layers ever compare un-normalized
strings. This closes a whole class of bypasses: case folding, Unicode
look-alikes (NFKC), zero-width / control characters, and stray whitespace.

Normalization is idempotent: normalize(normalize(x)) == normalize(x).
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable


def normalize_token(value: str) -> str:
    """Canonicalize a single identifier token.

    NFKC folds Unicode look-alikes (e.g. fullwidth, ligatures) to their
    canonical form; control/format categories (Cc, Cf, ...) — which include
    zero-width joiners used to smuggle distinct-but-identical-looking tokens —
    are dropped; the result is whitespace-trimmed and case-folded.
    """
    if not isinstance(value, str):
        raise TypeError(f"token must be str, got {type(value).__name__}")
    # Canonical compatibility form first, so look-alikes collapse.
    value = unicodedata.normalize("NFKC", value)
    # Drop any Unicode "Other" category char (control, format, surrogate,
    # private-use, unassigned) — zero-width space/joiner live in Cf.
    value = "".join(ch for ch in value if not unicodedata.category(ch).startswith("C"))
    return value.strip().casefold()


def normalize_labels(labels: Iterable[str]) -> tuple[str, ...]:
    """Normalize a collection of tokens, dropping empties, order-preserving,
    de-duplicated."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in labels:
        tok = normalize_token(raw)
        if tok and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return tuple(out)
