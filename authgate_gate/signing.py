"""Ed25519 signing for notary heads — Stage 4 of the #3 remedy.

The notary (see `authgate.notary`) is an append-only *witness* held in a separate
process. HMAC authenticates that a submission came from a key-holder — but any
key-holder, including the gate's own attacker, can compute it, so an HMAC'd head
proves nothing to a *third party*. A **signature** does: the notary holds an
Ed25519 private key that lives ONLY in the notary process, signs each head it
records, and publishes the public key. Now anyone can verify that a head
genuinely came from the notary, offline, without trusting the transport, the
gate, or a shared secret.

What this adds honestly:
  * third-party / offline verifiability of a head (the auditor needs only the
    public key and the signed head, not a live notary or a shared HMAC key);
  * a gate-side attacker who fabricates a head cannot forge the notary's
    signature — they do not hold the private key.

What it does NOT add — do not overclaim:
  * it does not beat a full-machine compromise of the *notary*: an attacker who
    owns the notary process/host can read the private key and sign anything.
    The private key file must be protected by the OS (own user, restrictive
    perms); reaching beyond that is the hardware root-of-trust tier (TPM/HSM),
    not this module. See SECURITY.md.

Depends on the `cryptography` package (Ed25519).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def head_message(chain: str, seq: int, entry_hash: str) -> bytes:
    """Canonical bytes signed/verified for a head.

    A JSON object with sorted keys and no whitespace — unambiguous (no delimiter
    collisions) and reproducible regardless of how the fields were assembled.
    """
    return json.dumps(
        {"chain": chain, "seq": seq, "hash": entry_hash},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def verify_head(
    public_key_hex: str, chain: str, seq: int, entry_hash: str, sig_hex: str
) -> bool:
    """True iff ``sig_hex`` is a valid notary signature over this head.

    Never raises: malformed key/sig hex or a bad signature all return False.
    This is the auditor-side primitive — needs only the published public key.
    """
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(sig_hex), head_message(chain, seq, entry_hash))
        return True
    except (InvalidSignature, ValueError):
        return False


class Ed25519Signer:
    """Holds the notary's private key and signs heads. Lives in the notary only."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        self._pub_hex = self._key.public_key().public_bytes_raw().hex()

    # -- construction ------------------------------------------------------- #
    @classmethod
    def generate(cls) -> Ed25519Signer:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_generate(cls, path: str | Path) -> Ed25519Signer:
        """Load the private key from ``path`` (unencrypted PEM), or generate and
        persist one on first run, alongside a ``<path>.pub`` with the raw public
        key hex for out-of-band distribution.

        The private key is written with owner-only permissions where the OS
        supports it; on all platforms, protecting this file is the operator's
        responsibility (an attacker who can read it can sign as the notary).
        """
        p = Path(path)
        if p.exists():
            key = serialization.load_pem_private_key(p.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError(f"{p}: not an Ed25519 private key")
            return cls(key)

        signer = cls.generate()
        p.parent.mkdir(parents=True, exist_ok=True)
        pem = signer._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Create with owner-only perms from the start (best-effort on Windows).
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, pem)
        finally:
            os.close(fd)
        p.with_suffix(p.suffix + ".pub").write_text(signer.public_key_hex(), encoding="utf-8")
        return signer

    # -- use ---------------------------------------------------------------- #
    def sign_head(self, chain: str, seq: int, entry_hash: str) -> str:
        return self._key.sign(head_message(chain, seq, entry_hash)).hex()

    def public_key_hex(self) -> str:
        return self._pub_hex
