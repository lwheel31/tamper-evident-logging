"""HMAC key management with rotation support.

Threat model assumptions:
- The attacker CANNOT access secret HMAC keys.
- Keys are stored in a protected directory outside attacker-writable logs.
- Historical keys are retained so older records can still be verified.
- A missing historical key must produce an explicit verification error,
  NEVER a false 'valid' result.

Owner: Ashton
"""

from __future__ import annotations

from pathlib import Path


def generate_key(key_id: str, store_path: Path) -> None:
    """Generate a new HMAC key and persist it.

    TODO (Ashton): Use secrets.token_bytes(32) for a 256-bit key.
    Store as <store_path>/<key_id>.key with restrictive permissions.
    """
    raise NotImplementedError("Ashton: implement key generation")


def load_key(key_id: str, store_path: Path) -> bytes:
    """Load a previously stored HMAC key.

    Must raise KeyError (not return empty/default) if the key file is
    missing — a missing key must never produce a false 'valid' result.

    TODO (Ashton): Read <store_path>/<key_id>.key, raise KeyError if absent.
    """
    raise NotImplementedError("Ashton: implement key loading")


def rotate_key(new_key_id: str, store_path: Path) -> str:
    """Generate a new key for future records. Old keys remain available.

    Returns the new key_id.

    TODO (Ashton): Generate a new key, return its key_id. Old keys stay
    on disk so historical verification still works.
    """
    raise NotImplementedError("Ashton: implement key rotation")


def list_keys(store_path: Path) -> list[str]:
    """List all available key IDs.

    TODO (Ashton): Enumerate <store_path>/*.key, return sorted key_ids.
    """
    raise NotImplementedError("Ashton: implement key listing")
