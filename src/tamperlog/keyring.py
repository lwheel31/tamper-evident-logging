"""HMAC key management with rotation support.

Threat model assumptions:
- The attacker CANNOT access secret HMAC keys.
- Keys are stored in a protected directory outside attacker-writable logs.
- Historical keys are retained so older records can still be verified.
- A missing historical key must produce an explicit verification error,
  NEVER a false 'valid' result.

Storage format: one file per key, <store_path>/<key_id>.key, holding the raw
32 key bytes. Files are created with owner-only permissions (0o600) and are
never overwritten, so rotating to a new key can't destroy an old one.

Owner: Ashton
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

KEY_BYTES = 32  # 256-bit key, matches the SHA-256 output size (RFC 2104 guidance)

# Same identifier rules the verifier uses: a plain name, never a path.
# Starts with a letter/digit, then letters/digits/underscore/hyphen, max 128.
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_WINDOWS_DEVICE = re.compile(r"(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])", re.IGNORECASE)


def _check_id(key_id: str) -> None:
    """Reject anything that could escape the key folder (e.g. '../x', 'a/b')."""
    if (not isinstance(key_id, str) or _SAFE_ID.fullmatch(key_id) is None
            or _WINDOWS_DEVICE.fullmatch(key_id) is not None):
        raise ValueError(f"unsafe key_id: {key_id!r}")


def _key_path(key_id: str, store_path: Path) -> Path:
    _check_id(key_id)
    return Path(store_path) / f"{key_id}.key"


def generate_key(key_id: str, store_path: Path) -> None:
    """Generate a new random 32-byte HMAC key and save it as <key_id>.key.

    Refuses to overwrite an existing key: replacing an old key would make
    every record signed with it unverifiable.
    """
    path = _key_path(key_id, store_path)
    store = Path(store_path)
    store.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Compare case-insensitively so 'Key1' and 'key1' can't both exist
    # (they'd be the same file on macOS/Windows).
    if key_id.lower() in (k.lower() for k in list_keys(store)):
        raise FileExistsError(f"key already exists: {key_id!r}")

    key = secrets.token_bytes(KEY_BYTES)
    # O_EXCL: fail instead of overwriting if the file appeared in the meantime.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)


def load_key(key_id: str, store_path: Path) -> bytes:
    """Load a stored HMAC key.

    Raises KeyError if the key doesn't exist. Never returns a default or
    substitute key, so a missing old key can't turn into a false 'valid'.
    """
    path = _key_path(key_id, store_path)
    if path.is_symlink() or not path.is_file():
        raise KeyError(key_id)
    key = path.read_bytes()
    if len(key) != KEY_BYTES:
        raise ValueError(f"key {key_id!r} is corrupted (wrong length)")
    return key


def rotate_key(new_key_id: str, store_path: Path) -> str:
    """Create a new key for future records and return its key_id.

    Old key files are left untouched so records signed before the rotation
    still verify. The logger then calls switch_key(new_key_id) to start
    using it; the chain itself continues without resetting.
    """
    generate_key(new_key_id, store_path)
    return new_key_id


def list_keys(store_path: Path) -> list[str]:
    """Return the sorted key_ids that are stored in store_path."""
    store = Path(store_path)
    if not store.is_dir():
        return []
    return sorted(p.stem for p in store.glob("*.key")
                  if p.is_file() and not p.is_symlink() and _SAFE_ID.fullmatch(p.stem))
