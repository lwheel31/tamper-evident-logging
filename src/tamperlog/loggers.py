"""Logging modes A-D.

Mode A: Plaintext (no integrity protection)
Mode B: SHA-256 hash chaining (no secret: attacker can recompute)
Mode C: HMAC-SHA256 chaining (secret key: attacker can't recompute)
Mode D: Mode C + a trusted checkpoint after every N records (default 1)

Every logger has the same method: append(timestamp, event_type, details) -> LogRecord.

Owner: Lucas (Modes A-C, Mode D append), Ashton (keyring + checkpoints that C/D call)
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

from . import checkpoints, keyring
from .schema import LogRecord
from .serialization import canonical_bytes, record_to_jsonl

# Public, documented starting value for prev_tag on the first chained record.
# It is NOT a secret; it just means "nothing came before this".
GENESIS_TAG = "0" * 64


class _BaseLogger:
    """Shared plumbing: sequence numbers and writing lines to the file."""

    def __init__(self, log_id: str, path: Path) -> None:
        self.log_id = log_id
        self.path = Path(path)
        # Refuse to continue an existing file: restarting at seq 0 would
        # corrupt it. Each run writes a fresh log.
        if self.path.exists() and self.path.stat().st_size > 0:
            raise FileExistsError(f"log already exists: {self.path}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.seq = 0

    def _write(self, record: LogRecord) -> None:
        # newline="\n" so Windows and Linux write identical files.
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(record_to_jsonl(record) + "\n")
        self.seq += 1

    def _new_record(self, timestamp: str, event_type: str, details: dict[str, Any]) -> LogRecord:
        return LogRecord(
            log_id=self.log_id, seq=self.seq, timestamp=timestamp,
            event_type=event_type, details=dict(details),
        )


class PlaintextLogger(_BaseLogger):
    """Mode A - writes records with no tag. Any edit is invisible."""

    def append(self, timestamp: str, event_type: str, details: dict[str, Any]) -> LogRecord:
        record = self._new_record(timestamp, event_type, details)
        self._write(record)
        return record


class HashChainLogger(_BaseLogger):
    """Mode B - tag = SHA-256(record including prev_tag).

    Detects careless edits, but anyone can recompute SHA-256, so an attacker
    who edits a record can simply rebuild every tag after it.
    """

    def __init__(self, log_id: str, path: Path) -> None:
        super().__init__(log_id, path)
        self.prev_tag = GENESIS_TAG

    def append(self, timestamp: str, event_type: str, details: dict[str, Any]) -> LogRecord:
        record = self._new_record(timestamp, event_type, details)
        record.prev_tag = self.prev_tag  # link to the previous record
        record.tag = hashlib.sha256(canonical_bytes(record)).hexdigest()
        self._write(record)
        self.prev_tag = record.tag
        return record


class HMACChainLogger(_BaseLogger):
    """Mode C - tag = HMAC-SHA256(key, record including prev_tag and key_id).

    Same chain as Mode B, but making a valid tag requires the secret key,
    which the attacker never has.

    The key comes from Ashton's keyring (load_key). Tests may pass `key`
    directly so this mode can be tested before the keyring is finished.
    """

    def __init__(self, log_id: str, path: Path, key_id: str,
                 key_store: Path | None = None, key: bytes | None = None) -> None:
        super().__init__(log_id, path)
        self.key_store = key_store
        self.prev_tag = GENESIS_TAG
        self.switch_key(key_id, key)

    def switch_key(self, key_id: str, key: bytes | None = None) -> None:
        """Use a different key for future records (key rotation).

        Older records keep their old key_id, which is covered by their tag,
        so the verifier knows which key to load for each one.
        """
        if key is None:
            if self.key_store is None:
                raise ValueError("need either key or key_store")
            key = keyring.load_key(key_id, self.key_store)
        if len(key) < 32:
            raise ValueError("HMAC key must be at least 32 bytes")
        self.key_id = key_id
        self._key = key

    def append(self, timestamp: str, event_type: str, details: dict[str, Any]) -> LogRecord:
        record = self._new_record(timestamp, event_type, details)
        record.key_id = self.key_id  # signed, so it can't be swapped
        record.prev_tag = self.prev_tag
        record.tag = hmac.new(self._key, canonical_bytes(record), hashlib.sha256).hexdigest()
        self._write(record)
        self.prev_tag = record.tag
        return record


class HMACCheckpointLogger(HMACChainLogger):
    """Mode D - Mode C plus a trusted checkpoint (log_id, seq, tag).

    The checkpoint is stored by Ashton's checkpoints module in a separate
    directory the attacker can't write. It lets the verifier notice when
    the END of the log has been cut off.
    """

    def __init__(self, log_id: str, path: Path, key_id: str, checkpoint_store: Path,
                 key_store: Path | None = None, key: bytes | None = None,
                 checkpoint_interval: int = 1) -> None:
        if checkpoint_interval < 1:
            raise ValueError("checkpoint_interval must be >= 1")
        super().__init__(log_id, path, key_id, key_store=key_store, key=key)
        self.checkpoint_store = Path(checkpoint_store)
        self.checkpoint_interval = checkpoint_interval

    def append(self, timestamp: str, event_type: str, details: dict[str, Any]) -> LogRecord:
        record = super().append(timestamp, event_type, details)
        # Record first, checkpoint second. Default interval 1 = every record.
        if (record.seq + 1) % self.checkpoint_interval == 0:
            checkpoints.create_checkpoint(self.log_id, record.seq, record.tag, self.checkpoint_store)
        return record
