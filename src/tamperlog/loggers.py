"""Logging modes A–D.

Mode A: Plaintext (no integrity protection)
Mode B: SHA-256 hash chaining
Mode C: HMAC-SHA256 chaining
Mode D: HMAC-SHA256 chaining + trusted checkpoints

Owner: Lucas (Modes A–C), Ashton (Mode D support via checkpoints)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .schema import LogRecord


class PlaintextLogger:
    """Mode A — writes log records with no integrity tag."""

    def __init__(self, log_id: str, path: Path) -> None:
        self.log_id = log_id
        self.path = path
        self.seq = 0

    def append(self, event_type: str, details: dict[str, Any]) -> LogRecord:
        """Create and persist a plaintext log record.

        TODO (Lucas): Build LogRecord with tag=None, serialize via
        record_to_jsonl, append to self.path, increment seq.
        """
        raise NotImplementedError("Lucas: implement PlaintextLogger.append")


class HashChainLogger:
    """Mode B — SHA-256 hash chain (no secret key)."""

    def __init__(self, log_id: str, path: Path) -> None:
        self.log_id = log_id
        self.path = path
        self.seq = 0
        self.prev_tag: str | None = None

    def append(self, event_type: str, details: dict[str, Any]) -> LogRecord:
        """Create a hash-chained record.

        TODO (Lucas): Compute tag = SHA-256(canonical_bytes(record)),
        where record includes prev_tag from the prior entry.
        """
        raise NotImplementedError("Lucas: implement HashChainLogger.append")


class HMACChainLogger:
    """Mode C — HMAC-SHA256 chain (requires secret key)."""

    def __init__(self, log_id: str, path: Path, key_id: str) -> None:
        self.log_id = log_id
        self.path = path
        self.key_id = key_id
        self.seq = 0
        self.prev_tag: str | None = None

    def append(self, event_type: str, details: dict[str, Any]) -> LogRecord:
        """Create an HMAC-chained record.

        TODO (Lucas): Like Mode B but use HMAC-SHA256 with the key from
        keyring.  Set key_id on the record.
        """
        raise NotImplementedError("Lucas: implement HMACChainLogger.append")


class HMACCheckpointLogger:
    """Mode D — HMAC-SHA256 chain + trusted checkpoints.

    Owner: Lucas (append), Ashton (checkpoint creation via checkpoints module)
    """

    def __init__(self, log_id: str, path: Path, key_id: str, checkpoint_interval: int = 10) -> None:
        self.log_id = log_id
        self.path = path
        self.key_id = key_id
        self.checkpoint_interval = checkpoint_interval
        self.seq = 0
        self.prev_tag: str | None = None

    def append(self, event_type: str, details: dict[str, Any]) -> LogRecord:
        """Create an HMAC-chained record, emitting checkpoints at intervals.

        TODO (Lucas + Ashton): After every checkpoint_interval records,
        call checkpoints.create_checkpoint() to store a trusted anchor.
        """
        raise NotImplementedError("Lucas + Ashton: implement HMACCheckpointLogger.append")
