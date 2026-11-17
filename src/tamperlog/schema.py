"""Log record schema definition.

AWAITING TEAM APPROVAL — review before implementing security logic.

Record format (JSONL, one JSON object per line):
    log_id:    str   — unique identifier for the log stream
    seq:       int   — 0-based sequence number, strictly increasing
    timestamp: str   — ISO-8601 UTC (e.g. "2026-11-15T12:00:00Z")
    event_type: str  — category such as "LOGIN", "FILE_ACCESS", "ADMIN_CMD"
    details:   dict  — arbitrary event payload
    key_id:    str | None — identifier of the HMAC key used (None for plaintext/hash modes)
    prev_tag:  str | None — tag of the previous record. First record uses the
                           public GENESIS_TAG (64 zeros). None in Mode A.
    tag:       str | None — computed hash/HMAC for this record (None for plaintext mode)

The tag is computed over all fields EXCEPT tag itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LogRecord:
    """A single tamper-evident log entry."""

    log_id: str
    seq: int
    timestamp: str
    event_type: str
    details: dict[str, Any] = field(default_factory=dict)
    key_id: str | None = None
    prev_tag: str | None = None
    tag: str | None = None

    # TODO (ALL): Agree on whether to add a 'mode' field for self-describing records.
