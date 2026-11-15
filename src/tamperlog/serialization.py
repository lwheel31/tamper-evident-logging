"""Deterministic JSON-to-UTF-8 serialization for tag computation.

The canonical byte representation of a record is used as hash/HMAC input.
It MUST exclude the 'tag' field so the tag is never part of its own input.

Owner: ALL (shared module — everyone reviews)
"""

from __future__ import annotations

import json
from typing import Any

from .schema import LogRecord


def canonical_bytes(record: LogRecord) -> bytes:
    """Return the deterministic UTF-8 byte representation of *record* for hashing.

    The 'tag' field is excluded. Keys are sorted, no extra whitespace,
    ensure_ascii=True for reproducibility across platforms.
    """
    # TODO (ALL): Confirm this serialization is truly deterministic for
    # nested dicts/lists in 'details'. Consider whether float keys or
    # non-string dict keys could appear and break sorting.
    d: dict[str, Any] = {
        "log_id": record.log_id,
        "seq": record.seq,
        "timestamp": record.timestamp,
        "event_type": record.event_type,
        "details": record.details,
        "key_id": record.key_id,
        "prev_tag": record.prev_tag,
        # 'tag' intentionally omitted
    }
    return json.dumps(d, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def record_to_jsonl(record: LogRecord) -> str:
    """Serialize a LogRecord to a single JSONL line (for storage)."""
    d: dict[str, Any] = {
        "log_id": record.log_id,
        "seq": record.seq,
        "timestamp": record.timestamp,
        "event_type": record.event_type,
        "details": record.details,
        "key_id": record.key_id,
        "prev_tag": record.prev_tag,
        "tag": record.tag,
    }
    return json.dumps(d, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def jsonl_to_record(line: str) -> LogRecord:
    """Deserialize a JSONL line back into a LogRecord."""
    d = json.loads(line)
    return LogRecord(**d)
