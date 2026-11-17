"""Deterministic JSON-to-UTF-8 serialization for tag computation.

The logger and the verifier must turn a record into the EXACT same bytes,
or honest logs would fail verification. canonical_bytes() is that contract.
It excludes 'tag' so a tag is never part of its own input.

Owner: Lucas (first draft) - everyone reviews.
"""

from __future__ import annotations

import json
from typing import Any

from .schema import LogRecord

# Fields covered by the tag, in a fixed list (order doesn't matter: keys are sorted).
SIGNED_FIELDS = ("log_id", "seq", "timestamp", "event_type", "details", "key_id", "prev_tag")


def _check_canonical(value: Any, where: str = "details") -> None:
    """Reject values that JSON can't encode unambiguously.

    - Non-string dict keys: json turns 1 and "1" into the same key "1",
      so two different records could produce identical bytes.
    - Floats: their text form can differ between systems; keep payloads to
      strings, ints, bools, None, lists and dicts.
    """
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError(f"{where}: dict keys must be strings, got {k!r}")
            _check_canonical(v, f"{where}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _check_canonical(v, f"{where}[{i}]")
    elif isinstance(value, float):
        raise TypeError(f"{where}: floats are not allowed in signed data")
    elif not (value is None or isinstance(value, (str, int, bool))):
        raise TypeError(f"{where}: unsupported type {type(value).__name__}")


def _dumps(d: dict[str, Any]) -> str:
    # sort_keys: same order every time. separators: no optional spaces.
    # ensure_ascii: non-ASCII becomes \\uXXXX, identical on every OS.
    return json.dumps(d, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def canonical_bytes(record: LogRecord) -> bytes:
    """Return the deterministic bytes that get hashed/HMACed for *record* (tag excluded)."""
    d = {name: getattr(record, name) for name in SIGNED_FIELDS}
    _check_canonical(d, "record")
    return _dumps(d).encode("utf-8")


def record_to_jsonl(record: LogRecord) -> str:
    """Serialize a LogRecord to one JSONL line (for storage), tag included."""
    d = {name: getattr(record, name) for name in SIGNED_FIELDS}
    d["tag"] = record.tag
    return _dumps(d)


def jsonl_to_record(line: str) -> LogRecord:
    """Parse one JSONL line back into a LogRecord.

    Raises ValueError/TypeError on malformed lines (bad JSON, missing or extra
    fields). The verifier should treat that as 'tampered', never skip it.
    """
    d = json.loads(line)
    if not isinstance(d, dict):
        raise ValueError("log line is not a JSON object")
    return LogRecord(**d)
