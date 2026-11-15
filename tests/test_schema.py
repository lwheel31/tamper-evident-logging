"""Tests for schema and serialization.

Owner: ALL (shared)
"""

import pytest
from tamperlog.schema import LogRecord
from tamperlog.serialization import canonical_bytes, record_to_jsonl, jsonl_to_record


def test_canonical_bytes_excludes_tag():
    """The tag field must not appear in canonical_bytes output."""
    rec = LogRecord(
        log_id="test", seq=0, timestamp="2026-01-01T00:00:00Z",
        event_type="LOGIN", details={"user": "alice"}, tag="should_not_appear",
    )
    raw = canonical_bytes(rec)
    assert b'"tag"' not in raw


def test_canonical_bytes_deterministic():
    """Same record must always produce identical bytes."""
    rec = LogRecord(
        log_id="test", seq=0, timestamp="2026-01-01T00:00:00Z",
        event_type="LOGIN", details={"b": 2, "a": 1},
    )
    assert canonical_bytes(rec) == canonical_bytes(rec)


def test_jsonl_roundtrip():
    """A record survives serialization and deserialization."""
    rec = LogRecord(
        log_id="test", seq=5, timestamp="2026-01-01T00:00:00Z",
        event_type="FILE_ACCESS", details={"path": "/etc/passwd"},
        key_id="k1", prev_tag="abc", tag="def",
    )
    line = record_to_jsonl(rec)
    restored = jsonl_to_record(line)
    assert restored == rec


# TODO (ALL): Add tests for edge cases — empty details, Unicode in details,
# very large seq numbers, None fields.


@pytest.mark.skip(reason="PENDING — events.generate_events not yet implemented")
def test_generate_events_deterministic():
    """Same seed must produce same event sequence."""
    pass
