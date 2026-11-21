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


def _rec(details):
    return LogRecord(log_id="t", seq=0, timestamp="2026-01-01T00:00:00Z",
                     event_type="X", details=details)


def test_key_order_does_not_change_bytes():
    assert canonical_bytes(_rec({"a": 1, "b": {"y": 2, "x": 3}})) == \
           canonical_bytes(_rec({"b": {"x": 3, "y": 2}, "a": 1}))


def test_unicode_is_stable():
    raw = canonical_bytes(_rec({"user": "Jos\u00e9"}))
    assert raw.isascii()
    assert jsonl_to_record(record_to_jsonl(_rec({"user": "Jos\u00e9"}))).details["user"] == "Jos\u00e9"


def test_non_string_keys_rejected():
    # {1: "x"} and {"1": "x"} would otherwise serialize identically
    with pytest.raises(TypeError):
        canonical_bytes(_rec({1: "x"}))


def test_floats_rejected():
    with pytest.raises(TypeError):
        canonical_bytes(_rec({"amount": 1.5}))


def test_malformed_line_raises():
    with pytest.raises((ValueError, TypeError)):
        jsonl_to_record('{"log_id": "t"}')  # missing fields
    with pytest.raises(ValueError):
        jsonl_to_record("not json")
