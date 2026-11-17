"""Verifier checks and explicit demonstrations of Modes A/B security limits."""

import hashlib
import json
import sys

import pytest

from tamperlog.events import generate_events
from tamperlog.loggers import GENESIS_TAG, HashChainLogger, PlaintextLogger
from tamperlog.schema import LogRecord
from tamperlog.serialization import canonical_bytes
from tamperlog.verifier import verify_hash_chain, verify_plaintext


@pytest.fixture(params=[("A", PlaintextLogger, verify_plaintext),
                       ("B", HashChainLogger, verify_hash_chain)], ids=["A", "B"])
def log_case(request, tmp_path):
    mode, logger_type, verify = request.param
    path = tmp_path / "log.jsonl"
    logger = logger_type("run-001", path)
    for event in generate_events(5):
        logger.append(*event)
    records = [json.loads(line) for line in path.read_text().splitlines()]
    return mode, path, records, verify


def write_records(path, records):
    path.write_text("".join(json.dumps(record, ensure_ascii=True) + "\n"
                            for record in records), encoding="utf-8")


def rehash(records):
    """Storage-only attacker: no keys, logger, or trusted state required."""
    previous = GENESIS_TAG
    for record in records:
        record["prev_tag"] = previous
        record["tag"] = hashlib.sha256(canonical_bytes(LogRecord(**record))).hexdigest()
        previous = record["tag"]


def assert_failure(result, seq, reason):
    assert result.valid is False
    assert result.first_bad_seq == seq
    assert result.total_records == seq + 1
    assert result.error.startswith(f"line {seq + 1}:")
    assert reason in result.error


def test_valid_logs(log_case):
    mode, path, _, verify = log_case
    result = verify(path)
    assert result.mode == mode
    assert result.log_id == "run-001"
    assert result.total_records == 5
    assert result.valid is True
    assert result.first_bad_seq is None
    assert result.error is None


def test_empty_log(log_case):
    mode, path, _, verify = log_case
    path.write_bytes(b"")
    result = verify(path)
    assert result.mode == mode
    assert result.valid is True
    assert result.total_records == 0
    assert result.log_id == ""
    assert result.first_bad_seq is None
    assert result.error is None


def test_missing_file_is_not_an_empty_log(log_case):
    _, path, _, verify = log_case
    with pytest.raises(FileNotFoundError):
        verify(path.with_name("missing.jsonl"))


@pytest.mark.parametrize("field", ["log_id", "seq", "timestamp", "event_type",
                                   "details", "key_id", "prev_tag", "tag"])
def test_every_field_is_required(log_case, field):
    _, path, records, verify = log_case
    del records[1][field]
    write_records(path, records)
    result = verify(path)
    assert_failure(result, 1, f"missing fields: {field}")
    assert result.log_id == "run-001"


def test_extra_field_rejected(log_case):
    _, path, records, verify = log_case
    records[1]["unsigned_extra"] = "hidden"
    write_records(path, records)
    assert_failure(verify(path), 1, "unexpected fields: unsigned_extra")


@pytest.mark.parametrize("field,value,reason", [
    ("log_id", None, "log_id must be a string"),
    ("log_id", 1, "log_id must be a string"),
    ("timestamp", 123, "timestamp must be a string"),
    ("timestamp", "not-a-date", "ISO 8601 UTC"),
    ("timestamp", "2026-11-17", "ISO 8601 UTC"),
    ("timestamp", "2026-11-17T12:00:00", "ISO 8601 UTC"),
    ("timestamp", "2026-11-17T12:00:00-05:00", "ISO 8601 UTC"),
    ("timestamp", "2026-02-30T12:00:00Z", "ISO 8601 UTC"),
    ("event_type", [], "event_type must be a string"),
    ("details", [], "details must be an object"),
    ("details", None, "details must be an object"),
    ("seq", True, "seq must be an integer"),
    ("seq", False, "seq must be an integer"),
    ("seq", "1", "seq must be an integer"),
    ("seq", 1.0, "seq must be an integer"),
    ("seq", None, "seq must be an integer"),
    ("key_id", "k1", "key_id must be null"),
    ("key_id", 7, "key_id must be null"),
])
def test_invalid_field_values(log_case, field, value, reason):
    _, path, records, verify = log_case
    records[1][field] = value
    write_records(path, records)
    assert_failure(verify(path), 1, reason)


@pytest.mark.parametrize("timestamp", [
    "2026-11-17T12:00:00Z:00", "2026-11-17T12:00:00Z.5",
    "2026-11-17T12:00:00ZZ", "2026-11-17T12:00:00Z+00:00",
    "2026-11-17T12:00:00+00:00:00.5", "2026-11-17T12:00:00Z\n",
    "2026-11-17T12:00:00.Z", "2026-11-17T12:00:00-00:00",
])
def test_malformed_utc_suffixes(log_case, timestamp):
    mode, path, records, verify = log_case
    records[1]["timestamp"] = timestamp
    if mode == "B":
        rehash(records)  # a matching digest must not conceal invalid structure
    write_records(path, records)
    assert_failure(verify(path), 1, "ISO 8601 UTC")


@pytest.mark.parametrize("timestamp", [
    "2026-11-17T12:00:00Z", "2026-11-17T12:00:00+00:00",
    "2026-11-17T12:00:00.123456Z", "2026-11-17T12:00:00.5+00:00",
])
def test_supported_utc_syntax(log_case, timestamp):
    mode, path, records, verify = log_case
    records[1]["timestamp"] = timestamp
    if mode == "B":
        rehash(records)
    write_records(path, records)
    assert verify(path).valid is True


def test_finite_floats_are_plaintext_only(log_case):
    mode, path, records, verify = log_case
    records[1]["details"] = {"nested": [{"amount": 1.5}]}
    write_records(path, records)
    if mode == "A":
        assert verify(path).valid is True
    else:
        assert_failure(verify(path), 1, "floats are not allowed in signed data")


def test_untouched_plaintext_logger_with_finite_floats(tmp_path):
    path = tmp_path / "floats.jsonl"
    logger = PlaintextLogger("floats", path)
    logger.append("2026-11-17T12:00:00Z", "MEASUREMENT",
                  {"amount": 1.5, "nested": [0.0, -0.0, -2.75, 1e308, 5e-324]})
    # Verify the logger's actual bytes, without parsing or rewriting the file.
    result = verify_plaintext(path)
    assert result.valid is True
    assert result.total_records == 1
    assert result.log_id == "floats"


@pytest.mark.parametrize("number", ["1e400", "-1e400"])
def test_overflowing_json_floats_are_rejected(log_case, number):
    _, path, records, verify = log_case
    records[1]["details"] = {"nested": ["NUMBER"]}
    lines = [json.dumps(record) for record in records]
    lines[1] = lines[1].replace('"NUMBER"', number)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert_failure(verify(path), 1, "JSON float must be finite")


@pytest.mark.parametrize("seq", [-1, 0, 2, 999])
def test_sequence_must_equal_expected_position(log_case, seq):
    _, path, records, verify = log_case
    records[1]["seq"] = seq
    write_records(path, records)
    assert_failure(verify(path), 1, f"sequence mismatch: expected 1, got {seq}")


def test_sequence_starts_at_zero(log_case):
    _, path, records, verify = log_case
    records[0]["seq"] = 1
    write_records(path, records)
    assert_failure(verify(path), 0, "sequence mismatch: expected 0, got 1")


def test_log_identity_is_consistent_even_after_rehash(log_case):
    mode, path, records, verify = log_case
    records[1]["log_id"] = "different-log"
    if mode == "B":
        rehash(records)
    write_records(path, records)
    assert_failure(verify(path), 1, "log_id differs")


@pytest.mark.parametrize("line,reason", [
    ("not json", "Expecting value"),
    ('{"seq":', "Expecting value"),
    ("", "Expecting value"),
    ("   ", "Expecting value"),
    ("[]", "JSON object"),
    ("null", "JSON object"),
    ("42", "JSON object"),
    ('{"seq":1,"seq":1}', "duplicate JSON key: 'seq'"),
    ('{"details":{"nested":[{"x":1,"x":2}]}}', "duplicate JSON key: 'x'"),
    ('{"details":{"x":NaN}}', "invalid JSON constant: NaN"),
    ('{"details":{"x":Infinity}}', "invalid JSON constant: Infinity"),
    ('{"details":{"x":-Infinity}}', "invalid JSON constant: -Infinity"),
])
def test_bad_json_lines_are_never_skipped(log_case, line, reason):
    _, path, records, verify = log_case
    lines = [json.dumps(record) for record in records]
    lines[1] = line
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert_failure(verify(path), 1, reason)


def test_invalid_utf8(log_case):
    _, path, records, verify = log_case
    path.write_bytes(json.dumps(records[0]).encode() + b"\n\xff\n")
    assert_failure(verify(path), 1, "utf-8")


def test_first_error_wins_over_later_encoding_error(log_case):
    _, path, _, verify = log_case
    path.write_bytes(b"not json\n\xff\n")
    result = verify(path)
    assert_failure(result, 0, "Expecting value")
    assert result.log_id == ""


def test_deeply_nested_hash_payload_fails_cleanly(tmp_path):
    path = tmp_path / "nested.jsonl"
    record = HashChainLogger("x", path).append(
        "2026-11-17T12:00:00Z", "LOGIN", {}).__dict__.copy()
    depth = sys.getrecursionlimit() + 100
    record["details"] = None
    line = json.dumps(record).replace(
        '"details": null', '"details": {"nested":'
        + "[" * depth + "0" + "]" * depth + "}")
    path.write_text(line + "\n")
    # Mode B's canonical traversal is recursive. Mode A's parser may support
    # deeper JSON; neither mode promises a fixed nesting limit.
    assert_failure(verify_hash_chain(path), 0, "recursion")


@pytest.mark.parametrize("field", ["prev_tag", "tag"])
@pytest.mark.parametrize("value", [None, 123, True, [], "", "0" * 63,
                                 "0" * 65, "g" * 64, "A" * 64, "é" * 64])
def test_hash_tags_require_exact_lowercase_hex(tmp_path, field, value):
    path = tmp_path / "b.jsonl"
    logger = HashChainLogger("x", path)
    record = logger.append("2026-11-17T12:00:00Z", "LOGIN", {}).__dict__.copy()
    record[field] = value
    write_records(path, [record])
    assert_failure(verify_hash_chain(path), 0, f"{field} must be 64 lowercase")


@pytest.mark.parametrize("field", ["prev_tag", "tag"])
@pytest.mark.parametrize("value", ["0" * 64, 123, False])
def test_plaintext_tags_must_be_null(tmp_path, field, value):
    path = tmp_path / "a.jsonl"
    record = PlaintextLogger("x", path).append(
        "2026-11-17T12:00:00Z", "LOGIN", {}).__dict__.copy()
    record[field] = value
    write_records(path, [record])
    assert_failure(verify_plaintext(path), 0, f"{field} must be null")


def test_modification_and_rehashed_rewrite(log_case):
    mode, path, records, verify = log_case
    incident = next(i for i, record in enumerate(records)
                    if record["event_type"] == "DATA_EXPORT")
    assert records[incident]["details"]["file"] == "payroll.db"
    records[incident]["event_type"] = "LOGIN_SUCCESS"
    records[incident]["details"] = {"user": "innocent"}
    write_records(path, records)
    result = verify(path)
    if mode == "A":
        assert result.valid is True  # structural success is not integrity
    else:
        assert_failure(result, incident, "SHA-256 digest mismatch")
        rehash(records)  # a malicious storage writer knows everything needed
        write_records(path, records)
        assert verify(path).valid is True


@pytest.mark.parametrize("position", [2, 4], ids=["middle", "final"])
@pytest.mark.parametrize("field,value", [
    ("timestamp", "2026-11-17T23:59:59Z"),
    ("event_type", "ATTACKER_EVENT"),
    ("details", {"nested": {"file": "innocent.txt"}}),
])
def test_individual_field_tampering(log_case, position, field, value):
    mode, path, records, verify = log_case
    assert records[position][field] != value
    records[position][field] = value
    write_records(path, records)  # preserve every original tag
    result = verify(path)
    if mode == "A":
        assert result.valid is True
    else:
        assert_failure(result, position, "SHA-256 digest mismatch")


@pytest.mark.parametrize("position", [0, 2])
def test_broken_link_with_correct_record_digest(tmp_path, position):
    path = tmp_path / "b.jsonl"
    logger = HashChainLogger("x", path)
    records = [logger.append(*event).__dict__.copy() for event in generate_events(5)]
    records[position]["prev_tag"] = "f" * 64
    # The altered record's digest is correct; linkage must be checked separately.
    records[position]["tag"] = hashlib.sha256(
        canonical_bytes(LogRecord(**records[position]))).hexdigest()
    write_records(path, records)
    assert_failure(verify_hash_chain(path), position, "prev_tag does not match")


def test_wrong_stored_digest(tmp_path):
    path = tmp_path / "b.jsonl"
    record = HashChainLogger("x", path).append(
        "2026-11-17T12:00:00Z", "LOGIN", {}).__dict__.copy()
    record["tag"] = "0" * 64
    write_records(path, [record])
    assert_failure(verify_hash_chain(path), 0, "SHA-256 digest mismatch")


@pytest.mark.parametrize("attack", ["delete", "reorder", "duplicate"])
def test_internal_sequence_damage(log_case, attack):
    _, path, records, verify = log_case
    if attack == "delete":
        del records[1]
    elif attack == "reorder":
        records[1], records[2] = records[2], records[1]
    else:
        records.insert(1, records[0].copy())
    write_records(path, records)
    assert_failure(verify(path), 1, "sequence mismatch")


@pytest.mark.parametrize("remaining", [0, 1, 3])
def test_tail_truncation_is_undetectable(log_case, remaining):
    _, path, records, verify = log_case
    write_records(path, records[:remaining])
    result = verify(path)
    assert result.valid is True
    assert result.total_records == remaining


def test_rehashed_deletion_and_identity_replacement_pass(tmp_path):
    path = tmp_path / "b.jsonl"
    logger = HashChainLogger("original", path)
    records = [logger.append(*event).__dict__.copy() for event in generate_events(5)]
    records = [record for record in records if record["event_type"] != "DATA_EXPORT"]
    for seq, record in enumerate(records):
        record["seq"] = seq
        record["log_id"] = "attacker-chosen"
    rehash(records)
    write_records(path, records)
    result = verify_hash_chain(path)
    assert result.valid is True
    assert result.log_id == "attacker-chosen"
    assert result.total_records == 4


def test_json_formatting_and_supported_payloads(log_case):
    mode, path, records, verify = log_case
    records[0]["timestamp"] = "2026-11-17T12:00:00+00:00"
    records[0]["details"] = {"unicode": "José", "nested": [True, False, None,
                              -3, {"b": 2, "a": 1}]}
    if mode == "B":
        rehash(records)
    # Change object key order, whitespace, Unicode escaping, and line endings;
    # tags cover canonical record values, not storage formatting.
    lines = [json.dumps(dict(reversed(list(record.items()))), ensure_ascii=False)
             for record in records]
    path.write_bytes("\r\n".join(lines).encode("utf-8"))  # final newline optional
    assert verify(path).valid is True


@pytest.mark.parametrize("details", [
    b'{}',
    (b'{"nested":{"a":[true,false,null,-3,{"x":"Jos\\u00e9"}],"z":2},'
     b'"path":"payroll.db"}'),
], ids=["empty", "nested"])
def test_hash_verifier_accepts_independently_constructed_record(tmp_path, details):
    path = tmp_path / "independent.jsonl"
    # Hand-written canonical bytes: neither logger nor serializer builds this
    # test's expected digest. tag is excluded; prev_tag and key_id are included.
    payload = (b'{"details":' + details
               + b',"event_type":"LOGIN","key_id":null,"log_id":"x",'
               b'"prev_tag":"' + b"0" * 64
               + b'","seq":0,"timestamp":"2026-11-17T12:00:00Z"}')
    record = json.loads(payload)
    record["tag"] = hashlib.sha256(payload).hexdigest()
    write_records(path, [record])
    assert verify_hash_chain(path).valid is True


@pytest.mark.skip(reason="PENDING — verifier not yet implemented")
def test_verify_hmac_chain_valid():
    pass


@pytest.mark.skip(reason="PENDING — verifier not yet implemented")
def test_verify_hmac_missing_key_is_not_valid():
    """A missing historical key must NOT produce valid=True."""
    pass


@pytest.mark.skip(reason="PENDING — verifier not yet implemented")
def test_verify_hmac_checkpoint():
    pass
