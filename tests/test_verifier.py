"""Modes A-D checks and attacks; key/checkpoint persistence is mocked."""

import hashlib
import hmac
import json
import sys
from unittest.mock import Mock, call

import pytest

from tamperlog import checkpoints, keyring
from tamperlog.events import generate_events
from tamperlog.loggers import (GENESIS_TAG, HashChainLogger, HMACChainLogger,
                               HMACCheckpointLogger, PlaintextLogger)
from tamperlog.schema import LogRecord
from tamperlog.serialization import canonical_bytes
from tamperlog.verifier import (verify_hash_chain, verify_hmac_chain,
                                verify_hmac_checkpoint, verify_plaintext)


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


# Security-store tests mock Ashton's interface, never his storage implementation.
KEY_A = b"A" * 32
KEY_B = b"B" * 32


@pytest.fixture
def hmac_case(tmp_path, monkeypatch):
    path = tmp_path / "c.jsonl"
    store = tmp_path / "trusted-keys"
    keys = {"k1": KEY_A, "k2": KEY_B}
    load = Mock(side_effect=lambda name, store_path: keys[name])
    monkeypatch.setattr(keyring, "load_key", load)
    logger = HMACChainLogger("run-001", path, "k1", key=KEY_A)
    records = [logger.append(*event).__dict__.copy() for event in generate_events(5)]
    return path, records, store, keys, load


def test_valid_hmac_chain(hmac_case):
    path, _, store, _, load = hmac_case
    result = verify_hmac_chain(path, store)
    assert result.valid is True
    assert result.mode == "C"
    assert result.log_id == "run-001"
    assert result.total_records == 5
    assert result.first_bad_seq is None and result.error is None
    assert load.call_args_list == [call("k1", store)] * 5


@pytest.mark.parametrize("field,value,reason", [
    ("timestamp", "2026-11-17T23:59:59Z", "HMAC-SHA256 digest mismatch"),
    ("event_type", "ATTACKER_EVENT", "HMAC-SHA256 digest mismatch"),
    ("details", {"file": "innocent.txt"}, "HMAC-SHA256 digest mismatch"),
    ("key_id", "k2", "HMAC-SHA256 digest mismatch"),
    ("log_id", "other", "log_id differs"),
    ("seq", True, "seq must be an integer"),
    ("prev_tag", "f" * 64, "prev_tag does not match"),
    ("tag", "0" * 64, "HMAC-SHA256 digest mismatch"),
    ("details", {"x": 1.5}, "floats are not allowed"),
])
def test_hmac_record_damage(hmac_case, field, value, reason):
    path, records, store, _, _ = hmac_case
    records[2][field] = value
    write_records(path, records)
    assert_failure(verify_hmac_chain(path, store), 2, reason)


@pytest.mark.parametrize("attack", ["delete", "reorder"])
def test_hmac_sequence_attacks(hmac_case, attack):
    path, records, store, _, _ = hmac_case
    if attack == "delete":
        del records[1]
    else:
        records[1], records[2] = records[2], records[1]
    write_records(path, records)
    assert_failure(verify_hmac_chain(path, store), 1, "sequence mismatch")


def test_hmac_public_rehash_does_not_forge(hmac_case):
    path, records, store, _, _ = hmac_case
    records[0]["details"] = {"file": "innocent.txt"}
    rehash(records)
    write_records(path, records)
    assert_failure(verify_hmac_chain(path, store), 0, "HMAC-SHA256 digest mismatch")


def test_hmac_wrong_key(hmac_case):
    path, _, store, keys, _ = hmac_case
    keys["k1"] = KEY_B
    assert_failure(verify_hmac_chain(path, store), 0, "HMAC-SHA256 digest mismatch")


@pytest.mark.parametrize("missing_id", ["k1", "k2"])
def test_hmac_rotation_and_missing_historical_key(hmac_case, missing_id):
    path, _, store, keys, _ = hmac_case
    # Build genuine logger output with rotation; the link must not reset.
    rotated = path.with_name("rotated.jsonl")
    logger = HMACChainLogger("rotated", rotated, "k1", key=KEY_A)
    events = list(generate_events(5))
    for event in events[:2]:
        logger.append(*event)
    logger.switch_key("k2", key=KEY_B)
    for event in events[2:]:
        logger.append(*event)
    assert verify_hmac_chain(rotated, store).valid is True
    del keys[missing_id]
    with pytest.raises(RuntimeError, match=f"cannot verify: key '{missing_id}' unavailable"):
        verify_hmac_chain(rotated, store)


@pytest.mark.parametrize("failure", [KeyError("missing"), PermissionError("denied"),
                                    OSError("offline"), NotImplementedError("pending")])
def test_hmac_key_dependency_failures(hmac_case, failure):
    path, _, store, _, load = hmac_case
    load.side_effect = failure
    with pytest.raises(RuntimeError, match="cannot verify: key 'k1' unavailable"):
        verify_hmac_chain(path, store)


@pytest.mark.parametrize("key", [None, b"", b"short", "A" * 32, bytearray(KEY_A)])
def test_hmac_invalid_loaded_keys(hmac_case, key):
    path, _, store, keys, _ = hmac_case
    keys["k1"] = key
    with pytest.raises(RuntimeError, match="must be bytes of at least 32 bytes"):
        verify_hmac_chain(path, store)


@pytest.mark.parametrize("key_id", [None, True, "", "../secret", "/tmp/secret",
                                   "..\\secret", "C:secret", "k*", "k?", "k[1]",
                                   "k\x00", "k.1", "é", "a" * 129,
                                   "NUL", "con", "COM1", "lpt9"])
def test_hmac_unsafe_key_ids_never_reach_store(hmac_case, key_id):
    path, records, store, _, load = hmac_case
    records[0]["key_id"] = key_id
    write_records(path, records)
    assert_failure(verify_hmac_chain(path, store), 0, "safe store identifier")
    load.assert_not_called()


@pytest.mark.parametrize("remaining", [0, 1, 3])
def test_hmac_tail_truncation_passes(hmac_case, remaining):
    path, records, store, _, _ = hmac_case
    write_records(path, records[:remaining])
    result = verify_hmac_chain(path, store)
    assert result.valid is True
    assert result.total_records == remaining


def test_hmac_key_id_is_authenticated_even_with_equal_key_bytes(hmac_case):
    path, records, store, keys, _ = hmac_case
    keys["k2"] = KEY_A
    records[2]["key_id"] = "k2"
    write_records(path, records)
    assert_failure(verify_hmac_chain(path, store), 2, "HMAC-SHA256 digest mismatch")


@pytest.mark.parametrize("position", [0, 4], ids=["genesis", "final"])
def test_hmac_linkage_with_correct_record_mac(hmac_case, position):
    path, records, store, _, _ = hmac_case
    records[position]["prev_tag"] = "f" * 64
    records[position]["tag"] = hmac.new(
        KEY_A, canonical_bytes(LogRecord(**records[position])), hashlib.sha256).hexdigest()
    write_records(path, records)
    assert_failure(verify_hmac_chain(path, store), position, "prev_tag does not match")


def test_hmac_final_record_corruption(hmac_case):
    path, records, store, _, _ = hmac_case
    records[-1]["details"] = {"file": "innocent.txt"}
    write_records(path, records)
    assert_failure(verify_hmac_chain(path, store), 4, "HMAC-SHA256 digest mismatch")


@pytest.mark.parametrize("mode", ["C", "D"])
def test_hmac_independent_vector(tmp_path, monkeypatch, mode):
    # HMAC independently calculated with OpenSSL dgst -sha256 -mac HMAC,
    # hexkey 41 repeated 32 times, over these hand-written canonical bytes.
    # No shared serializer/logger or hmac.new builds the test's expected tag.
    payload = (b'{"details":{"nested":{"a":[true,null,-3,{"x":"Jos\\u00e9"}],"z":2}},'
               b'"event_type":"LOGIN","key_id":"k1","log_id":"vector","prev_tag":"'
               + b"0" * 64 + b'","seq":0,"timestamp":"2026-11-17T12:00:00Z"}')
    record = json.loads(payload)
    record["tag"] = "8b41ea2ff1d703a6e6cb77dca28a4c718d0b62a80aabae177247cb23e25edd44"
    path = tmp_path / "vector.jsonl"
    write_records(path, [record])
    monkeypatch.setattr(keyring, "load_key", Mock(return_value=KEY_A))
    monkeypatch.setattr(checkpoints, "load_checkpoints", Mock(return_value=[
        checkpoints.Checkpoint("vector", 0, record["tag"])]))

    def verify():
        if mode == "C":
            return verify_hmac_chain(path, tmp_path / "keys")
        return verify_hmac_checkpoint(path, tmp_path / "keys", tmp_path / "checkpoints",
                                      expected_log_id="vector")

    assert verify().valid is True
    record["details"]["nested"]["z"] = 3
    write_records(path, [record])
    assert_failure(verify(), 0, "HMAC-SHA256 digest mismatch")


@pytest.fixture
def checkpoint_case(hmac_case, tmp_path, monkeypatch):
    path, records, key_store, _, _ = hmac_case
    checkpoint_store = tmp_path / "trusted-checkpoints"
    # Independent snapshot of trusted anchors, unaffected by stored-log edits.
    trusted = [checkpoints.Checkpoint(record["log_id"], record["seq"], record["tag"])
               for record in records]
    load = Mock(return_value=trusted)
    monkeypatch.setattr(checkpoints, "load_checkpoints", load)
    return path, records, key_store, checkpoint_store, trusted, load


def test_valid_checkpoint_verification(checkpoint_case):
    path, _, keys, store, _, load = checkpoint_case
    result = verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001")
    assert result.valid is True
    assert result.mode == "D" and result.log_id == "run-001"
    assert result.total_records == 5
    assert result.first_bad_seq is None and result.error is None
    load.assert_called_once_with("run-001", store)


def test_checkpoint_identity_argument_is_required(checkpoint_case):
    path, _, keys, store, _, load = checkpoint_case
    with pytest.raises(TypeError, match="expected_log_id"):
        verify_hmac_checkpoint(path, keys, store)
    load.assert_not_called()


@pytest.mark.parametrize("expected", [None, "", "../other", "other*", "a" * 129])
def test_checkpoint_unsafe_expected_identity(checkpoint_case, expected):
    path, _, keys, store, _, load = checkpoint_case
    with pytest.raises(ValueError, match="expected_log_id must be a safe store identifier"):
        verify_hmac_checkpoint(path, keys, store, expected_log_id=expected)
    load.assert_not_called()


@pytest.mark.parametrize("remaining", [0, 1, 3])
def test_checkpoint_tail_truncation_fails(checkpoint_case, remaining):
    path, records, keys, store, _, _ = checkpoint_case
    write_records(path, records[:remaining])
    result = verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001")
    assert result.valid is False
    assert result.log_id == "run-001"
    assert result.total_records == remaining
    assert result.first_bad_seq == remaining
    assert "missing record" in result.error


def test_checkpoint_deleted_file_fails(checkpoint_case):
    path, _, keys, store, _, _ = checkpoint_case
    path.unlink()
    result = verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001")
    assert result.valid is False
    assert result.total_records == 0 and result.first_bad_seq == 0
    assert result.log_id == "run-001"
    assert "log file missing" in result.error


@pytest.mark.parametrize("attack,reason", [("modify", "HMAC-SHA256 digest mismatch"),
                                         ("delete", "sequence mismatch"),
                                         ("reorder", "sequence mismatch")])
def test_checkpoint_underlying_hmac_attacks(checkpoint_case, attack, reason):
    path, records, keys, store, _, _ = checkpoint_case
    if attack == "modify":
        records[1]["details"] = {"file": "innocent.txt"}
    elif attack == "delete":
        del records[1]
    else:
        records[1], records[2] = records[2], records[1]
    write_records(path, records)
    assert_failure(verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001"), 1, reason)


def test_checkpoint_mismatch_on_valid_hmac_chain(checkpoint_case):
    path, _, keys, store, trusted, _ = checkpoint_case
    trusted[2].tag = "f" * 64
    assert verify_hmac_chain(path, keys).valid is True
    assert_failure(verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001"),
                   2, "tag differs from trusted checkpoint")


@pytest.mark.parametrize("missing", ["all", "middle", "last"])
def test_required_checkpoints_missing(checkpoint_case, missing):
    path, _, keys, store, trusted, _ = checkpoint_case
    if missing == "all":
        trusted.clear()
    elif missing == "middle":
        del trusted[2]
    else:
        trusted.pop()
    with pytest.raises(RuntimeError, match="cannot verify"):
        verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001")


@pytest.mark.parametrize("failure", [KeyError("missing"), PermissionError("denied"),
                                    OSError("offline"), ValueError("bad JSON"),
                                    NotImplementedError("pending")])
def test_checkpoint_dependency_failures(checkpoint_case, failure):
    path, _, keys, store, _, load = checkpoint_case
    load.side_effect = failure
    with pytest.raises(RuntimeError, match="cannot verify: trusted checkpoints unavailable"):
        verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001")


@pytest.mark.parametrize("damage", ["identity", "bool-seq", "duplicate", "unordered",
                                   "bad-tag", "wrong-type", "sparse"])
def test_invalid_trusted_checkpoint_data(checkpoint_case, damage):
    path, _, keys, store, trusted, _ = checkpoint_case
    if damage == "identity":
        trusted[1].log_id = "other"
    elif damage == "bool-seq":
        trusted[1].seq = True
    elif damage == "duplicate":
        trusted[1].seq = 0
    elif damage == "unordered":
        trusted[1], trusted[2] = trusted[2], trusted[1]
    elif damage == "bad-tag":
        trusted[1].tag = "invalid"
    elif damage == "wrong-type":
        trusted[1] = {"log_id": "run-001", "seq": 1, "tag": "0" * 64}
    else:
        trusted[:] = trusted[1::2]  # checkpoint_interval=2 is unsupported
    with pytest.raises(RuntimeError, match="cannot verify: checkpoints must"):
        verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001")


@pytest.mark.parametrize("returned", [None, (), {}])
def test_invalid_checkpoint_container(checkpoint_case, returned):
    path, _, keys, store, _, load = checkpoint_case
    load.return_value = returned
    with pytest.raises(RuntimeError, match="nonempty trusted checkpoint list"):
        verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001")


def test_checkpoint_empty_log_without_anchors_cannot_pass(checkpoint_case):
    path, _, keys, store, trusted, _ = checkpoint_case
    path.write_bytes(b"")
    trusted.clear()
    with pytest.raises(RuntimeError, match="nonempty trusted checkpoint list"):
        verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001")


def test_checkpoint_log_substitution_uses_trusted_identity(checkpoint_case):
    path, _, keys, store, trusted, load = checkpoint_case
    other = path.with_name("other.jsonl")
    logger = HMACChainLogger("other-log", other, "k1", key=KEY_A)
    other_records = [logger.append(*event) for event in generate_events(5)]
    other_checkpoints = [checkpoints.Checkpoint(r.log_id, r.seq, r.tag) for r in other_records]
    available = {"run-001": trusted, "other-log": other_checkpoints}
    load.side_effect = lambda identity, store_path: available[identity]
    assert verify_hmac_chain(other, keys).valid is True  # authentic other log
    assert_failure(verify_hmac_checkpoint(other, keys, store, expected_log_id="run-001"),
                   0, "log_id differs from expected identity")
    load.assert_called_once_with("run-001", store)
    # Selecting the other identity deliberately verifies the other log. The
    # caller's independent identity, not access to its key, prevents substitution.
    assert verify_hmac_checkpoint(other, keys, store, expected_log_id="other-log").valid is True


def test_checkpoint_same_identity_replay_fails(checkpoint_case):
    path, _, keys, store, _, _ = checkpoint_case
    other = path.with_name("other-history.jsonl")
    # Represents another already signed artifact available to a storage reader;
    # constructing the fixture with a key does not give that key to the attacker.
    logger = HMACChainLogger("run-001", other, "k1", key=KEY_A)
    for timestamp, event_type, details in generate_events(5):
        logger.append(timestamp, event_type, {**details, "history": "different"})
    assert verify_hmac_chain(other, keys).valid is True
    assert_failure(verify_hmac_checkpoint(other, keys, store, expected_log_id="run-001"),
                   0, "tag differs from trusted checkpoint")


def test_checkpoint_silently_incomplete_trusted_snapshot_is_not_detectable(checkpoint_case):
    path, records, keys, store, trusted, _ = checkpoint_case
    # A faulty/stale TRUSTED loader returning only a prefix violates its
    # load-all contract. The verifier has no independent checkpoint count.
    # This is a dependency limit, not a permitted storage-only attacker action.
    del trusted[3:]
    write_records(path, records[:3])
    assert verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001").valid is True


def test_checkpoint_malformed_log_does_not_trigger_key_lookup(checkpoint_case, hmac_case):
    path, _, keys, store, _, _ = checkpoint_case
    *_, load_key = hmac_case
    path.write_text('{"details":{"x":1,"x":2}}\n', encoding="utf-8")
    assert_failure(verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001"),
                   0, "duplicate JSON key")
    load_key.assert_not_called()


def test_checkpoint_key_dependency_failure_is_not_success(checkpoint_case, hmac_case):
    path, _, keys, store, _, _ = checkpoint_case
    *_, load_key = hmac_case
    load_key.side_effect = KeyError("missing")
    with pytest.raises(RuntimeError, match="cannot verify: key"):
        verify_hmac_checkpoint(path, keys, store, expected_log_id="run-001")


def test_checkpoint_logger_rotation_with_mocked_security_stores(tmp_path, monkeypatch):
    # Exercises real logger/verifier wiring but NOT on-disk key/checkpoint stores.
    path = tmp_path / "d.jsonl"
    keys, store = tmp_path / "keys", tmp_path / "checkpoints"
    trusted = []

    def create(identity, seq, tag, store_path):
        assert store_path == store
        checkpoint = checkpoints.Checkpoint(identity, seq, tag)
        trusted.append(checkpoint)
        return checkpoint

    monkeypatch.setattr(checkpoints, "create_checkpoint", create)
    monkeypatch.setattr(checkpoints, "load_checkpoints", Mock(return_value=trusted))
    monkeypatch.setattr(keyring, "load_key", lambda name, store_path: {"k1": KEY_A, "k2": KEY_B}[name])
    logger = HMACCheckpointLogger("rotation", path, "k1", store, key=KEY_A)
    events = list(generate_events(5))
    for event in events[:2]:
        logger.append(*event)
    logger.switch_key("k2", key=KEY_B)
    for event in events[2:]:
        logger.append(*event)
    assert [cp.seq for cp in trusted] == list(range(5))
    assert verify_hmac_checkpoint(path, keys, store, expected_log_id="rotation").valid is True
