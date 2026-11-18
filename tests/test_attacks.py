"""Attack artifacts and verifier outcomes; security persistence remains mocked."""

from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tamperlog import attacks, checkpoints, keyring
from tamperlog.events import generate_events
from tamperlog.loggers import (GENESIS_TAG, HashChainLogger, HMACChainLogger,
                               HMACCheckpointLogger, PlaintextLogger)
from tamperlog.schema import LogRecord
from tamperlog.serialization import canonical_bytes
from tamperlog.verifier import (verify_hash_chain, verify_hmac_chain,
                                verify_hmac_checkpoint, verify_plaintext)


def read_records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def write_records(path, records):
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


@pytest.fixture(params=["A", "B", "C", "D"])
def log_case(request, tmp_path, monkeypatch):
    mode = request.param
    path = tmp_path / "logs" / "events.jsonl"
    key_store, checkpoint_store = tmp_path / "keys", tmp_path / "checkpoints"
    key = b"A" * 32  # fixture only; attacks are never given this key or its store
    trusted = []

    def create(identity, seq, tag, store):
        assert store == checkpoint_store
        checkpoint = checkpoints.Checkpoint(identity, seq, tag)
        trusted.append(checkpoint)
        return checkpoint

    monkeypatch.setattr(checkpoints, "create_checkpoint", create)
    if mode == "A":
        logger = PlaintextLogger("run-001", path)
    elif mode == "B":
        logger = HashChainLogger("run-001", path)
    elif mode == "C":
        logger = HMACChainLogger("run-001", path, "k1", key=key)
    else:
        logger = HMACCheckpointLogger("run-001", path, "k1", checkpoint_store, key=key)
    for event in generate_events(5):
        logger.append(*event)
    original = path.read_bytes()
    # Sentinels check trusted files as well as mocked interface access.
    key_store.mkdir()
    checkpoint_store.mkdir()
    key_file = key_store / "k1.key"
    checkpoint_file = checkpoint_store / "sentinel.json"
    key_file.write_bytes(key)
    checkpoint_file.write_text("trusted fixture\n", encoding="utf-8")
    guards = []
    for module, names in ((keyring, ["load_key", "generate_key", "rotate_key", "list_keys"]),
                          (checkpoints, ["create_checkpoint", "load_checkpoints"])):
        for name in names:
            guard = Mock(side_effect=AssertionError("attack accessed a trusted interface"))
            monkeypatch.setattr(module, name, guard)
            guards.append(guard)

    def verify(artifact):
        if mode == "A":
            return verify_plaintext(artifact)
        if mode == "B":
            return verify_hash_chain(artifact)
        with monkeypatch.context() as context:
            context.setattr(keyring, "load_key", Mock(return_value=key))
            context.setattr(checkpoints, "load_checkpoints", Mock(return_value=trusted))
            if mode == "C":
                return verify_hmac_chain(artifact, key_store)
            return verify_hmac_checkpoint(artifact, key_store, checkpoint_store,
                                          expected_log_id="run-001")

    yield SimpleNamespace(mode=mode, path=path, records=read_records(path), verify=verify)
    assert path.read_bytes() == original
    assert key_file.read_bytes() == key
    assert checkpoint_file.read_text(encoding="utf-8") == "trusted fixture\n"
    assert [cp.seq for cp in trusted] == (list(range(5)) if mode == "D" else [])
    for guard in guards:
        guard.assert_not_called()


def test_modify_record_contents_and_detection(log_case):
    case = log_case
    assert case.records[2]["event_type"] == "DATA_EXPORT"
    assert case.records[2]["details"]["file"] == "payroll.db"
    details = {"file": "innocent.txt", "nested": [True, None, {"x": "José"}]}
    original_details = deepcopy(details)
    output = attacks.modify_record(case.path, 2, details)
    expected = deepcopy(case.records)
    expected[2]["details"] = details
    assert read_records(output) == expected  # includes every original tag/link
    assert details == original_details
    assert output.name == "events.modified.jsonl" and output != case.path
    assert case.verify(output).valid is (case.mode == "A")


def test_delete_record_contents_and_detection(log_case):
    case = log_case
    output = attacks.delete_record(case.path, 2)
    assert read_records(output) == case.records[:2] + case.records[3:]
    assert [r["seq"] for r in read_records(output)] == [0, 1, 3, 4]
    assert output.name == "events.deleted.jsonl"
    assert case.verify(output).valid is False


def test_delete_final_record_is_tail_truncation(log_case):
    case = log_case
    output = attacks.delete_record(case.path, 4)
    assert read_records(output) == case.records[:4]
    assert case.verify(output).valid is (case.mode != "D")


def test_reorder_record_contents_and_detection(log_case):
    case = log_case
    output = attacks.reorder_records(case.path, 1, 3)
    assert read_records(output) == [case.records[i] for i in [0, 3, 2, 1, 4]]
    assert output.name == "events.reordered.jsonl"
    assert case.verify(output).valid is False


@pytest.mark.parametrize("remaining", [0, 3, 5])
def test_truncate_record_contents_and_detection(log_case, remaining):
    case = log_case
    output = attacks.truncate_log(case.path, remaining)
    assert read_records(output) == case.records[:remaining]
    assert output.name == "events.truncated.jsonl"
    # Controls pass; a genuine truncation is detected only with trusted anchors.
    assert case.verify(output).valid is (case.mode != "D" or remaining == 5)


@pytest.mark.parametrize("operation", ["delete", "reorder"])
def test_explicit_sequence_repair(log_case, operation):
    case = log_case
    if operation == "delete":
        damaged = attacks.delete_record(case.path, 2)
    else:
        damaged = attacks.reorder_records(case.path, 0, 3)
    before = read_records(damaged)
    evidence = damaged.read_bytes()
    if case.mode in ("C", "D"):
        with pytest.raises(ValueError, match="restricted to Modes A/B"):
            attacks.repair_sequences(damaged)
    else:
        repaired = attacks.repair_sequences(damaged)
        expected = deepcopy(before)
        for seq, record in enumerate(expected):
            record["seq"] = seq
        assert read_records(repaired) == expected
        assert case.verify(repaired).valid is (case.mode == "A")
    assert damaged.read_bytes() == evidence


@pytest.mark.parametrize("operation", ["modify", "delete", "reorder"])
def test_public_hash_reconstruction_and_evasion(log_case, operation):
    case = log_case
    if operation == "modify":
        damaged = attacks.modify_record(case.path, 2, {"file": "innocent.txt"})
    elif operation == "delete":
        damaged = attacks.delete_record(case.path, 2)
    else:
        damaged = attacks.reorder_records(case.path, 0, 3)
    before = read_records(damaged)
    evidence = damaged.read_bytes()
    if case.mode != "B":
        with pytest.raises(ValueError, match="requires Mode B"):
            attacks.rebuild_hash_chain(damaged)
    else:
        rebuilt = attacks.rebuild_hash_chain(damaged)
        after = read_records(rebuilt)
        previous = GENESIS_TAG
        for seq, (old, new) in enumerate(zip(before, after)):
            assert {k: v for k, v in old.items() if k not in ("seq", "prev_tag", "tag")} == {
                k: v for k, v in new.items() if k not in ("seq", "prev_tag", "tag")}
            assert new["seq"] == seq and new["prev_tag"] == previous
            assert new["tag"] == hashlib.sha256(canonical_bytes(LogRecord(**new))).hexdigest()
            previous = new["tag"]
        assert len(after) == len(before)
        assert case.verify(rebuilt).valid is True
    assert damaged.read_bytes() == evidence


def test_target_is_stored_sequence_not_line_position(log_case):
    case = log_case
    deleted = attacks.delete_record(case.path, 1)
    output = attacks.modify_record(deleted, 3, {"targeted": True})
    records = read_records(output)
    assert [r["seq"] for r in records] == [0, 2, 3, 4]
    assert records[2]["details"] == {"targeted": True}
    assert records[3] == case.records[4]
    with pytest.raises(ValueError, match="does not exist"):
        attacks.delete_record(deleted, 1)


@pytest.mark.parametrize("invoke", [
    lambda p: attacks.modify_record(p, True, {}),
    lambda p: attacks.delete_record(p, -1),
    lambda p: attacks.delete_record(p, "2"),
    lambda p: attacks.modify_record(p, 99, {}),
    lambda p: attacks.reorder_records(p, 0, 99),
    lambda p: attacks.reorder_records(p, 1, 1),
    lambda p: attacks.reorder_records(p, False, 1),
    lambda p: attacks.truncate_log(p, -1),
    lambda p: attacks.truncate_log(p, True),
    lambda p: attacks.truncate_log(p, 1.0),
    lambda p: attacks.truncate_log(p, 6),
])
def test_invalid_requests_create_no_artifacts(tmp_path, invoke):
    path = tmp_path / "events.jsonl"
    logger = PlaintextLogger("test", path)
    for event in generate_events(5):
        logger.append(*event)
    before = path.read_bytes()
    with pytest.raises(ValueError):
        invoke(path)
    assert list(tmp_path.iterdir()) == [path]
    assert path.read_bytes() == before


@pytest.mark.parametrize("details", [[], {1: "coerced"}, {"nested": [{1: "bad"}]},
                                     {"value": {1, 2}}, {"value": (1, 2)},
                                     {"value": float("nan")}, {"value": float("inf")}])
def test_invalid_details_are_not_silently_coerced(tmp_path, details):
    path = tmp_path / "events.jsonl"
    PlaintextLogger("test", path).append("2026-11-17T12:00:00Z", "X", {})
    with pytest.raises((ValueError, TypeError)):
        attacks.modify_record(path, 0, details)
    assert list(tmp_path.iterdir()) == [path]


def test_plaintext_float_compatibility(log_case):
    case = log_case
    if case.mode == "A":
        output = attacks.modify_record(case.path, 2, {"nested": [1.5, -0.0]})
        assert case.verify(output).valid is True
    else:
        with pytest.raises(TypeError, match="floats are not allowed"):
            attacks.modify_record(case.path, 2, {"nested": [1.5]})
        assert not case.path.with_name("events.modified.jsonl").exists()


@pytest.mark.parametrize("operation,args,suffix", [
    (attacks.modify_record, (2, {"file": "innocent.txt"}), "modified"),
    (attacks.delete_record, (2,), "deleted"),
    (attacks.reorder_records, (1, 3), "reordered"),
    (attacks.truncate_log, (3,), "truncated"),
    (attacks.repair_sequences, (), "resequenced"),
    (attacks.rebuild_hash_chain, (), "rehashed"),
])
def test_artifacts_are_deterministic_and_never_overwritten(tmp_path, operation, args, suffix):
    sources = []
    for name in ("first", "second"):
        path = tmp_path / name / "events.jsonl"
        logger = HashChainLogger("repeatable", path)
        for event in generate_events(5):
            logger.append(*event)
        sources.append(path)
    before = [p.read_bytes() for p in sources]
    outputs = [operation(path, *args) for path in sources]
    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    assert outputs[0].name == f"events.{suffix}.jsonl"
    saved = outputs[0].read_bytes()
    with pytest.raises(FileExistsError):
        operation(sources[0], *args)
    assert outputs[0].read_bytes() == saved
    assert [p.read_bytes() for p in sources] == before


@pytest.mark.parametrize("dangling", [False, True])
def test_destination_symlink_cannot_overwrite_evidence(tmp_path, dangling):
    path = tmp_path / "events.jsonl"
    PlaintextLogger("test", path).append("2026-11-17T12:00:00Z", "X", {})
    before = path.read_bytes()
    output = tmp_path / "events.modified.jsonl"
    target = tmp_path / "missing.jsonl" if dangling else path
    output.symlink_to(target)
    with pytest.raises(FileExistsError):
        attacks.modify_record(path, 0, {"modified": True})
    assert path.read_bytes() == before
    assert output.is_symlink()
    if dangling:
        assert not target.exists()


@pytest.mark.parametrize("line,reason", [
    ("not JSON\n", "line 2"),
    ("\n", "line 2"),
    ('{"seq":1,"seq":2}\n', "duplicate JSON key"),
    ('{"details":{"x":1,"x":2}}\n', "duplicate JSON key"),
    ('{"details":{"value":NaN}}\n', "invalid JSON constant"),
    ('{"details":{"value":1e400}}\n', "JSON float must be finite"),
    ('{}\n', "eight schema fields"),
])
def test_malformed_lines_are_never_skipped(tmp_path, line, reason):
    path = tmp_path / "events.jsonl"
    record = PlaintextLogger("test", path).append("2026-11-17T12:00:00Z", "X", {})
    path.write_text(json.dumps(record.__dict__) + "\n" + line, encoding="utf-8")
    before = path.read_bytes()
    # Even truncating before the damage must reject the malformed input.
    with pytest.raises(ValueError, match=reason):
        attacks.truncate_log(path, 1)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("field,value,reason", [
    ("seq", True, "nonnegative integer"),
    ("seq", 0, "duplicate sequence"),
    ("details", [], "details must be an object"),
    ("log_id", "other", "mixed log identities"),
    ("key_id", 1, "nonempty string"),
    ("tag", "bad", "lowercase hexadecimal"),
])
def test_malformed_record_fields(tmp_path, field, value, reason):
    path = tmp_path / "events.jsonl"
    logger = HashChainLogger("test", path)
    records = [logger.append(*event).__dict__.copy() for event in generate_events(5)]
    records[1][field] = value
    write_records(path, records)
    before = path.read_bytes()
    with pytest.raises(ValueError, match=reason):
        attacks.delete_record(path, 2)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_empty_and_single_record_boundaries(tmp_path):
    path = tmp_path / "one.jsonl"
    PlaintextLogger("test", path).append("2026-11-17T12:00:00Z", "X", {})
    empty = attacks.delete_record(path, 0)
    assert empty.read_bytes() == b""
    assert attacks.truncate_log(empty, 0).read_bytes() == b""
    assert attacks.repair_sequences(empty).read_bytes() == b""
    assert attacks.rebuild_hash_chain(empty).read_bytes() == b""
    with pytest.raises(ValueError, match="does not exist"):
        attacks.modify_record(empty, 0, {})


def test_missing_input_does_not_create_artifact(tmp_path):
    with pytest.raises(FileNotFoundError):
        attacks.delete_record(tmp_path / "missing.jsonl", 0)
    assert list(tmp_path.iterdir()) == []


def test_cyclic_details_create_no_artifact(tmp_path):
    path = tmp_path / "events.jsonl"
    PlaintextLogger("test", path).append("2026-11-17T12:00:00Z", "X", {})
    details = {}
    details["cycle"] = details
    before = path.read_bytes()
    with pytest.raises(ValueError, match="cycle or excessive nesting"):
        attacks.modify_record(path, 0, details)
    assert list(tmp_path.iterdir()) == [path]
    assert path.read_bytes() == before


def test_invalid_utf8_is_not_skipped(tmp_path):
    path = tmp_path / "invalid.jsonl"
    path.write_bytes(b"\xff\n")
    with pytest.raises(ValueError, match="line 1"):
        attacks.truncate_log(path, 0)
    assert path.read_bytes() == b"\xff\n"
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("damage", ["missing", "extra", "mixed"])
def test_schema_defaults_extras_and_mixed_modes_are_rejected(tmp_path, damage):
    path = tmp_path / "events.jsonl"
    logger = HashChainLogger("test", path)
    records = [logger.append(*event).__dict__.copy() for event in generate_events(5)]
    if damage == "missing":
        del records[1]["details"]  # dataclass defaults must not conceal omission
    elif damage == "extra":
        records[1]["unsigned"] = "must not silently disappear"
    else:
        records[1]["tag"] = records[1]["prev_tag"] = None
    write_records(path, records)
    before = path.read_bytes()
    with pytest.raises(ValueError):
        attacks.delete_record(path, 2)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]
