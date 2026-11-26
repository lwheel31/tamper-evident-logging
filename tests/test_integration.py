"""Real persistence integration gates. No mocks, fallback keys, or fake stores.

Only the exact existing provider stubs may skip a test. Once those entry points
are implemented, assertions and unexpected backend failures must fail normally.
"""

from dataclasses import asdict
import hashlib
import hmac
from pathlib import Path

import pytest

from tamperlog import checkpoints, experiment, keyring
from tamperlog.events import generate_events
from tamperlog.loggers import HMACChainLogger, HMACCheckpointLogger
from tamperlog.serialization import jsonl_to_record
from tamperlog.verifier import verify_hmac_chain, verify_hmac_checkpoint


# Capture actual entry points, not arbitrary exception text from deeper helpers.
_KNOWN_STUBS = {
    keyring.generate_key: "Ashton: implement key generation",
    keyring.load_key: "Ashton: implement key loading",
    keyring.rotate_key: "Ashton: implement key rotation",
    keyring.list_keys: "Ashton: implement key listing",
    checkpoints.create_checkpoint: "Ashton: implement checkpoint creation",
    checkpoints.load_checkpoints: "Ashton: implement checkpoint loading",
}


def _real_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except NotImplementedError as exc:
        origin = exc.__traceback__
        while origin.tb_next is not None:
            origin = origin.tb_next
        for dependency, message in _KNOWN_STUBS.items():
            if origin.tb_frame.f_code is dependency.__code__ and str(exc) == message:
                pytest.skip(f"real-store integration blocked: {dependency.__module__}.{dependency.__name__} is an unimplemented stub")
        raise  # Unknown/indirect failures are not dependency skips.


@pytest.fixture
def real_keys(tmp_path):
    store = tmp_path / "trusted" / "keys"
    store.mkdir(parents=True, mode=0o700)
    _real_call(keyring.generate_key, "initial", store)
    key = _real_call(keyring.load_key, "initial", store)
    if not isinstance(key, bytes) or len(key) < 32:
        pytest.fail("real key store must return bytes of length >= 32")
    return store


@pytest.fixture
def real_checkpoint_log(tmp_path, real_keys):
    store = tmp_path / "trusted" / "checkpoints"
    store.mkdir(mode=0o700)
    path = tmp_path / "logs" / "original.jsonl"
    identity = "real-integration-D"
    logger = _real_call(HMACCheckpointLogger, identity, path, "initial", store,
                        key_store=real_keys, checkpoint_interval=1)
    for event in generate_events(50, 42):
        _real_call(logger.append, *event)
    trusted = _real_call(checkpoints.load_checkpoints, identity, store)
    assert [cp.seq for cp in trusted] == list(range(50))  # catches lexical 10-before-2 sorting
    assert all(isinstance(cp, checkpoints.Checkpoint) and cp.log_id == identity for cp in trusted)
    baseline = verify_hmac_checkpoint(path, real_keys, store, expected_log_id=identity)
    assert baseline.valid and baseline.total_records == 50
    return path, real_keys, store, identity, trusted


def test_full_comparison_matrix(tmp_path, real_checkpoint_log):
    """Enable the actual 16-cell runner only after real key/checkpoint preflight."""
    report = experiment.run_experiment(output_dir=tmp_path / "runs", event_count=50, seed=42)
    assert len(report["results"]) == 16
    assert {(r["mode"], r["attack"]) for r in report["results"]} == {
        (mode, attack) for mode in "ABCD" for attack in ("modify", "delete", "reorder", "truncate")}
    assert all(b["status"] == "VALID" for b in report["baselines"].values()), report["baselines"]
    expected = {
        "A": ["MISSED"] * 4,
        "B": ["MISSED"] * 4,
        "C": ["DETECTED", "DETECTED", "DETECTED", "MISSED"],
        "D": ["DETECTED"] * 4,
    }
    run = Path(report["run_directory"])
    for mode, outcomes in expected.items():
        rows = [r for r in report["results"] if r["mode"] == mode]
        assert [r["outcome"] for r in rows] == outcomes
        assert all(r["attack_applied"] and r["control_result"]["valid"] for r in rows)
        original = (run / report["baselines"][mode]["artifact"]).read_bytes()
        assert hashlib.sha256(original).hexdigest() == report["baselines"][mode]["sha256"]
        for row in rows:
            assert (run / "attacks" / mode / row["attack"] / "input.jsonl").read_bytes() == original
            for relative, digest in row["artifacts"].items():
                assert hashlib.sha256((run / relative).read_bytes()).hexdigest() == digest
    # No BLOCKED/CANNOT_VERIFY row is converted to a skip after successful preflight.


@pytest.mark.parametrize("mode", ["C", "D"])
def test_real_historical_rotation_and_missing_key(tmp_path, real_keys, mode):
    previous_key = _real_call(keyring.load_key, "initial", real_keys)
    path = tmp_path / "logs" / f"rotated-{mode}.jsonl"
    identity = f"real-rotation-{mode}"
    anchors = tmp_path / "trusted" / "rotation-checkpoints"
    anchors.mkdir(mode=0o700)
    if mode == "C":
        logger = _real_call(HMACChainLogger, identity, path, "initial", key_store=real_keys)
    else:
        logger = _real_call(HMACCheckpointLogger, identity, path, "initial", anchors,
                            key_store=real_keys, checkpoint_interval=1)
    events = list(generate_events(50, 42))
    for event in events[:25]:
        _real_call(logger.append, *event)
    rotated_id = _real_call(keyring.rotate_key, "rotated", real_keys)
    assert rotated_id == "rotated"
    retained = hmac.compare_digest(previous_key, _real_call(keyring.load_key, "initial", real_keys))
    different = not hmac.compare_digest(previous_key, _real_call(keyring.load_key, rotated_id, real_keys))
    assert retained, "rotation replaced historical key material"
    assert different, "rotation reused the old key"
    _real_call(logger.switch_key, rotated_id)
    for event in events[25:]:
        _real_call(logger.append, *event)
    records = [jsonl_to_record(line) for line in path.read_text().splitlines()]
    assert [r.key_id for r in records] == ["initial"] * 25 + ["rotated"] * 25
    assert records[25].prev_tag == records[24].tag
    if mode == "D":
        assert len(_real_call(checkpoints.load_checkpoints, identity, anchors)) == 50

    def verify(keys):
        if mode == "C":
            return verify_hmac_chain(path, keys)
        return verify_hmac_checkpoint(path, keys, anchors, expected_log_id=identity)

    assert verify(real_keys).valid
    evidence = path.read_bytes()
    # A separate real store with only the new identifier avoids assuming the
    # provider's key filename format or deleting fixtures through private APIs.
    missing_old = tmp_path / "missing-historical-keys"
    missing_old.mkdir(mode=0o700)
    _real_call(keyring.generate_key, rotated_id, missing_old)
    with pytest.raises(KeyError):
        _real_call(keyring.load_key, "initial", missing_old)
    with pytest.raises(RuntimeError, match="cannot verify: key 'initial' unavailable"):
        verify(missing_old)
    assert path.read_bytes() == evidence


@pytest.mark.parametrize("damage", ["missing-tail", "mismatch"])
def test_real_checkpoint_completeness(tmp_path, real_checkpoint_log, damage):
    path, keys, original_store, identity, trusted = real_checkpoint_log
    evidence = path.read_bytes()
    snapshot = [asdict(cp) for cp in trusted]
    alternate = tmp_path / "incomplete-or-wrong-checkpoints"
    alternate.mkdir(mode=0o700)
    for cp in trusted:
        if damage == "missing-tail" and cp.seq == 49:
            continue
        tag = cp.tag
        if damage == "mismatch" and cp.seq == 25:
            tag = "f" * 64 if cp.tag != "f" * 64 else "e" * 64
        _real_call(checkpoints.create_checkpoint, identity, cp.seq, tag, alternate)
    # Probe the loader directly so only a known load stub can skip; malformed
    # snapshots and unexpected loader exceptions must fail the test.
    _real_call(checkpoints.load_checkpoints, identity, alternate)
    assert verify_hmac_chain(path, keys).valid
    if damage == "missing-tail":
        with pytest.raises(RuntimeError, match="missing trusted checkpoint at seq 49"):
            verify_hmac_checkpoint(path, keys, alternate, expected_log_id=identity)
    else:
        result = verify_hmac_checkpoint(path, keys, alternate, expected_log_id=identity)
        assert result.valid is False and result.first_bad_seq == 25
        assert "trusted checkpoint" in result.error
    assert path.read_bytes() == evidence
    assert [asdict(cp) for cp in _real_call(checkpoints.load_checkpoints, identity, original_store)] == snapshot


def test_real_independent_identity_rejects_other_log(real_checkpoint_log):
    path, keys, store, identity, trusted = real_checkpoint_log
    for cp in trusted:
        checkpoints.create_checkpoint("other-log", cp.seq, cp.tag, store)
    result = verify_hmac_checkpoint(path, keys, store, expected_log_id="other-log")
    assert not result.valid and result.first_bad_seq == 0
    assert "expected identity" in result.error
    assert verify_hmac_checkpoint(path, keys, store, expected_log_id=identity).valid


def test_real_empty_checkpoint_store_cannot_authorize_log(tmp_path, real_checkpoint_log):
    path, keys, store, identity, trusted = real_checkpoint_log
    empty = tmp_path / "empty-checkpoints"
    empty.mkdir()
    with pytest.raises(RuntimeError, match="nonempty trusted checkpoint list"):
        verify_hmac_checkpoint(path, keys, empty, expected_log_id=identity)
    assert verify_hmac_checkpoint(path, keys, store, expected_log_id=identity).valid
