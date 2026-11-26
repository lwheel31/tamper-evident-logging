"""Tests for logging modes. Owner: Lucas (A-C), Ashton (D checkpoints)"""

import hashlib
import hmac

import pytest
from tamperlog.events import generate_events
from tamperlog.loggers import (GENESIS_TAG, HashChainLogger, HMACChainLogger,
                               HMACCheckpointLogger, PlaintextLogger)
from tamperlog.serialization import canonical_bytes, jsonl_to_record

KEY_A = b"A" * 32  # throwaway test keys, never real secrets
KEY_B = b"B" * 32


def write_all(logger, n=20):
    return [logger.append(*e) for e in generate_events(n)]


def read_back(path):
    return [jsonl_to_record(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_plaintext_logger(tmp_path):
    path = tmp_path / "a.jsonl"
    written = write_all(PlaintextLogger("log-a", path))
    stored = read_back(path)
    assert stored == written
    assert [r.seq for r in stored] == list(range(20))
    assert all(r.tag is None and r.prev_tag is None for r in stored)


def test_hash_chain_logger(tmp_path):
    path = tmp_path / "b.jsonl"
    write_all(HashChainLogger("log-b", path))
    stored = read_back(path)
    assert stored[0].prev_tag == GENESIS_TAG
    for prev, cur in zip(stored, stored[1:]):
        assert cur.prev_tag == prev.tag  # each record links to the one before
    for r in stored:  # anyone can recompute the tag: that's Mode B's weakness
        assert r.tag == hashlib.sha256(canonical_bytes(r)).hexdigest()


def test_hmac_chain_logger(tmp_path):
    path = tmp_path / "c.jsonl"
    write_all(HMACChainLogger("log-c", path, "k1", key=KEY_A))
    stored = read_back(path)
    for prev, cur in zip(stored, stored[1:]):
        assert cur.prev_tag == prev.tag
    for r in stored:
        assert r.key_id == "k1"
        assert r.tag == hmac.new(KEY_A, canonical_bytes(r), hashlib.sha256).hexdigest()
        # Mode B-style recomputation (no key) does NOT give the right tag
        assert r.tag != hashlib.sha256(canonical_bytes(r)).hexdigest()


def test_hmac_key_rotation(tmp_path):
    path = tmp_path / "rot.jsonl"
    log = HMACChainLogger("log-rot", path, "k1", key=KEY_A)
    events = list(generate_events(10))
    for e in events[:5]:
        log.append(*e)
    log.switch_key("k2", key=KEY_B)
    for e in events[5:]:
        log.append(*e)
    stored = read_back(path)
    assert [r.key_id for r in stored] == ["k1"] * 5 + ["k2"] * 5
    assert stored[5].prev_tag == stored[4].tag  # chain continues across rotation
    for r in stored:
        key = KEY_A if r.key_id == "k1" else KEY_B
        assert r.tag == hmac.new(key, canonical_bytes(r), hashlib.sha256).hexdigest()


def test_same_events_across_modes(tmp_path):
    """All modes log identical content; only tags differ."""
    a = write_all(PlaintextLogger("x", tmp_path / "a.jsonl"))
    c = write_all(HMACChainLogger("x", tmp_path / "c.jsonl", "k1", key=KEY_A))
    assert [(r.timestamp, r.event_type, r.details) for r in a] == \
           [(r.timestamp, r.event_type, r.details) for r in c]


def test_refuses_to_overwrite_existing_log(tmp_path):
    path = tmp_path / "a.jsonl"
    write_all(PlaintextLogger("x", path), n=5)
    with pytest.raises(FileExistsError):
        PlaintextLogger("x", path)


def test_short_key_rejected(tmp_path):
    with pytest.raises(ValueError):
        HMACChainLogger("x", tmp_path / "c.jsonl", "k1", key=b"short")


def test_hmac_checkpoint_logger(tmp_path):
    from tamperlog import checkpoints
    path = tmp_path / "d.jsonl"
    store = tmp_path / "trusted"
    written = write_all(HMACCheckpointLogger("log-d", path, "k1", store, key=KEY_A), n=10)
    # One checkpoint per record; the last one matches the final record.
    trusted = checkpoints.load_checkpoints("log-d", store)
    assert [cp.seq for cp in trusted] == list(range(10))
    assert [cp.tag for cp in trusted] == [r.tag for r in written]
    assert trusted[-1].seq == written[-1].seq and trusted[-1].tag == written[-1].tag
