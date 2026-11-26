"""Tests for trusted checkpoints. Owner: Ashton"""

import pytest

import threading
from concurrent.futures import ThreadPoolExecutor

from tamperlog import checkpoints
from tamperlog.checkpoints import Checkpoint

TAG_A = "a" * 64
TAG_B = "b" * 64


def test_create_and_load_checkpoint(tmp_path):
    cp = checkpoints.create_checkpoint("log-d", 0, TAG_A, tmp_path)
    assert cp == Checkpoint("log-d", 0, TAG_A)
    assert checkpoints.load_checkpoints("log-d", tmp_path) == [cp]


def test_checkpoints_sorted_numerically(tmp_path):
    # Written out of order; seq 10 must come after seq 2, not before it.
    for seq in [10, 2, 0, 1, 11, 3, 4, 5, 6, 7, 8, 9]:
        checkpoints.create_checkpoint("log-d", seq, TAG_A, tmp_path)
    assert [cp.seq for cp in checkpoints.load_checkpoints("log-d", tmp_path)] == list(range(12))


def test_checkpoint_stored_outside_log_dir(tmp_path):
    log_dir = tmp_path / "logs"
    trusted = tmp_path / "trusted"
    log_dir.mkdir()
    checkpoints.create_checkpoint("log-d", 0, TAG_A, trusted)
    assert list(log_dir.iterdir()) == []
    assert (trusted / "log-d_cp_0.json").is_file()


def test_same_checkpoint_twice_is_ok(tmp_path):
    checkpoints.create_checkpoint("log-d", 0, TAG_A, tmp_path)
    checkpoints.create_checkpoint("log-d", 0, TAG_A, tmp_path)
    assert len(checkpoints.load_checkpoints("log-d", tmp_path)) == 1


def test_conflicting_checkpoint_rejected(tmp_path):
    checkpoints.create_checkpoint("log-d", 0, TAG_A, tmp_path)
    with pytest.raises(FileExistsError):
        checkpoints.create_checkpoint("log-d", 0, TAG_B, tmp_path)
    assert checkpoints.load_checkpoints("log-d", tmp_path)[0].tag == TAG_A


def test_logs_do_not_mix(tmp_path):
    checkpoints.create_checkpoint("demo", 0, TAG_A, tmp_path)
    checkpoints.create_checkpoint("demo-2", 0, TAG_B, tmp_path)
    assert checkpoints.load_checkpoints("demo", tmp_path) == [Checkpoint("demo", 0, TAG_A)]


def test_malformed_checkpoint_raises_not_skipped(tmp_path):
    checkpoints.create_checkpoint("log-d", 0, TAG_A, tmp_path)
    (tmp_path / "log-d_cp_1.json").write_text("not json")
    with pytest.raises(ValueError):
        checkpoints.load_checkpoints("log-d", tmp_path)


def test_mismatched_filename_and_contents_raises(tmp_path):
    checkpoints.create_checkpoint("log-d", 0, TAG_A, tmp_path)
    (tmp_path / "log-d_cp_0.json").rename(tmp_path / "log-d_cp_5.json")
    with pytest.raises(ValueError):
        checkpoints.load_checkpoints("log-d", tmp_path)


@pytest.mark.parametrize("log_id, seq, tag", [
    ("../x", 0, TAG_A), ("ok", -1, TAG_A), ("ok", True, TAG_A), ("ok", 0, "A" * 64), ("ok", 0, "short"),
])
def test_bad_inputs_rejected(tmp_path, log_id, seq, tag):
    with pytest.raises(ValueError):
        checkpoints.create_checkpoint(log_id, seq, tag, tmp_path)


def test_missing_store_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        checkpoints.load_checkpoints("log-d", tmp_path / "missing")


@pytest.mark.parametrize("late_tag", [TAG_A, TAG_B])
def test_concurrent_checkpoint_publication_never_replaces_winner(tmp_path, monkeypatch, late_tag):
    opened = threading.Event()
    resume = threading.Event()
    real_open = checkpoints.os.open

    def paused_open(*args, **kwargs):
        if threading.current_thread().name.startswith("late-checkpoint"):
            opened.set()
            assert resume.wait(10), "writer was not released"
        return real_open(*args, **kwargs)

    monkeypatch.setattr(checkpoints.os, "open", paused_open)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="late-checkpoint") as pool:
        late = pool.submit(checkpoints.create_checkpoint, "log-d", 0, late_tag, tmp_path)
        try:
            assert opened.wait(10), "writer did not reach temporary-file creation"
            winner = checkpoints.create_checkpoint("log-d", 0, TAG_A, tmp_path)
            before = (tmp_path / "log-d_cp_0.json").read_bytes()
        finally:
            resume.set()
        if late_tag == TAG_A:
            assert late.result(timeout=10) == winner
        else:
            with pytest.raises(FileExistsError):
                late.result(timeout=10)
    assert (tmp_path / "log-d_cp_0.json").read_bytes() == before
    assert checkpoints.load_checkpoints("log-d", tmp_path) == [winner]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["log-d_cp_0.json"]


def test_checkpoint_short_writes_are_completed(tmp_path, monkeypatch):
    real_write = checkpoints.os.write
    monkeypatch.setattr(checkpoints.os, "write", lambda fd, data: real_write(fd, data[:7]))
    expected = checkpoints.create_checkpoint("log-d", 0, TAG_A, tmp_path)
    assert checkpoints.load_checkpoints("log-d", tmp_path) == [expected]


@pytest.mark.parametrize("failure", ["zero-write", "fsync", "link"])
def test_failed_checkpoint_creation_cleans_temp_and_can_retry(tmp_path, monkeypatch, failure):
    with monkeypatch.context() as patch:
        if failure == "zero-write":
            patch.setattr(checkpoints.os, "write", lambda fd, data: 0)
        else:
            def fail(*args):
                raise OSError("injected persistence failure")
            patch.setattr(checkpoints.os, failure, fail)
        with pytest.raises(OSError):
            checkpoints.create_checkpoint("log-d", 0, TAG_A, tmp_path)
    assert list(tmp_path.iterdir()) == []
    expected = checkpoints.create_checkpoint("log-d", 0, TAG_A, tmp_path)
    assert checkpoints.load_checkpoints("log-d", tmp_path) == [expected]


@pytest.mark.parametrize("contents", [
    '{"log_id":"log-d","seq":0,"tag":"' + TAG_A + '","tag":"' + TAG_B + '"}',
    '{"log_id":"log-d","seq":0,"tag":"short"}',
])
def test_ambiguous_or_invalid_trusted_json_is_rejected(tmp_path, contents):
    (tmp_path / "log-d_cp_0.json").write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError):
        checkpoints.load_checkpoints("log-d", tmp_path)
    with pytest.raises(ValueError):
        checkpoints.create_checkpoint("log-d", 0, TAG_B, tmp_path)
