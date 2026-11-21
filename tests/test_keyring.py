"""Tests for key management.

Owner: Ashton
"""

import stat

import pytest

from tamperlog import keyring


def test_generate_and_load_key(tmp_path):
    keyring.generate_key("k1", tmp_path)
    key = keyring.load_key("k1", tmp_path)
    assert isinstance(key, bytes) and len(key) == 32
    # Loading again gives the exact same bytes (no regeneration).
    assert keyring.load_key("k1", tmp_path) == key


def test_key_file_is_owner_only(tmp_path):
    keyring.generate_key("k1", tmp_path)
    mode = stat.S_IMODE((tmp_path / "k1.key").stat().st_mode)
    assert mode == 0o600


def test_missing_key_raises(tmp_path):
    """load_key for a nonexistent key must raise KeyError."""
    with pytest.raises(KeyError):
        keyring.load_key("nope", tmp_path)


def test_generate_refuses_overwrite(tmp_path):
    keyring.generate_key("k1", tmp_path)
    original = keyring.load_key("k1", tmp_path)
    with pytest.raises(FileExistsError):
        keyring.generate_key("k1", tmp_path)
    with pytest.raises(FileExistsError):
        keyring.generate_key("K1", tmp_path)  # case alias on macOS/Windows
    assert keyring.load_key("k1", tmp_path) == original


def test_rotate_key_preserves_old(tmp_path):
    keyring.generate_key("key-v1", tmp_path)
    old = keyring.load_key("key-v1", tmp_path)
    new_id = keyring.rotate_key("key-v2", tmp_path)
    assert new_id == "key-v2"
    assert keyring.load_key("key-v1", tmp_path) == old  # old key kept
    assert keyring.load_key("key-v2", tmp_path) != old  # new key is different
    assert keyring.list_keys(tmp_path) == ["key-v1", "key-v2"]


@pytest.mark.parametrize("bad_id", ["", "../escape", "a/b", "a.b", "-lead", "CON", "lpt1", "x" * 129])
def test_unsafe_key_ids_rejected(tmp_path, bad_id):
    with pytest.raises(ValueError):
        keyring.generate_key(bad_id, tmp_path)
    with pytest.raises(ValueError):
        keyring.load_key(bad_id, tmp_path)


def test_corrupted_key_is_an_error(tmp_path):
    keyring.generate_key("k1", tmp_path)
    (tmp_path / "k1.key").write_bytes(b"short")
    with pytest.raises(ValueError):
        keyring.load_key("k1", tmp_path)


def test_list_keys_empty_store(tmp_path):
    assert keyring.list_keys(tmp_path / "missing") == []
