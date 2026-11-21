"""Trusted checkpoints for Mode D.

A checkpoint is a small record stored SEPARATELY from the attacker-writable
log file. It contains:
    log_id:   str — which log stream
    seq:      int — the last sequence number covered
    tag:      str — the tag of the record at that seq

Checkpoints act as trusted anchors: if an attacker cuts off the end of the
log, the trusted store still has checkpoints for the missing records, so the
verifier can report them as missing.

Storage format: one JSON file per checkpoint,
<store_path>/<log_id>_cp_<seq>.json. Each file is written to a temp file
first and then renamed, so a crash can't leave a half-written checkpoint.

Threat model: the attacker CANNOT modify or delete checkpoints.

Owner: Ashton
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

# Same safe-name rule as keyring/verifier, so log_id can't be a path.
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_WINDOWS_DEVICE = re.compile(r"(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])", re.IGNORECASE)
_TAG = re.compile(r"[0-9a-f]{64}")


@dataclass
class Checkpoint:
    log_id: str
    seq: int
    tag: str


def _check_log_id(log_id: str) -> None:
    if (not isinstance(log_id, str) or _SAFE_ID.fullmatch(log_id) is None
            or _WINDOWS_DEVICE.fullmatch(log_id) is not None):
        raise ValueError(f"unsafe log_id: {log_id!r}")


def _checkpoint_path(log_id: str, seq: int, store_path: Path) -> Path:
    return Path(store_path) / f"{log_id}_cp_{seq}.json"


def create_checkpoint(log_id: str, seq: int, tag: str, store_path: Path) -> Checkpoint:
    """Save a trusted checkpoint and return it.

    If a checkpoint for this (log_id, seq) already exists with the same tag,
    that's fine. If it exists with a DIFFERENT tag, refuse: trusted history
    must never be rewritten.
    """
    _check_log_id(log_id)
    if type(seq) is not int or seq < 0:
        raise ValueError(f"seq must be a non-negative integer, got {seq!r}")
    if not isinstance(tag, str) or _TAG.fullmatch(tag) is None:
        raise ValueError("tag must be 64 lowercase hex characters")

    store = Path(store_path)
    store.mkdir(parents=True, exist_ok=True, mode=0o700)
    checkpoint = Checkpoint(log_id, seq, tag)
    path = _checkpoint_path(log_id, seq, store)

    if path.exists() or path.is_symlink():
        if _read_checkpoint(path) == checkpoint:
            return checkpoint
        raise FileExistsError(f"conflicting checkpoint already exists for {log_id!r} seq {seq}")

    # Write to a temp file, flush to disk, then rename into place (atomic).
    data = json.dumps({"log_id": log_id, "seq": seq, "tag": tag}, sort_keys=True)
    temp = store / f".{path.name}.tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, path)
    return checkpoint


def _read_checkpoint(path: Path) -> Checkpoint:
    """Read one checkpoint file. Raises ValueError if it's malformed."""
    if path.is_symlink():
        raise ValueError(f"checkpoint is a symlink: {path.name}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(data, dict) or set(data) != {"log_id", "seq", "tag"}
            or not isinstance(data["log_id"], str) or type(data["seq"]) is not int
            or not isinstance(data["tag"], str)):
        raise ValueError(f"malformed checkpoint file: {path.name}")
    return Checkpoint(data["log_id"], data["seq"], data["tag"])


def load_checkpoints(log_id: str, store_path: Path) -> list[Checkpoint]:
    """Load every checkpoint for log_id, sorted by seq as a number.

    Sorting by number matters: sorting filenames as text would put
    seq 10 before seq 2. A bad file raises an error instead of being skipped,
    so the verifier never gets a silently shortened list.
    """
    _check_log_id(log_id)
    store = Path(store_path)
    if not store.is_dir():
        raise FileNotFoundError(f"checkpoint store not found: {store}")

    # Exact filename match, so log 'demo' doesn't pick up files for 'demo_cp_x' etc.
    name_pattern = re.compile(re.escape(log_id) + r"_cp_(0|[1-9][0-9]*)\.json")
    found = []
    for path in store.iterdir():
        match = name_pattern.fullmatch(path.name)
        if match is None:
            continue
        checkpoint = _read_checkpoint(path)
        if checkpoint.log_id != log_id or checkpoint.seq != int(match.group(1)):
            raise ValueError(f"checkpoint contents don't match filename: {path.name}")
        found.append(checkpoint)
    return sorted(found, key=lambda cp: cp.seq)
