"""Trusted checkpoints for Mode D.

A checkpoint is a small record stored SEPARATELY from the attacker-writable
log file. It contains:
    log_id:   str — which log stream
    seq:      int — the last sequence number covered
    tag:      str — the tag of the record at that seq

Checkpoints act as trusted anchors: if an attacker modifies records
before a checkpoint, verification can detect the inconsistency because
the checkpoint's tag will no longer match the recomputed chain.

Threat model: the attacker CANNOT modify or delete checkpoints.

Owner: Ashton
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Checkpoint:
    log_id: str
    seq: int
    tag: str


def create_checkpoint(log_id: str, seq: int, tag: str, store_path: Path) -> Checkpoint:
    """Persist a trusted checkpoint.

    TODO (Ashton): Write a JSON file to <store_path>/<log_id>_cp_<seq>.json.
    Return the Checkpoint.
    """
    raise NotImplementedError("Ashton: implement checkpoint creation")


def load_checkpoints(log_id: str, store_path: Path) -> list[Checkpoint]:
    """Load all checkpoints for a given log, ordered by seq.

    TODO (Ashton): Glob for <store_path>/<log_id>_cp_*.json, parse, sort.
    """
    raise NotImplementedError("Ashton: implement checkpoint loading")
