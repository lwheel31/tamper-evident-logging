"""Simulated attacks on log files.

Each function takes a log file path, applies a specific tampering
strategy, and writes the modified file. These are used in experiments
to test detection capabilities of each mode.

Threat model capabilities exercised:
- Read, modify, delete, reorder, truncate, and rewrite stored log files.
- The attacker CANNOT access HMAC keys, modify checkpoints, or alter
  the logger/verifier code.

Owner: Julian
"""

from __future__ import annotations

from pathlib import Path


def modify_record(path: Path, target_seq: int, new_details: dict) -> Path:
    """Change the details of a single record.

    TODO (Julian): Read JSONL, replace details at target_seq,
    write to a new file. Do NOT recompute tags (attacker lacks keys).
    Return path to tampered file.
    """
    raise NotImplementedError("Julian: implement record modification attack")


def delete_record(path: Path, target_seq: int) -> Path:
    """Remove a single record from the log.

    TODO (Julian): Remove the line at target_seq, write new file.
    """
    raise NotImplementedError("Julian: implement record deletion attack")


def reorder_records(path: Path, seq_a: int, seq_b: int) -> Path:
    """Swap two records in the log.

    TODO (Julian): Swap lines at seq_a and seq_b.
    """
    raise NotImplementedError("Julian: implement reorder attack")


def truncate_log(path: Path, keep_count: int) -> Path:
    """Truncate the log to only the first keep_count records.

    TODO (Julian): Keep first keep_count lines only.
    """
    raise NotImplementedError("Julian: implement truncation attack")


def rewrite_log(path: Path) -> Path:
    """Rewrite the entire log with fabricated records (no valid chain).

    TODO (Julian): Generate plausible-looking but fake records.
    For hash-chain mode the attacker CAN recompute valid hashes (no key).
    For HMAC modes the attacker CANNOT produce valid tags.
    """
    raise NotImplementedError("Julian: implement full rewrite attack")
