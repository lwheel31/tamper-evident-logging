"""Log verification for all four modes.

Verifies integrity of stored log files by recomputing tags and comparing
against stored values (and checkpoints for Mode D).

Owner: Julian
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class VerificationResult:
    """Outcome of verifying a log file."""
    mode: str
    log_id: str
    total_records: int
    valid: bool
    first_bad_seq: int | None = None
    error: str | None = None


def verify_plaintext(path: Path) -> VerificationResult:
    """Mode A — can only check structural validity (parseable JSONL, seq order).

    TODO (Julian): Parse records, verify seq is monotonically increasing.
    No tag verification is possible.
    """
    raise NotImplementedError("Julian: implement plaintext verification")


def verify_hash_chain(path: Path) -> VerificationResult:
    """Mode B — recompute SHA-256 chain and compare tags.

    TODO (Julian): For each record, compute expected tag from canonical_bytes,
    compare to stored tag, verify prev_tag linkage.
    """
    raise NotImplementedError("Julian: implement hash-chain verification")


def verify_hmac_chain(path: Path, key_store: Path) -> VerificationResult:
    """Mode C — recompute HMAC-SHA256 chain and compare tags.

    Must raise an error (not return valid=True) if a required key is missing.

    TODO (Julian): Like Mode B but use HMAC with key from keyring.
    Handle key_id changes (rotation) within the log.
    """
    raise NotImplementedError("Julian: implement HMAC-chain verification")


def verify_hmac_checkpoint(path: Path, key_store: Path, checkpoint_store: Path) -> VerificationResult:
    """Mode D — HMAC chain + checkpoint anchor validation.

    TODO (Julian): Run HMAC chain verification, then cross-check against
    loaded checkpoints. A mismatch at a checkpoint boundary is a strong
    signal of tampering in the preceding segment.
    """
    raise NotImplementedError("Julian: implement HMAC-checkpoint verification")
