"""Log verification for all four modes.

Verifies integrity of stored log files by recomputing tags and comparing
against stored values (and checkpoints for Mode D).

Verify captured, stable log artifacts. These functions do not create a snapshot
or lock out a storage attacker during the read; success describes the captured
input, not a file that remains writable. This does not restrict the attacker's
ability to modify stored logs before capture.

There are no explicit line-size, payload-depth, memory, or CPU limits. A hostile
artifact can exhaust resources before a result is returned. RecursionError is
reported when raised, but this is not a resource-exhaustion defense.

Owner: Julian
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
import math
from pathlib import Path
import re

from .loggers import GENESIS_TAG
from .schema import LogRecord
from .serialization import SIGNED_FIELDS, canonical_bytes

# Explicit UTC profile: extended calendar date/time, seconds, optional decimal
# fraction, then Z or +00:00. Calendar validity is checked separately below.
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|\+00:00)"
)


@dataclass
class VerificationResult:
    """Outcome of verifying a log file.

    total_records counts lines examined, including the first failing line;
    verification stops there. first_bad_seq is that line's expected zero-based
    sequence, never an untrusted stored seq. log_id is the first structurally
    valid record's identity, or "" if none is available. valid means only that
    the selected mode's checks passed, not authenticity or completeness.
    """
    mode: str
    log_id: str
    total_records: int
    valid: bool
    first_bad_seq: int | None = None
    error: str | None = None


def verify_plaintext(path: Path) -> VerificationResult:
    """Mode A: check structure, log identity, and zero-based sequence order.

    Success gives no cryptographic integrity guarantee: valid edits pass.
    Empty files pass with zero records and log_id=""; they provide no evidence
    that events were logged. Blank lines fail, including in otherwise empty
    files. File access errors propagate rather than being treated as empty logs.
    """
    return _verify(path, "A")


def verify_hash_chain(path: Path) -> VerificationResult:
    """Mode B: check structure, linkage, and independently recomputed SHA-256.

    Empty files and file access errors behave as in verify_plaintext. A valid
    chain is internally consistent; public hashes cannot prove authenticity or
    completeness. Rehashed rewrites and valid tail truncation can pass.
    """
    return _verify(path, "B")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate keys in every object, including nested details."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _finite_float(value: str) -> float:
    # JSON exponents such as 1e400 overflow float() without raising. The parse
    # hook checks numbers at every nesting level, without a second traversal.
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON float must be finite")
    return number


def _parse_record(line: str, mode: str) -> LogRecord:
    data = json.loads(line, object_pairs_hook=_unique_object,
                      parse_constant=_reject_constant, parse_float=_finite_float)
    if not isinstance(data, dict):
        raise ValueError("log line must be a JSON object")
    # Require every on-disk field, even fields with dataclass defaults. Reject
    # extras because canonical_bytes would otherwise leave them unprotected.
    fields = set(SIGNED_FIELDS) | {"tag"}
    missing = fields - data.keys()
    extra = data.keys() - fields
    if missing:
        raise ValueError(f"missing fields: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"unexpected fields: {', '.join(sorted(extra))}")
    for field in ("log_id", "timestamp", "event_type"):
        if not isinstance(data[field], str):
            raise ValueError(f"{field} must be a string")
    # bool is a subclass of int in Python, but is not a sequence number.
    if type(data["seq"]) is not int:
        raise ValueError("seq must be an integer (not boolean)")
    if not isinstance(data["details"], dict):
        raise ValueError("details must be an object")
    timestamp = data["timestamp"]
    if _UTC_TIMESTAMP.fullmatch(timestamp) is None:
        raise ValueError("timestamp must be an ISO 8601 UTC datetime "
                         "(YYYY-MM-DDTHH:MM:SS[.fraction]Z or +00:00)")
    normalized = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
    try:
        datetime.fromisoformat(normalized)
    except ValueError:
        raise ValueError("timestamp must be an ISO 8601 UTC datetime") from None
    if data["key_id"] is not None:
        raise ValueError(f"key_id must be null in Mode {mode}")
    for field in ("prev_tag", "tag"):
        value = data[field]
        if mode == "A":
            if value is not None:
                raise ValueError(f"{field} must be null in Mode A")
        elif (not isinstance(value, str) or len(value) != 64
              or any(char not in "0123456789abcdef" for char in value)):
            raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")
    return LogRecord(**data)


def _verify(path: Path, mode: str) -> VerificationResult:
    result = VerificationResult(mode=mode, log_id="", total_records=0, valid=True)
    previous_tag = GENESIS_TAG
    # Decode each physical line separately so a later UTF-8 error cannot hide
    # an earlier failure through the text reader's buffering.
    with open(path, "rb") as stream:
        for expected_seq, raw_line in enumerate(stream):
            result.total_records += 1
            try:
                record = _parse_record(raw_line.decode("utf-8"), mode)
                # Only Mode B has a canonical signed-data domain. Plaintext
                # JSON may contain finite floats, as emitted by its logger.
                if mode == "B":
                    payload = canonical_bytes(record)
                if expected_seq == 0:
                    result.log_id = record.log_id
                if record.log_id != result.log_id:
                    raise ValueError("log_id differs from the first record")
                if record.seq != expected_seq:
                    raise ValueError(f"sequence mismatch: expected {expected_seq}, got {record.seq}")
                if mode == "B":
                    if not hmac.compare_digest(record.prev_tag, previous_tag):
                        raise ValueError("prev_tag does not match the previous tag (or genesis)")
                    expected_tag = hashlib.sha256(payload).hexdigest()
                    if not hmac.compare_digest(record.tag, expected_tag):
                        raise ValueError("SHA-256 digest mismatch")
                    previous_tag = record.tag
            except (ValueError, TypeError, RecursionError) as exc:
                result.valid = False
                result.first_bad_seq = expected_seq
                result.error = f"line {expected_seq + 1}: {exc}"
                return result
    return result


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
