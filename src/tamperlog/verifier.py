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

from . import checkpoints, keyring
from .loggers import GENESIS_TAG
from .schema import LogRecord
from .serialization import SIGNED_FIELDS, canonical_bytes

# Explicit UTC profile: extended calendar date/time, seconds, optional decimal
# fraction, then Z or +00:00. Calendar validity is checked separately below.
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|\+00:00)"
)

# Identifiers passed to a filename-based trusted store must be opaque names,
# never paths. No separators, dots, glob syntax, whitespace, or Unicode aliases.
_STORE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")


def _is_store_identifier(value: object) -> bool:
    # Windows device names remain special even when a loader appends .key.
    return (isinstance(value, str) and _STORE_IDENTIFIER.fullmatch(value) is not None
            and value.upper() not in {"CON", "PRN", "AUX", "NUL"}
            and re.fullmatch(r"(?:COM|LPT)[1-9]", value, re.IGNORECASE) is None)


@dataclass
class VerificationResult:
    """Outcome of verifying a log file.

    total_records counts examined lines, including a failing line. For missing
    Mode D records, first_bad_seq is the first absent expected position and
    there is no line to count. Otherwise it is the failing line's expected
    zero-based sequence, never an untrusted stored seq. log_id is the first
    structurally valid record's identity (or "" if unavailable), except Mode D
    uses the independently supplied expected identity. valid means only that
    the selected mode's checks passed, subject to its documented assumptions.
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


def _is_tag(value: object) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


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
    if mode in ("A", "B"):
        if data["key_id"] is not None:
            raise ValueError(f"key_id must be null in Mode {mode}")
    elif not _is_store_identifier(data["key_id"]):
        raise ValueError("key_id must be a safe store identifier "
                         "(1-128 ASCII letters/digits/underscores/hyphens, starting alphanumeric; "
                         "device names excluded)")
    for field in ("prev_tag", "tag"):
        value = data[field]
        if mode == "A":
            if value is not None:
                raise ValueError(f"{field} must be null in Mode A")
        elif not _is_tag(value):
            raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")
    return LogRecord(**data)


def _load_hmac_key(key_id: str, key_store: Path) -> bytes:
    """A trusted dependency failure is 'cannot verify', not proof of tampering."""
    try:
        key = keyring.load_key(key_id, key_store)
    except (KeyError, OSError, ValueError, TypeError, NotImplementedError):
        # Do not expose key contents or dependency messages containing paths.
        raise RuntimeError(f"cannot verify: key {key_id!r} unavailable") from None
    if not isinstance(key, bytes) or len(key) < 32:
        raise RuntimeError(f"cannot verify: key {key_id!r} must be bytes of at least 32 bytes")
    return key


def _verify(path: Path, mode: str, key_store: Path | None = None,
            trusted_checkpoints: list[checkpoints.Checkpoint] | None = None,
            expected_log_id: str | None = None) -> VerificationResult:
    result = VerificationResult(mode=mode, log_id=expected_log_id or "",
                                total_records=0, valid=True)
    previous_tag = GENESIS_TAG
    try:
        stream = open(path, "rb")
    except FileNotFoundError:
        if mode != "D":
            raise
        return VerificationResult(mode="D", log_id=expected_log_id, total_records=0,
                                  valid=False, first_bad_seq=0,
                                  error="log file missing; trusted checkpoints require records")
    # Decode each physical line separately so a later UTF-8 error cannot hide
    # an earlier failure through the text reader's buffering.
    with stream:
        for expected_seq, raw_line in enumerate(stream):
            result.total_records += 1
            try:
                record = _parse_record(raw_line.decode("utf-8"), mode)
                # Cryptographic modes use canonical signed data; plaintext
                # may contain finite floats, as emitted by its logger.
                if mode != "A":
                    payload = canonical_bytes(record)
                if expected_seq == 0 and expected_log_id is None:
                    result.log_id = record.log_id
                if record.log_id != result.log_id:
                    anchor = "expected identity" if mode == "D" else "the first record"
                    raise ValueError(f"log_id differs from {anchor}")
                if record.seq != expected_seq:
                    raise ValueError(f"sequence mismatch: expected {expected_seq}, got {record.seq}")
                if mode != "A":
                    if not hmac.compare_digest(record.prev_tag, previous_tag):
                        raise ValueError("prev_tag does not match the previous tag (or genesis)")
                    if mode == "B":
                        expected_tag = hashlib.sha256(payload).hexdigest()
                        mismatch = "SHA-256 digest mismatch"
                    else:
                        key = _load_hmac_key(record.key_id, key_store)
                        expected_tag = hmac.new(key, payload, hashlib.sha256).hexdigest()
                        mismatch = "HMAC-SHA256 digest mismatch"
                    if not hmac.compare_digest(record.tag, expected_tag):
                        raise ValueError(mismatch)
                    previous_tag = record.tag
                if trusted_checkpoints is not None:
                    if expected_seq >= len(trusted_checkpoints):
                        raise RuntimeError(f"cannot verify: missing trusted checkpoint at seq {expected_seq}")
                    if not hmac.compare_digest(record.tag, trusted_checkpoints[expected_seq].tag):
                        raise ValueError("tag differs from trusted checkpoint")
            except (ValueError, TypeError, RecursionError) as exc:
                result.valid = False
                result.first_bad_seq = expected_seq
                result.error = f"line {expected_seq + 1}: {exc}"
                return result
    if trusted_checkpoints is not None and result.total_records < len(trusted_checkpoints):
        result.valid = False
        result.first_bad_seq = result.total_records
        result.error = f"missing record at seq {result.total_records}; trusted checkpoint exists"
    return result


def verify_hmac_chain(path: Path, key_store: Path) -> VerificationResult:
    """Mode C: verify HMAC-SHA256 with each record's historical key_id.

    Missing, invalid, unavailable, or unimplemented keys raise RuntimeError
    ('cannot verify'). Invalid stored records return valid=False. Safe key IDs
    are restricted to the documented store-name profile before any lookup.
    Chain continuity survives key rotation. A valid prefix, including an empty
    existing file, still passes: there is no completeness or expected-identity
    anchor in this API. File access errors propagate as in Modes A/B.
    """
    return _verify(path, "C", key_store)


def verify_hmac_checkpoint(path: Path, key_store: Path, checkpoint_store: Path, *,
                           expected_log_id: str) -> VerificationResult:
    """Mode D: verify HMAC plus one trusted checkpoint for every record.

    expected_log_id MUST come from trusted caller configuration, independently
    of the log file. It selects checkpoints and anchors record identity. The
    signature change was explicitly approved for Sprint 02.

    Trusted-data failures raise RuntimeError ('cannot verify'); checkpoint
    mismatches and missing log records return valid=False. No checkpoints,
    including for an empty log, cannot establish completeness and raise.
    Only checkpoint_interval=1 is supported; sparse checkpoint sets fail closed.
    Other file access errors propagate. Use stable, current trusted artifacts;
    freshness/rollback of the trusted store is outside the storage-only threat.
    """
    if not _is_store_identifier(expected_log_id):
        raise ValueError("expected_log_id must be a safe store identifier from trusted configuration")
    try:
        trusted = checkpoints.load_checkpoints(expected_log_id, checkpoint_store)
    except (KeyError, OSError, ValueError, TypeError, NotImplementedError):
        raise RuntimeError("cannot verify: trusted checkpoints unavailable") from None
    if not isinstance(trusted, list) or not trusted:
        raise RuntimeError("cannot verify: a nonempty trusted checkpoint list is required")
    for seq, checkpoint in enumerate(trusted):
        if (not isinstance(checkpoint, checkpoints.Checkpoint)
                or checkpoint.log_id != expected_log_id
                or type(checkpoint.seq) is not int or checkpoint.seq != seq
                or not _is_tag(checkpoint.tag)):
            raise RuntimeError("cannot verify: checkpoints must have the expected identity, "
                               "valid tags, and consecutive sequences from zero")
    return _verify(path, "D", key_store, trusted, expected_log_id)
