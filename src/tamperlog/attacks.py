"""Repeatable storage-only attacks on captured synthetic JSONL logs.

Every implemented operation reads the source and creates a deterministic sibling
artifact, e.g. events.modified.jsonl. Existing destinations (including symlinks)
raise FileExistsError; originals are never opened for writing. Repeat experiments
in separate directories or use a new source copy. Output JSON is reformatted by
the shared serializer, so unchanged records preserve values, not storage bytes.

Basic attacks preserve stored sequence labels and tags. Targets are stored seq
values, not physical line indexes. repair_sequences and rebuild_hash_chain are
explicit, separate evasion steps for A/B. No function loads keys or checkpoints.
Mechanism guards use stored field shape, not authenticated mode identification;
experiments must select the original mode's verifier independently of the file.
Returning a Path means the transformation completed, not that verification will
pass or that an incident was hidden. Inputs must be stable, schema-shaped logs;
these helpers are not an independent verifier or a hostile-filesystem sandbox.
All records are held in memory; I/O failures propagate and can leave an incomplete
output artifact. Full-log fabrication remains deferred.

Owner: Julian
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from .loggers import GENESIS_TAG
from .schema import LogRecord
from .serialization import SIGNED_FIELDS, canonical_bytes, record_to_jsonl


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON float must be finite")
    return number


def _nonnegative_int(name: str, value: int) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer (not boolean)")


def _read_records(path: Path) -> list[LogRecord]:
    """Reject ambiguous/malformed inputs, but permit sequence gaps and reordering.

    Deliberately do not check digests, linkage, or timestamp semantics: already
    tampered copies must remain usable as inputs to the explicit repair steps.
    """
    records = []
    seen = set()
    fields = set(SIGNED_FIELDS) | {"tag"}
    with open(path, "rb") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                data = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object,
                                  parse_constant=_reject_constant, parse_float=_finite_float)
                if not isinstance(data, dict) or set(data) != fields:
                    raise ValueError("record must contain exactly the eight schema fields")
                for name in ("log_id", "timestamp", "event_type"):
                    if not isinstance(data[name], str):
                        raise ValueError(f"{name} must be a string")
                _nonnegative_int("seq", data["seq"])
                if data["seq"] in seen:
                    raise ValueError("duplicate sequence label; target would be ambiguous")
                if not isinstance(data["details"], dict):
                    raise ValueError("details must be an object")
                if data["key_id"] is not None and (
                        not isinstance(data["key_id"], str) or not data["key_id"]):
                    raise ValueError("key_id must be null or a nonempty string")
                record = LogRecord(**data)
                plaintext = record.tag is None and record.prev_tag is None
                if plaintext:
                    if record.key_id is not None:
                        raise ValueError("plaintext records must have null key_id")
                else:
                    for name in ("tag", "prev_tag"):
                        value = data[name]
                        if (not isinstance(value, str) or len(value) != 64
                                or any(char not in "0123456789abcdef" for char in value)):
                            raise ValueError(f"{name} must be 64 lowercase hexadecimal characters")
                    canonical_bytes(record)
                if records:
                    first = records[0]
                    if record.log_id != first.log_id:
                        raise ValueError("mixed log identities")
                    if (plaintext != (first.tag is None)
                            or (record.key_id is None) != (first.key_id is None)):
                        raise ValueError("mixed logging mechanisms")
                records.append(record)
                seen.add(record.seq)
            except (ValueError, TypeError, RecursionError) as exc:
                raise ValueError(f"line {line_number}: {exc}") from None
    return records


def _target_index(records: list[LogRecord], seq: int) -> int:
    _nonnegative_int("target sequence", seq)
    for index, record in enumerate(records):
        if record.seq == seq:
            return index
    raise ValueError(f"target sequence {seq} does not exist")


def _check_json_value(value: object) -> None:
    """Validate caller-supplied details without JSON's silent key/type coercions."""
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("details object keys must be strings")
            _check_json_value(item)
    elif isinstance(value, list):
        for item in value:
            _check_json_value(item)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("details floats must be finite")
    elif value is not None and not isinstance(value, (str, int, bool)):
        raise TypeError("details must contain only JSON values")


def _write_copy(path: Path, operation: str, records: list[LogRecord]) -> Path:
    destination = path.with_name(f"{path.stem}.{operation}{path.suffix}")
    # Finish serialization before reserving a filename; invalid payloads must
    # not leave artifacts. Exclusive creation also refuses existing symlinks.
    payload = "".join(record_to_jsonl(record) + "\n" for record in records)
    with open(destination, "x", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)
    return destination


def modify_record(path: Path, target_seq: int, new_details: dict) -> Path:
    """Replace the entire details object at target_seq; preserve every other field.

    Identical details are permitted as a control. Plaintext accepts finite
    floats; tagged modes retain the shared canonical payload restrictions.
    """
    path = Path(path)
    if not isinstance(new_details, dict):
        raise TypeError("new_details must be a dictionary")
    try:
        _check_json_value(new_details)
    except RecursionError:
        raise ValueError("details contain a cycle or excessive nesting") from None
    records = _read_records(path)
    index = _target_index(records, target_seq)
    records[index].details = new_details
    if records[index].tag is not None:
        canonical_bytes(records[index])
    return _write_copy(path, "modified", records)


def delete_record(path: Path, target_seq: int) -> Path:
    """Delete the record labelled target_seq, leaving retained seq/tags unchanged."""
    path = Path(path)
    records = _read_records(path)
    del records[_target_index(records, target_seq)]
    return _write_copy(path, "deleted", records)


def reorder_records(path: Path, seq_a: int, seq_b: int) -> Path:
    """Swap two distinct stored sequence labels without renumbering or retagging."""
    path = Path(path)
    records = _read_records(path)
    index_a = _target_index(records, seq_a)
    index_b = _target_index(records, seq_b)
    if index_a == index_b:
        raise ValueError("reordering requires two distinct target sequences")
    records[index_a], records[index_b] = records[index_b], records[index_a]
    return _write_copy(path, "reordered", records)


def truncate_log(path: Path, keep_count: int) -> Path:
    """Keep the first keep_count physical records (0..length inclusive).

    Zero removes every record; keeping the full length is a control copy.
    Retained sequence labels and tags remain unchanged.
    """
    path = Path(path)
    _nonnegative_int("keep_count", keep_count)
    records = _read_records(path)
    if keep_count > len(records):
        raise ValueError("keep_count exceeds the number of records")
    return _write_copy(path, "truncated", records[:keep_count])


def repair_sequences(path: Path) -> Path:
    """Renumber A/B records from zero in physical order without changing tags.

    Mode B still needs rebuild_hash_chain after edits to signed fields.
    HMAC-labelled inputs are refused; use the basic attacks to preserve C/D tags.
    Empty inputs produce empty copies because they carry no mechanism metadata.
    """
    path = Path(path)
    records = _read_records(path)
    if any(record.key_id is not None for record in records):
        raise ValueError("sequence repair is restricted to Modes A/B")
    for seq, record in enumerate(records):
        record.seq = seq
    return _write_copy(path, "resequenced", records)


def rebuild_hash_chain(path: Path) -> Path:
    """Renumber and rebuild Mode B's public SHA-256 chain in physical file order.

    Recompute all prev_tag/tag values from the public 64-zero genesis value.
    Refuse plaintext and HMAC-labelled records; never look up a key. Empty
    inputs yield empty copies, without claiming to establish their original mode.
    This demonstrates internal consistency after forgery, not authenticity.
    """
    path = Path(path)
    records = _read_records(path)
    if any(record.key_id is not None or record.tag is None for record in records):
        raise ValueError("hash reconstruction requires Mode B records")
    previous = GENESIS_TAG
    for seq, record in enumerate(records):
        record.seq = seq
        record.prev_tag = previous
        record.tag = hashlib.sha256(canonical_bytes(record)).hexdigest()
        previous = record.tag
    return _write_copy(path, "rehashed", records)


def rewrite_log(path: Path) -> Path:
    """Full-log fabrication is deferred; compose the explicit attacks instead."""
    raise NotImplementedError("Julian: full-log fabrication is deferred")
