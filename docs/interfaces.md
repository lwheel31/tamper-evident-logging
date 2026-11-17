# Interfaces

> Status: PROPOSED, awaiting approval from all three teammates.
> Source of truth for signatures is the code; this file explains intent.

## Record (`schema.py`, JSON Lines, one object per line)
| Field | Type | Notes |
|---|---|---|
| log_id | str | identifies the log |
| seq | int | starts at 0, increments by 1 |
| timestamp | str | ISO 8601 |
| event_type | str | e.g. LOGIN_SUCCESS, DATA_EXPORT |
| details | dict | event data |
| key_id | str or null | null in Modes A/B |
| prev_tag | str or null | null in Mode A; first record uses public GENESIS_TAG (64 zeros) |
| tag | str or null | hex; NOT included in its own input |

## Serialization (`serialization.py`)
- `canonical_bytes(record)`: deterministic UTF-8 JSON (sorted keys, fixed separators), excludes `tag`.

## Events (`events.py`)
- `generate_events(count=50, seed=42)` yields `(timestamp, event_type, details)`. Deterministic.
  The payroll export incident sits in the middle of the log.

## Logger (`loggers.py`)
- Every mode: `append(timestamp, event_type, details) -> LogRecord`.
- Mode C/D take `key_id` plus `key_store` (uses keyring.load_key) or `key` bytes (tests).
- Mode C/D: `switch_key(new_key_id)` for rotation. Mode D also takes `checkpoint_store`
  and calls `checkpoints.create_checkpoint` after every record by default.
- Signed data allows only str/int/bool/None/list/dict (no floats, string keys only).

## Keyring (`keyring.py`)
- `generate_key`, `load_key`, `rotate_key`, `list_keys`. Missing key raises `KeyError`.

## Checkpoints (`checkpoints.py`)
- `create_checkpoint(log_id, seq, tag, store_path)`, `load_checkpoints(log_id, store_path)`.

## Verifier (`verifier.py`)
- Returns valid / tampered (with first bad seq) / cannot verify. Uses `hmac.compare_digest`.

## Attacks (`attacks.py`)
- modify, delete, reorder, truncate (planned four). `rewrite_log` added by scaffold, pending Julian's decision.
