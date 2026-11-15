# Interfaces

> Status: PROPOSED, awaiting approval from all three teammates.
> Source of truth for signatures is the code; this file explains intent.

## Record (`schema.py`, JSON Lines, one object per line)
| Field | Type | Notes |
|---|---|---|
| log_id | str | identifies the log |
| seq | int | starts at 1, increments by 1 |
| timestamp | str | ISO 8601 |
| event_type | str | e.g. LOGIN_SUCCESS, DATA_EXPORT |
| details | dict | event data |
| key_id | str or null | null in Modes A/B |
| prev_tag | str or null | null in Mode A; documented initial value for seq 1 |
| tag | str or null | hex; NOT included in its own input |

## Serialization (`serialization.py`)
- `canonical_bytes(record)`: deterministic UTF-8 JSON (sorted keys, fixed separators), excludes `tag`.

## Logger (`loggers.py`)
- `append(event_type, details) -> LogRecord`, one class per mode.

## Keyring (`keyring.py`)
- `generate_key`, `load_key`, `rotate_key`, `list_keys`. Missing key raises `KeyError`.

## Checkpoints (`checkpoints.py`)
- `create_checkpoint(log_id, seq, tag, store_path)`, `load_checkpoints(log_id, store_path)`.

## Verifier (`verifier.py`)
- Returns valid / tampered (with first bad seq) / cannot verify. Uses `hmac.compare_digest`.

## Attacks (`attacks.py`)
- modify, delete, reorder, truncate (planned four). `rewrite_log` added by scaffold, pending Julian's decision.
