# Implemented interfaces and pending integration agreements

This document describes current branch behavior; code remains the signature
source of truth. Implemented behavior is not a claim of team-wide ratification
or completed persistence integration. Julian explicitly approved Mode D's
required `expected_log_id` argument in Sprint 02. Storage policy and the
constraints listed below still require joint review with Ashton/Lucas.

## Records and serialization — implemented

All stored records contain exactly these eight fields:

| Field | Verifier contract |
|---|---|
| `log_id` | String, consistent across records. D additionally requires equality to trusted caller configuration. |
| `seq` | Integer excluding booleans, starts at zero and advances by one. |
| `timestamp` | ASCII `YYYY-MM-DDTHH:MM:SS[.fraction]` followed by uppercase `Z` or exactly `+00:00`; valid calendar/time under Python `datetime`. |
| `event_type` | String; no enumeration or event-truth check is imposed. |
| `details` | Object. A allows finite JSON floats; cryptographic modes use the canonical domain below. |
| `key_id` | Null in A/B; safe nonempty store identifier in C/D. Each record identifies its historical key. |
| `prev_tag` | Null in A; otherwise 64 lowercase hex characters. First chained record uses `GENESIS_TAG = "0" * 64`. |
| `tag` | Null in A; otherwise 64 lowercase hex characters. Excluded from its own canonical input. |

Verifiers reject blank/malformed JSONL lines, invalid UTF-8, duplicate keys at
any depth, missing/extra fields, and invalid types/tags. Timestamp parsing is a
supported UTC profile, not all ISO 8601: compact/week dates, other offsets, and
leap seconds are rejected. It proves neither timestamp truth nor chronological
order. Empty-string identities remain legal for A/B/C but cannot select D's
trusted store under its identifier profile.

`canonical_bytes(record: LogRecord) -> bytes` covers `log_id`, `seq`, `timestamp`,
`event_type`, `details`, `key_id`, and `prev_tag`. JSON keys are sorted, separators
fixed, non-ASCII escaped, and bytes UTF-8 encoded. Nested signed data permits
strings, integers, booleans, nulls, lists, and string-keyed objects; no floats.

`record_to_jsonl(record) -> str` includes `tag` and does not append a newline.
`jsonl_to_record(line) -> LogRecord` is a convenience decoder, **not** the strict
verification boundary: Python's default duplicate-key interpretation and
`LogRecord` defaults remain possible. Do not use it alone to certify structure
or authenticity. The loggers likewise do not enforce every verifier constraint.

## Events and loggers — implemented

`generate_events(count=50, seed=42)` yields deterministic
`(timestamp, event_type, details)` tuples; count must be >= 4. The payroll export
incident is inserted near the middle. Seeds control only synthetic events, not
security keys.

| Constructor | Parameters |
|---|---|
| `PlaintextLogger`, `HashChainLogger` | `(log_id, path)` |
| `HMACChainLogger` | `(log_id, path, key_id, key_store=None, key=None)` |
| `HMACCheckpointLogger` | `(log_id, path, key_id, checkpoint_store, key_store=None, key=None, checkpoint_interval=1)` |

Every logger exposes `append(timestamp, event_type, details) -> LogRecord` and
refuses a nonempty existing destination. C/D use `key_store` with
`keyring.load_key`, or explicitly supplied bytes for local/API testing. The
experiment uses real persistence interfaces, not injected test keys.
`switch_key(new_key_id, key=None)` changes the key for future C/D records without
resetting chain linkage. Keys must be at least 32 bytes. D supports configurable
append intervals, but current verification/experiments require interval **1**.

## Verification — implemented

```python
verify_plaintext(path: Path) -> VerificationResult
verify_hash_chain(path: Path) -> VerificationResult
verify_hmac_chain(path: Path, key_store: Path) -> VerificationResult
verify_hmac_checkpoint(path: Path, key_store: Path, checkpoint_store: Path, *,
                       expected_log_id: str) -> VerificationResult
```

Mode/expected identity/store locations are trusted caller configuration. Never
select them from attacker-controlled records. D selects anchors by the supplied
identity; C has no independent expected-identity or completeness anchor.
Recompute tags with the shared canonical bytes and compare with
`hmac.compare_digest`. A checks structure only; B consistency alone is not
authenticity. C cannot detect a valid tail cut; D covers the records in its
complete/current trusted checkpoint snapshot.

| `VerificationResult` field | Meaning |
|---|---|
| `mode` | A/B/C/D selected by the caller. |
| `log_id` | First structurally valid identity, or empty when unavailable; D reports the supplied expected identity. |
| `total_records` | Physical lines examined, including a failing line; absent records add no count. |
| `valid` | Selected mode's checks passed under its assumptions, not a universal security claim. |
| `first_bad_seq` | Expected zero-based position of first invalid/missing record, not its untrusted stored sequence. |
| `error` | Explanation, or null on success. |

Malformed stored records, invalid digests/linkage, and disagreements with
well-formed checkpoint tags return `valid=False`.
Missing/invalid/unavailable trusted data raises `RuntimeError` with
`cannot verify:`; it does not return a third result status. Other unexpected
exceptions propagate. A/B/C file-access errors propagate. D returns invalid for
a missing file after loading anchors; other file errors propagate.

Existing empty files pass A/B/C with zero records and empty identity. D requires
a nonempty, ordered `list[Checkpoint]`, expected identity, exact sequences
0..N-1 excluding booleans, valid tags, and matching coverage. Empty/no-anchor
histories, gaps, duplicates, missing anchors, and malformed trusted metadata
cannot produce success. The current format has no trusted empty-history marker.

## Attacks — implemented except full-log fabrication

```python
modify_record(path: Path, target_seq: int, new_details: dict) -> Path
delete_record(path: Path, target_seq: int) -> Path
reorder_records(path: Path, seq_a: int, seq_b: int) -> Path
truncate_log(path: Path, keep_count: int) -> Path
repair_sequences(path: Path) -> Path
rebuild_hash_chain(path: Path) -> Path
```

All operations create deterministic sibling copies using exclusive creation;
existing files/symlinks raise `FileExistsError`. Original bytes remain unchanged.
Targets are unique **stored sequence labels**, not line indexes. Reordering
requires distinct labels. Truncation keeps the first physical records, accepts
0..length inclusive, and allows the full-length control. Modify replaces the
entire details object; identical details are also a control.

Basic attacks retain sequence labels, previous tags, HMAC tags, and key IDs.
`repair_sequences` renumbers A/B in physical order without retagging.
`rebuild_hash_chain` renumbers and rebuilds all B links/digests from genesis.
Both refuse HMAC-labelled input; reconstruction also refuses plaintext. Empty
copies carry no mode metadata and are permitted. These guards use field shape,
not authenticated mode identification; the verifier must remain independently
selected. Helpers never load keys or checkpoints.

Inputs must be unambiguous, schema-shaped logs. Gaps/reordering are allowed so
attack outputs can be repaired, but duplicate labels, mixed identities/mode
families, malformed lines, and invalid payloads are rejected. Tagged payloads
retain canonical restrictions. Output JSON is reformatted; output values rather
than raw formatting are preserved. Validation errors propagate; failed I/O can
leave incomplete artifacts. Returning a path proves transformation execution,
not detection evasion or incident concealment. `rewrite_log(path)` remains an
explicitly deferred `NotImplementedError`.

## Experiment and CLI — implemented

`run_experiment(*, output_dir=Path("experiment-results"), event_count=50, seed=42)`
returns the exported report dictionary. The original no-argument call remains
valid. `render_matrix(report) -> str` renders recorded outcomes. CLI:
`tamperlog experiment --output-dir PATH --event-count 50 --seed 42`.

The runner generates one stream, validates original baselines, isolates all 16
cases, repairs A deletion/reorder sequences, reconstructs B chains, and preserves
C/D authentication data. It checks transformations, original bytes, D checkpoint
snapshots, and post-attack untouched controls. It exports parameters, targets,
actual results/positions, evidence hashes, and runtime/source fingerprints.

`DETECTED`/`MISSED` require an executed attack plus valid controls.
`CANNOT_VERIFY` means comparison could not be established; `BLOCKED` means
prerequisites prevented the cell; `ERROR` means execution/evidence/protocol
failure. Initial baselines separately use `VALID`/`INVALID` and dependency/error
states. Known verifier dependency errors follow the current `cannot verify:`
convention; arbitrary runtime exceptions are not automatically dependency errors.
See [methodology and observed results](experiments.md).

## Persistence interfaces — stubs; team implementation/agreement pending

| Interface | Required integration behavior |
|---|---|
| `generate_key(key_id, store_path) -> None` | Persist cryptographically random bytes, length >= 32; no overwrite or identifier alias collision. |
| `load_key(key_id, store_path) -> bytes` | Return exact historical bytes. Missing ID raises `KeyError`; unavailable/invalid storage raises an error. No regeneration, default key, or current-key substitution. |
| `rotate_key(new_key_id, store_path) -> str` | Generate and return the requested new identifier; retain old IDs and bytes. |
| `list_keys(store_path) -> list[str]` | List actual stored identifiers. |
| `create_checkpoint(log_id, seq, tag, store_path) -> Checkpoint` | Atomically persist the exact tuple before success; propagate failures and reject conflicting replacement. |
| `load_checkpoints(log_id, store_path) -> list[Checkpoint]` | Return all current anchors for that identity as a detached, stable, numerically ordered snapshot. Never silently omit failures or return a stale/cached prefix. |

`Checkpoint` is the existing dataclass with `log_id: str`, `seq: int`, `tag: str`.
Trusted-store identifiers are 1-128 ASCII characters, alphanumeric first,
remaining characters letters/digits/underscore/hyphen; dots, separators, glob
syntax, nulls, whitespace, Unicode aliases, and CON/PRN/AUX/NUL/COM1-9/LPT1-9
(case-insensitive) are excluded. Providers must validate independently of the
verifier and enforce containment, safe symlink behavior, permissions, and
immutable history. Agree on these constraints before integration; logger string
parameters do not enforce them automatically.

The checkpoint API has no independent freshness/high-water mark. Complete and
current retrieval is a trusted-backend obligation; matching old log/checkpoint
prefixes can pass if it is violated. Directory separation alone is not physical
trust separation. Stable artifacts, protected stores, and the approved
write/checkpoint-window assumption remain necessary. No typed exception redesign,
new record field, or persistence implementation is introduced by this document.
