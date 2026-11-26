# Reproducible logging experiments

The runner evaluates four attacks against four fixed verification modes. Real
A/B experiments run independently of the security persistence modules.
C/D follow the complete logging/verification path with Ashton's implemented stores;
no production fallback keys or mocked results are supplied.

## Observed integrated results — 2026-11-25

On local `integration-review/ashton-security`, based on `228d8fbd` plus
uncommitted review corrections, two non-editably installed Windows CLI runs
with 50 events and seed 42 produced the following measured results:

| Attack | A | B | C | D |
|---|---|---|---|---|
| Modify | MISSED | MISSED | DETECTED | DETECTED |
| Delete | MISSED | MISSED | DETECTED | DETECTED |
| Reorder | MISSED | MISSED | DETECTED | DETECTED |
| Truncate | MISSED | MISSED | MISSED | DETECTED |

All four untouched baselines and all 16 post-attack controls verified 50 records.
All original/input and exported artifact hashes were checked; D retained all 50
matching anchors. Repeats matched event/parameter/source hashes, A/B artifact
bytes, C/D event content, and outcomes. Fresh random HMAC keys differed as expected.
See [the dated review receipt](reproduction.md#integration-review--2026-11-25).
The November 17 evidence, readiness assessments, and proposed PR text below are
historical; their persistence blockers and publication instructions are superseded
by this review. They remain as the record of the earlier partial experiment.

## Running

With the project installed, use:

```sh
tamperlog experiment --output-dir /tmp/tamperlog-experiments --event-count 50 --seed 42
```

From a checkout without the console script installed, the equivalent command is:

```sh
PYTHONPATH=src python3 -m tamperlog.cli experiment --output-dir /tmp/tamperlog-experiments --event-count 50 --seed 42
```

Defaults are 50 events, seed 42, and `experiment-results` as the output container.
Counts must be integers >= 4. Each invocation creates a fresh private `run-*`
directory; existing runs and files are never reused or overwritten. CLI exit code
zero means a report was produced, not that every cell ran or every attack failed.
Invalid arguments or failures preventing report export produce a nonzero exit.

The Python entry point is
`run_experiment(*, output_dir=Path("experiment-results"), event_count=50, seed=42)`;
it returns the same dictionary exported as `results.json`. Its original
no-argument invocation remains supported.

## Method

1. Generate the event stream once and save `events.json`. Find the unique
   `DATA_EXPORT` of `payroll.db`; do not infer targets from altered log metadata.
2. Write identical event content through the four loggers. Mode and expected
   identity (`experiment-A` through `experiment-D`) come from runner configuration.
   C/D generate keys through `keyring.generate_key`, and D uses interval 1.
3. Verify each untouched log and check its content and record count against the
   configured stream. An invalid/unavailable baseline blocks that mode's attacks.
4. Start every attack from a byte-identical copy of the original in its own
   directory. Check the actual output against the requested content/order changes.
   Preserve and hash the original, input copy, intermediate, and final artifacts.
5. Verify the final attack artifact using its configured mode. Reverify the
   untouched control afterward. Check D's trusted checkpoint snapshot for changes.
   Failed controls or changed evidence invalidate attribution of detection.

| Attack | Controlled transformation |
|---|---|
| Modify | Replace the export's filename with `reports/q3.xlsx`; retain other details. |
| Delete | Remove the payroll export record. |
| Reorder | Swap the export with the following event. The export remains present. |
| Truncate | Keep only records before the payroll export, removing it and the tail. |

For A, deletion/reordering includes explicit sequence repair. For B, every attack
includes public sequence/link/tag reconstruction. C/D retain original HMAC tags
and sequence labels, and the runner does not update trusted checkpoints after
baseline generation. These are attacker strategies, not four identical byte edits.
A `MISSED` reordering means the altered chronology passed verification; it does
not mean the payroll export disappeared.

## Outcome definitions

| Outcome | Evidence required |
|---|---|
| `DETECTED` | Requested attack completed, verifier returned invalid, and untouched control/evidence checks passed. |
| `MISSED` | Requested attack completed, verifier accepted it, and untouched control/evidence checks passed. |
| `CANNOT_VERIFY` | Verification/trusted snapshot data is unavailable, or the untouched control no longer establishes a valid comparison. |
| `BLOCKED` | No eligible baseline or other required prerequisite; attack verification was not attempted. |
| `ERROR` | Unexpected execution/I/O/protocol failure, incorrect attack effect, or altered source/checkpoint evidence. |

Initial baselines separately report `VALID`, `INVALID`, `BLOCKED`,
`CANNOT_VERIFY`, or `ERROR`. Raw verifier results remain in JSON even if a later
control check invalidates scoring. `first_bad_seq` records the attacked verifier's
reported position, or null when none was reported. Missing/unimplemented dependencies
are never counted as successful detection. Arbitrary runtime exceptions are
`ERROR`, not automatically dependency failures.

## Evidence and reproducibility

Each run contains:

- `events.json`: the deterministic input stream.
- `logs/<mode>/original.jsonl`: untouched baselines that could be generated.
- `attacks/<mode>/<attack>/`: independent inputs and intermediate/final artifacts.
- `results.json`: parameters, targets, configured modes/identities, initial
  baselines, transformation steps, execution flags, actual verifier/control
  results, failure positions, explanations, artifact hashes, checkpoint snapshot
  hashes, runtime information, and selected source-file fingerprints.
- `matrix.md`: the matrix rendered from actual recorded outcomes.
- `trusted/<mode>/`: private key/checkpoint stores when setup succeeds.

**Do not publish `trusted/` or distribute an entire keyed run directory.** The
JSON/Markdown reports contain no key bytes or raw backend exception messages.
Exported artifact hashes aid comparison; they do not authenticate the report.

Matching count/seed reproduces events and attack targets. Fresh HMAC keys must
remain random, so C/D tag bytes need not match across runs. A/B artifact hashes
and outcomes are reproducible for the same implementation and parameters. Keep
run evidence separately from source; the runner never infers verification mode
from attacker-controlled record fields.

## Observed real results — 2026-11-17

Executed the module CLI without mocks using 50 events and seed 42. The payroll
export was sequence 25; reorder targeted 25/26, and truncation retained 25 records.
A/B untouched logs each verified all 50 records. Both C/D setups reached the real
`keyring.generate_key` stub and raised `NotImplementedError`; no C/D attack
verification was attempted.

| Attack | A: Plaintext | B: SHA-256 | C: HMAC | D: HMAC + checkpoints |
|---|---|---|---|---|
| Modify | MISSED | MISSED | BLOCKED | BLOCKED |
| Delete | MISSED | MISSED | BLOCKED | BLOCKED |
| Reorder | MISSED | MISSED | BLOCKED | BLOCKED |
| Truncate | MISSED | MISSED | BLOCKED | BLOCKED |

These are eight observed misses and eight blocked cells, not evidence of C/D
detection or failure. The A/B observations apply to the repair/reconstruction
strategies above; they do not imply that unrepaired/unrehashed attacks pass.
A repeat API run with the same parameters produced an identical report apart
from its isolated run directory; all exported artifact hashes were checked.
Validation evidence is retained outside the repository at
`/private/tmp/tamperlog-sprint04-evidence/run-xodcedls/` (CLI) and
`/private/tmp/tamperlog-sprint04-evidence/run-gmdsqnuc/` (repeat). These temporary
locations are not durable archives; retain the nonsecret evidence before cleanup.

Full C/D paths, classification failures, control validation, and checkpoint
preservation are exercised with test-only store doubles. Those tests do not
establish persistence integration or real C/D experimental results.

## Remaining integration limits

Ashton must supply protected historical keys and complete, current, stable,
numerically ordered per-record checkpoints, or raise on failure. Matching stale
log/checkpoint prefixes cannot be detected by the verifier alone; the runner's
snapshot comparison detects changes during a run, not stale state supplied from
the outset. Key generation, permissions, containment, atomic persistence, and
physical trust separation still require integration review. Separate directories
in this single-process prototype do not establish separate security principals.

Artifacts/stores must remain stable during reads. Inputs and event counts have
no explicit resource bounds; failed writes can leave incomplete artifacts. Do
not treat file existence as successful execution. No report establishes events
that were never logged, HMAC nonrepudiation, or resistance to compromised trusted
stores. Key-rotation behavior remains covered by verifier tests; rotation
experiments and performance/statistical studies are outside this runner's scope.

## Integration readiness — 2026-11-17

### Branch and conflict assessment

Before Sprint 04/05 publication, live remote heads were `julian/testing`
**728dbce** and `main` **e61fce9**;
GitHub's read-only comparison confirmed **4 ahead / 1 behind**. The common
ancestor is **3f732e0**. Main's only additional commit merges Lucas's logging
branch; its tree is identical to that ancestor (`bfd34b6...`). Therefore no
textual merge conflicts are expected at these exact heads. This conclusion is
from tree comparison, not an executed merge; refresh the comparison before
integration if either branch moves.

Lucas's events/loggers and the shared schema/serializer are byte-identical
between the current working tree and main. Keyring/checkpoint modules are also
unchanged stubs. The published `ashton/security` head remains **c6fe442**; this
says nothing about unpushed work. Existing Sprint 04 runner, CLI, and tests were
preserved and revalidated, not regenerated.

The proposed PR covers Sprints 01-05: those four commits plus the reviewed
Sprint 04/05 publication, including `tests/test_experiment.py` and
`docs/reproduction.md`. The historical `728dbce` revision alone lacks that work.
Record the published commit in the handoff and refresh the branch comparison
before opening a PR. The readiness assessment above preceded publication.

### Shared-interface alignment

| Area | Current contract and coordination required |
|---|---|
| Mode D identity | `verify_hmac_checkpoint(path, key_store, checkpoint_store, *, expected_log_id)` requires the previously approved keyword argument from trusted configuration. The runner supplies it; future callers must do the same. |
| Identifier profile | Trusted-store names are 1-128 ASCII characters, alphanumeric first, then letters/digits/underscore/hyphen; reserved Windows device names are rejected. Logger inputs remain generic strings, so generators and storage APIs must align with this narrower profile. |
| Payloads/timestamps | Verifiers enforce schema types and a strict UTC timestamp profile. A accepts finite JSON floats; cryptographic modes reject floats. Loggers do not enforce every verifier constraint. The runner's generated events satisfy the contract. |
| Checkpoint cadence | The logger exposes other intervals, but the approved experiment/verifier policy requires one checkpoint per record. The runner explicitly selects interval 1. |
| Cannot verify | Verifiers raise `RuntimeError` with a `cannot verify:` prefix for known trusted-data failures. The runner recognizes this existing convention; unknown exceptions remain errors. A typed exception contract would require separate coordination. |
| Shared documentation | Sprint 05 updates README and `docs/interfaces.md` to the implemented contracts and distinguishes pending team agreement. Shared source/architecture proposal labels remain; no team ratification or persistence implementation is inferred. |

The present main merge introduces no conflicting edits. Future collaboration
hotspots are `docs/ai-usage.md` (retain every member's disclosure), shared
interface documentation, and CLI subparser registration when more commands are
added. These are coordination risks, not current merge conflicts.

### Ashton's implementation acceptance contract

| Interface / responsibility | Required behavior before real C/D results can be accepted |
|---|---|
| `generate_key(key_id, store_path) -> None` | Persist cryptographically random key bytes of length >= 32; restrict access and reject existing identifier/case-alias collisions. Do not derive keys from the experiment seed. |
| `load_key(key_id, store_path) -> bytes` | Return the exact immutable historical key. Missing IDs raise `KeyError`; read/permission failures raise `OSError`, malformed data raises `ValueError`/`TypeError`. Never silently regenerate keys, return defaults, or substitute the current key. |
| `rotate_key(new_key_id, store_path) -> str` | Create and return a new identifier while retaining all older identifiers and bytes. `list_keys(store_path) -> list[str]` must describe the actual stored IDs. |
| `create_checkpoint(log_id, seq, tag, store_path) -> Checkpoint` | Persist exactly that identity/sequence/tag atomically before reporting success. Propagate persistence failure and reject conflicting replacement of an existing anchor. |
| `load_checkpoints(log_id, store_path) -> list[Checkpoint]` | Return a detached, complete, current, stable snapshot for exactly that log: all records from seq 0, numerically ordered, no duplicates/gaps, integer sequences excluding booleans, lowercase 64-hex tags. Return all anchors, not only the last one. |
| Checkpoint retrieval failures | Reject ambiguous/malformed JSON, duplicate/conflicting anchors, inaccessible files, and partial reads. Never silently filter failures or return a cached/truncated prefix. Empty results cannot authorize an empty Mode D history. |
| Store isolation | Validate identifiers independently of verifier guards; enforce containment and safe symlink handling. Keys must be unreadable/unwritable and checkpoints unmodifiable/undeletable by the storage attacker. Separate directories alone do not establish this boundary. |

The three-field checkpoint API provides no independent high-water mark proving
that a returned snapshot is current and exhaustive. This remains a trusted
backend obligation. If the chosen backend cannot meet it, report the gap and
agree on a stronger contract before claiming truncation/rollback protection.
Logger append and checkpoint persistence are separate steps; the threat model's
assumption about the write/checkpoint window remains necessary.

### Recommended integration sequence

1. Review the preserved Sprint 04 implementation, Sprint 05 documentation/real-store
   test gates, and the cumulative verifier/attack contract; approve code and the actual partial results separately from
   any claim of complete system integration.
2. With explicit authorization, commit/push the intended workstream files.
   Opening the cumulative PR against main requires separate approval. The
   assessed content does not require a preliminary merge/rebase; follow team
   policy if an up-to-date branch is required and recheck live heads then.
   This document does not authorize publishing or merging.
3. Coordinate shared documentation and Ashton's contract on the integrated base.
   Preserve his ownership; review security-store behavior in its own PR.
4. With real stores, rerun all baselines and 16 cells, and test key rotation,
   missing historical keys, >10 checkpoints (numeric sorting), denied access,
   malformed/partial retrieval, stale snapshots, alias/symlink handling, and
   interrupted persistence. Run the five real-store gates prepared in Sprint 05,
   which replace the old end-to-end placeholder. Replace remaining teammate unit
   placeholders with meaningful assertions before removing their skips.
5. Publish updated empirical C/D results only after these gates pass. Preserve
   originals and nonsecret evidence; exclude private stores from report exports.

### Proposed pull request

**Base:** `main`. **Head:** `julian/testing`, after approved workstream publication.

**Title:** Add log verification, reproducible attacks, and experiment reporting

**Description:**

```markdown
Implement Modes A-D verification, storage-only attack helpers, and a seeded
experiment CLI covering all 16 mode/attack combinations. Each case starts from
independent evidence, applies the configured repair/reconstruction strategy,
uses a trusted verification mode/identity, and exports actual outcomes with
untouched controls and artifact hashes.

Validation: local and clean installed-package suites report **436 passed,
11 skipped**. Five real-store gates explicitly skip on known persistence stubs;
six teammate-owned placeholders remain. Real runs
with 50 events/seed 42 reproduce eight A/B misses and eight C/D blocked cells;
blocked dependencies are not counted as detection. Full C/D orchestration and
failure classification have passing store-double coverage; real-store tests
are prepared but blocked. README/interfaces and independent reproduction
instructions now match the implementation.

Security persistence remains unimplemented. Mode D requires independently
supplied `expected_log_id` and complete/current per-record checkpoints. This PR
preserves Lucas's implementation and Ashton's modules; real persistence/trust
separation still requires integration validation. GUI work and other CLI
subcommands are outside this change.

## AI Disclosure

AI tools assisted with implementation, testing, documentation, and code review under student direction. Contributions and design decisions are documented in `docs/ai-usage.md`. Each team member is responsible for understanding and explaining their respective implementation.
```

### Readiness revalidation evidence

The fresh unmocked CLI run is
`/private/tmp/tamperlog-sprint04-readiness/run-j0s5wqgd/results.json`; its repeat
is `/private/tmp/tamperlog-sprint04-readiness/run-1ukjz2zi/results.json`.
Reports match apart from their isolated directory, all exported artifact hashes
match, and every A/B attack input matches its original byte-for-byte. The
outcomes remain eight `MISSED` and eight `BLOCKED`, with no C/D attack verifier
results fabricated. Existing evidence directories were preserved. These are
temporary validation locations, not durable report archives.

Adversarial review rechecked baseline gating, fixed mode/identity selection,
no-op rejection, source/anchor preservation, key changes, incomplete controls,
rollback snapshots, error classification, and exception sanitization. Existing
fault-injection tests cover these paths. No new in-scope implementation defect
requiring code changes was identified; the trusted-backend and stable-artifact
limits above remain. This is an AI-assisted review, not independent student or
completed end-to-end security validation.


## Sprint 05 submission preparation

See [reproduction and human-review handoff](reproduction.md) for the clean
installed-package validation record, resolved environment, real-store test gates,
artifact checks, and submission checklist. The runtime runner/CLI and existing
Sprint 04 tests were preserved. New real integration scenarios use no store
doubles and do not turn unexpected backend failures into skips. The fresh
installed console runs reproduce the same eight misses/eight blocked cells;
C/D persistence integration remains outstanding.
