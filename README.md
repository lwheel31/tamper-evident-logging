# Tamper-Evident Logging — ITIS 6200

A synthetic cybersecurity experiment comparing plaintext, SHA-256 chaining,
HMAC chaining, and HMAC with trusted checkpoints against a storage attacker.

**Current status:** All loggers, verifiers, four required attacks, experiment
orchestration, and the experiment CLI are implemented. Real A/B runs work.
Ashton's key/checkpoint persistence remains unimplemented, so real C/D runs are
blocked. Mocked tests do not establish completed integration.

## Install and run

Requires Python **>= 3.10**. Current validation uses Python **3.13.3 on macOS**;
other supported runtimes/platforms have not been validated. Runtime code uses
the standard library; the declared development dependency is `pytest>=7.0`.

From the reviewed checkout or an exact working-tree snapshot (macOS/Linux):

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pip check
python -m pytest -q -rs
tamperlog experiment --output-dir /tmp/tamperlog-runs --event-count 50 --seed 42
```

On Windows, use the appropriate Python launcher and `.venv\Scripts` activation;
the commands above describe the validated macOS workflow. For a non-editable,
isolated package test outside the checkout, follow [clean reproduction](docs/reproduction.md).
The source repository is [lwheel31/tamper-evident-logging](https://github.com/lwheel31/tamper-evident-logging).
Use the reviewed publication revision of `julian/testing` and record
`git rev-parse HEAD`. Historical revision `728dbce` contains Sprints 01-03;
it does not contain the experiment runner or Sprint 05 reproduction work.

`experiment` is the implemented CLI subcommand. It accepts `--output-dir`,
`--event-count` (integer >= 4), and `--seed`; defaults are `experiment-results`,
50, and 42. `tamperlog --help` and `tamperlog experiment --help` show usage.
`generate`, `verify`, `attack`, and `keys` are not registered CLI commands;
their implemented operations are available through Python APIs where applicable.
From an uninstalled checkout, use `PYTHONPATH=src python3 -m tamperlog.cli experiment ...`.

Every invocation creates a fresh private `run-*` directory. Existing evidence
is never reused or overwritten. Exit code zero means a report was produced,
not that all modes ran or every attack was detected.

## Architecture and ownership

The runner generates one seeded event stream and sends identical event content
to each logger. It validates untouched baselines, then applies each attack to an
independent original copy. Trusted configuration selects the verifier and log
identity; record contents never select those security assumptions.

| Component | Responsibility / owner |
|---|---|
| `events.py`, `loggers.py` | Lucas: deterministic events, A-C logging, and D append calls into checkpoints. |
| `schema.py`, `serialization.py` | Shared contracts: eight-field JSONL records and deterministic canonical bytes. |
| `keyring.py`, `checkpoints.py` | Ashton: protected historical keys and trusted per-record anchors; persistence pending. |
| `verifier.py`, `attacks.py`, `experiment.py` | Julian: verification, storage-only attacks, experiment execution, and integration. |
| CLI and shared reviews | Team collaboration; experiment subcommand implemented. |

Keys/checkpoints belong outside attacker-writable logs. Separate directories in
this prototype do not demonstrate separate credentials or filesystem protection.
See [implemented interfaces and open agreements](docs/interfaces.md).

## Mechanisms and security limits

| Mode | Implemented check | Limit against the approved attacker |
|---|---|---|
| A | Record structure, identity consistency, sequence order | Valid-looking edits and sequence repair can pass. No cryptographic integrity. |
| B | A plus public SHA-256 digests and previous-tag links | An attacker can rebuild the chain. Valid prefixes pass. |
| C | HMAC-SHA256 with each record's historical key | New authenticated contents require a secret key; valid prefixes and replay of signed logs can still pass. |
| D | C plus independently expected identity and every trusted checkpoint | Covers substitution/truncation relative to a complete, current, protected checkpoint set. Trusted-store rollback is outside the guarantee. |

The attacker may read/write stored logs, modify/delete/reorder entries, truncate,
and rewrite the file. The attacker cannot obtain keys, modify trusted anchors,
or control logger/verifier code. The approved model assumes no attacker action
between a record write and its checkpoint. See the [threat model](docs/threat-model.md).

Neither mode prevents disclosure or proves events that were never recorded.
HMAC is not nonrepudiation. A/B/C accept existing empty files without proving an
honest empty history; D fails closed because no trusted empty-history marker is
implemented. Verification assumes stable captured artifacts and trusted stores.
There are no explicit resource bounds or snapshot locks.

## Actual experiment evidence

Real unmocked runs with **50 events, seed 42** verified both A/B originals and
targeted payroll export sequence **25**. A deletion/reorder repairs sequences;
B rebuilds public sequences/links/hashes. C/D preserve HMAC tags and checkpoints.

| Attack | A | B | C | D |
|---|---|---|---|---|
| Modify | MISSED | MISSED | BLOCKED | BLOCKED |
| Delete | MISSED | MISSED | BLOCKED | BLOCKED |
| Reorder | MISSED | MISSED | BLOCKED | BLOCKED |
| Truncate | MISSED | MISSED | BLOCKED | BLOCKED |

Eight misses and eight blocked cells are observed results for these strategies.
C/D stopped at the real key-generation stub; they are not measured successes
or failures. `MISSED` means the transformation passed verification: reordering
changes chronology but leaves the export present. Unrepaired/unrehashed edits
are covered separately by attack/verifier tests.

Runs export `events.json`, original/attack JSONL artifacts, `results.json`, and
`matrix.md`. JSON records targets, transformations, actual verifier/control
results, failure positions, statuses, and evidence hashes. Outcomes are
`DETECTED`, `MISSED`, `CANNOT_VERIFY`, `BLOCKED`, or `ERROR`; a failed untouched
control prevents a detection claim. Matching real repeats reproduced A/B hashes
and results. Fresh HMAC keys must remain random, not seeded for byte equality.

**Never publish `trusted/` or an entire keyed run directory.** JSON/Markdown
exports omit key bytes and raw backend exception messages. Artifact hashes do
not authenticate the report. The default repository output directory is ignored;
keep other generated runs outside the checkout. Only deliberately reviewed,
nonsecret evidence should enter an academic submission.

## Tests and submission readiness

Latest local and isolated installed-package validation: **436 passed, 11 skipped**
(2026-11-17). Run `python -m pytest -q -rs` to show skip reasons. Unit and orchestration tests
use explicit test doubles for pending stores; `tests/test_integration.py` uses
real store interfaces with no fallback keys or mocks. Its five scenarios cover
the full 16-cell runner, C/D historical rotation and missing keys, and missing
or mismatched checkpoints. They skip only exact known unimplemented entry-point
stubs; unexpected errors and assertion failures remain failures.

Teammate-owned keyring/checkpoint/logger test placeholders also remain skipped.
Those are unfinished tests, not integration evidence. See
[reproduction and human-review handoff](docs/reproduction.md) for actual validation
counts, installation evidence, artifact review, blockers, and submission gates;
[experiment methodology](docs/experiments.md) contains the detailed protocol and
proposed cumulative PR description.

## AI Disclosure

AI tools assisted with implementation, testing, documentation, and code review under student direction. Contributions and design decisions are documented in `docs/ai-usage.md`. Each team member is responsible for understanding and explaining their respective implementation.
