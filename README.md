# Tamper-Evident Logging — ITIS 6200

A synthetic cybersecurity experiment comparing plaintext, SHA-256 chaining,
HMAC chaining, and HMAC with trusted checkpoints against a storage attacker.

**Current status:** All loggers, verifiers, four required attacks, experiment
orchestration, and the experiment CLI are implemented. Ashton's persistence is
implemented on the integration-review branch. Two installed 50-event/seed-42
runs exercised all four modes with real disposable stores. Local persistence
corrections are approved for publication in an integration PR; merging remains
subject to human approval. PR #4 is not merged.

## Install and run

Requires Python **>= 3.10**. The November 25 review exercised Windows/Python
**3.13.5** and Ubuntu/WSL/Python **3.14.4**; Windows has three platform-specific
test failures described below. Earlier validation used macOS/Python 3.13.3.
Other supported runtime combinations have not been validated. Runtime code uses
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
the commands above describe the general workflow; validation was performed on macOS, Windows, and Ubuntu/WSL as documented below. For a non-editable,
isolated package test outside the checkout, follow [clean reproduction](docs/reproduction.md).
The source repository is [lwheel31/tamper-evident-logging](https://github.com/lwheel31/tamper-evident-logging).
Use the reviewed integration revision and record
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
| `keyring.py`, `checkpoints.py` | Ashton: historical key persistence and trusted per-record anchors; local integration corrections under review. |
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

Two installed, unmocked runs on November 25 with **50 events, seed 42** verified all four originals and
targeted payroll export sequence **25**. A deletion/reorder repairs sequences;
B rebuilds public sequences/links/hashes. C/D preserve HMAC tags and checkpoints.

| Attack | A | B | C | D |
|---|---|---|---|---|
| Modify | MISSED | MISSED | DETECTED | DETECTED |
| Delete | MISSED | MISSED | DETECTED | DETECTED |
| Reorder | MISSED | MISSED | DETECTED | DETECTED |
| Truncate | MISSED | MISSED | MISSED | DETECTED |

Nine misses and seven detections are observed results for these strategies,
with all untouched 50-record baselines and controls valid. `MISSED` means the transformation passed verification: reordering
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

November 25 validation of the locally corrected review: **485 passed, no skips**
in an isolated Ubuntu installed-package suite; Windows reports **482 passed,
3 failed, no skips** (two symlink privilege failures and a POSIX `0600` assertion).
Windows ACL isolation remains an operator responsibility; POSIX mode arguments
do not establish Windows owner-only access. Run `python -m pytest -q -rs`.
Unit and orchestration tests use explicit store doubles; `tests/test_integration.py` uses
real store interfaces with no fallback keys or mocks. Its scenarios cover
the full 16-cell runner, C/D historical rotation and missing keys, missing
or mismatched checkpoints, and independent identity. The historical skip helper recognizes only exact known unimplemented entry-point
stubs; unexpected errors and assertion failures remain failures.

Ashton's keyring/checkpoint/logger tests now execute. No new skips hide failures. See
[reproduction and human-review handoff](docs/reproduction.md) for actual validation
counts, installation evidence, artifact review, blockers, and submission gates;
[experiment methodology](docs/experiments.md) contains the detailed protocol and
proposed cumulative PR description.

## AI Disclosure

AI tools assisted with implementation, testing, documentation, and code review under student direction. Contributions and design decisions are documented in `docs/ai-usage.md`. Each team member is responsible for understanding and explaining their respective implementation.
