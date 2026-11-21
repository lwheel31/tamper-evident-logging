# Reproduction and human-review handoff

## Revision and scope

Use the reviewed Sprints 01-05 publication revision of `julian/testing` and
record its full commit ID with `git rev-parse HEAD`. Historical revision
`728dbce` contains only Sprints 01-03 and cannot reproduce the complete workstream.
For a published revision, use a clean checkout at that exact commit. For an
uncommitted review, copy the intended working tree; `git archive HEAD` omits
uncommitted changes.

The runtime implementation is preserved. Sprint 05 updates documentation,
prepares real-store tests, and protects the default output directory from
accidental inclusion. It does not implement persistence, add runtime dependencies,
redesign security components, or certify deployment isolation.

## Independent reproduction

For normal development, follow the editable installation in [README](../README.md).
For packaging validation, use a fresh temporary directory and non-editable install:

1. Copy the intended source, tests, metadata, and documentation from the reviewed
   checkout, including `tests/test_experiment.py`. Exclude `.git`,
   virtual environments, caches, build products, keys, and generated run artifacts.
   Review `git ls-files --cached --others --exclude-standard` before copying;
   ignored files already tracked by Git still require explicit inspection.
2. Create a virtual environment with no system site packages. Install the copied
   project and its declared development extra. Example paths below are outside
   the checkout; replace them with your own snapshot/environment locations.

   ```sh
   python3 -m venv /tmp/tamperlog-check/venv
   /tmp/tamperlog-check/venv/bin/python -m pip install "/tmp/tamperlog-check/source[dev]"
   /tmp/tamperlog-check/venv/bin/python -m pip check
   ```

3. Change to an empty directory outside the source tree. Remove `PYTHONPATH`,
   confirm imports come from that environment's `site-packages`, and run tests
   without the repository's pytest `pythonpath=src` setting:

   ```sh
   cd /tmp/tamperlog-check/work
   env -u PYTHONPATH /tmp/tamperlog-check/venv/bin/python -c 'import tamperlog; print(tamperlog.__file__)'
   env -u PYTHONPATH /tmp/tamperlog-check/venv/bin/python -m pytest -c /dev/null /tmp/tamperlog-check/source/tests -q -rs
   ```

   Create the example directories first. Existing CLI subprocess unit tests
   deliberately set `PYTHONPATH` to the copied source; the separate installed
   console-script check below is necessary to verify packaging/entry-point behavior.

4. Execute the installed console script twice with separate fresh run directories:

   ```sh
   env -u PYTHONPATH /tmp/tamperlog-check/venv/bin/tamperlog experiment --output-dir /tmp/tamperlog-check/runs --event-count 50 --seed 42
   ```

   Confirm both untouched A/B logs verify 50 records, all 16 cells are present,
   parameters/targets match, and A/B input copies and artifact hashes match.
   Reports should match apart from run directory while C/D are blocked. With real
   random keys, C/D tag bytes need not match; compare content, controls, and outcomes.
5. Record Python, pip, resolved dependency versions, source/test hashes, and the
   actual commands/results. Dependencies are lower-bounded, not locked: this is
   a source/parameter reproduction procedure, not a bit-for-bit environment lock.
   Only macOS/Python 3.13.3 has been exercised; declared Python >= 3.10 support
   still needs a runtime/platform matrix.

## Real-store test gates

`tests/test_integration.py` contains five scenarios, without mocks:

- One full experiment verifies all 16 actual mode/attack combinations after a
  real key/checkpoint preflight; 50 anchors exercise numeric sorting beyond 9.
- C/D rotation tests retain historical keys and linkage, then use another real
  store missing the old identifier and require `KeyError` / `cannot verify`.
- Two checkpoint tests retain valid HMAC records while required tail anchors
  are absent or a well-formed trusted tag disagrees.

The skip helper recognizes only exact known provider-stub messages raised from
those entry points' code objects. Permission errors, malformed data, arbitrary
`NotImplementedError`s, unexpected helper failures, and assertion failures are
not skips. After preflight succeeds, blocked/error runner cells fail the real
matrix test instead of becoming skips. No test manufactures valid C/D outcomes.

Currently, all five scenarios stop at the real `generate_key` stub. Six separate
teammate-owned unit/logger placeholders remain skipped. Replacing the old single
integration placeholder adds four explicit blocked scenarios, not four passing
results or a regression in implemented behavior.

## Recorded validation — 2026-11-17

| Check | Actual result |
|---|---|
| Local complete suite | 436 passed, 11 skipped; unchanged passing count from Sprint 04. |
| Fresh non-editable install | Wheel built from the uncommitted working-tree snapshot and installed successfully; system and user site packages disabled. |
| Dependency check | `pip check`: no broken requirements. |
| Installed-package suite | 436 passed, 11 skipped with `PYTHONPATH` unset, outside source, `-c /dev/null`. |
| Package provenance | All 11 installed Python module files match working-tree source bytes. |
| Installed console CLI | Two real 50-event/seed-42 runs: 8 MISSED A/B cells, 8 BLOCKED C/D cells at key generation. |
| Reproduction checks | Reports match except run directory; originals/input copies and exported artifact hashes match. |
| Skip policy probes | Five unexpected exceptions propagated, including identical stub wording from unrelated code; only the known entry-point stub skipped. |

Resolved versions: Python 3.13.3, pip 25.0.1, pytest 9.2.0, iniconfig 2.3.1,
packaging 26.3, pluggy 1.7.0, Pygments 2.21.0, project 0.1.0. These are recorded
versions, not a new dependency lock or additions to `pyproject.toml`.
The sandbox initially blocked package-index access; the successful installation
used approved network access for declared build/dev dependencies only.

The temporary validation root is
`/private/var/folders/47/8bdc_kds329ghkrdbzqt9r840000gn/T/tamperlog-sprint05-validation-qlltd7b5/`.
It contains `validation.json`, `source-manifest.json`, a source snapshot, the
isolated environment, and `runs/run-zt0la892/results.json` plus
`runs/run-pjjca9bn/results.json`. Imports came from `venv/.../site-packages`.
Existing CLI subprocess unit tests still deliberately use the snapshot source;
the two separately invoked installed console runs close that validation gap.
Keep nonsecret receipts/evidence in a durable approved location before temporary
cleanup; do not copy the virtual environment or private stores into a submission.

Final publication revalidation reproduced the same suite count and installed-CLI
results. Its receipt is `publication-validation.json` under that validation root;
the two additional reports are in `publication-runs/run-nqhxyyox/` and
`publication-runs/run-3w4pcki_/`. Module provenance, help/invalid-count behavior,
dependency checks, controls, and exported artifact hashes were rechecked.

## Audit findings and remaining blockers

- No new in-scope runtime correctness defect was identified in the cumulative
  audit. Parser duplication has distinct purposes: verification enforces
  continuity; attack helpers must accept gaps/reordering for explicit repair.
  The existing control/evidence checks are retained rather than redesigned.
- Real C/D integration remains blocked. Ashton must retain immutable historical
  keys and provide complete, current, stable per-record checkpoint retrieval or
  raise. A stale log plus matching stale anchors can pass if that contract is
  violated; snapshot hashes only detect changes observed during a run.
- Logger input validation is weaker than verifier validation. The implemented
  UTC profile, identifier restrictions, and per-record D policy are documented
  in [interfaces](interfaces.md); they require team alignment, not silent
  broadening or modification of teammates' modules.
- Real-store tests do not prove entropy, credential separation, permissions,
  containment, crash consistency, or freedom from concurrency/resource attacks.
  Those require source review and environment-specific integration checks.
- This is an AI-assisted audit and tool-executed validation, not independent
  human approval or proof of cryptographic security.

## Artifact and submission review

Before any commit, inspect the intended files and the staged diff. `.gitignore`
excludes keys/trusted stores, caches/build products, and default
`experiment-results/`; custom run locations should remain outside the repository.
Ignore rules do not protect already-tracked files. Known fixed keys in tests
are disclosed synthetic fixtures, not generated persistence keys.

Publish only reviewed nonsecret evidence (`results.json`, `matrix.md`, event/log
artifacts needed by the report), never an entire keyed run directory. Check
private-key/token patterns and unexpected binary/generated files without printing
secrets. Do not include virtual environments, local package metadata, or pip
caches. Record actual blocked cells; do not infer C/D detection from mocks.

## Human approval and PR handoff

1. Independently explain the decisions below and review implementation, skips,
   installation evidence, and artifact inventory. Resolve shared-contract issues
   with Lucas/Ashton. The updated interface document describes behavior without
   asserting unrecorded team ratification.
2. After explicit authorization, stage only the intended source/test/doc changes:
   `.gitignore`, `README.md`, `docs/ai-usage.md`, `docs/experiments.md`,
   `docs/interfaces.md`, `docs/reproduction.md`, `src/tamperlog/cli.py`,
   `src/tamperlog/experiment.py`, `tests/test_experiment.py`, and
   `tests/test_integration.py`. Inspect the staged diff for credentials, generated
   data, and attribution changes; the file list is not authorization to stage or
   publish now.
3. Recheck remote heads. The previously verified main merge has no additional
   file content beyond the common ancestor, so no textual conflict was expected
   then. Do not assume this remains true after teammates publish changes.
4. Commit/push only with explicit publication authorization. Opening a PR and
   merging require separate approval. Use the
   [PR proposal](experiments.md#proposed-pull-request), updating validation counts
   and recording the published commit. Do not force-push or remove teammates'
   AI disclosures.
5. Review Ashton's implementation separately. Once real-store gates run, record
   actual integration results and remove remaining placeholder skips only when
   meaningful tests replace them. Update the academic report with the approved
   revision, parameters, commands, environment versions, and nonsecret evidence.

Before submission, be able to explain canonical bytes and excluded tags; public
rehashing versus keyed authentication; authenticated historical key IDs and
rotation; why valid prefixes pass C; why D needs independent identity and current
anchors; why unavailable data is not detection; why reordering need not conceal
an incident; and why tests/mocks/hashes do not establish physical trust or human
validation. Human review is the next step; no merge, commit, push, or PR creation
is authorized by this document.
