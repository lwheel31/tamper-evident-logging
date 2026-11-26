# Reproduction and human-review handoff

## Integration review — 2026-11-25

GitHub PR #4 was independently checked: open, unmerged, mergeable, head
`228d8fbd807ac7529ddac4b524a9eb6bdb8a61e8`, base
`cf58a794cdbbf73d0770df1132b4cdbe65884189`, six commits ahead and none behind.
The review uses local `integration-review/ashton-security` from that head.
Publication of the reviewed corrections in an integration PR is now approved;
merging remains subject to separate human approval. The historical Sprint 05 sections below describe the earlier state,
not the current persistence implementation or merge instructions.

### Actual validation

| Check | November 25 measured result |
|---|---|
| Original PR, Windows/Python 3.13.5/pytest 9.0.0 | 465 passed, 6 failed, no skips. |
| Pre-fix deterministic regressions | Binary-key translation and conflicting checkpoint publication failed; identical concurrent publication passed. |
| Corrected Windows full suite | 482 passed, 3 failed, no skips (485 collected). |
| Isolated installed Ubuntu/WSL suite | 485 passed, no skips; Python 3.14.4, pytest 9.2.0. |
| Isolated Windows package | Non-editable wheel installed; module bytes matched reviewed snapshot; `pip check` passed. |
| Installed Windows console CLI, twice | All 16 cells ran; 7 DETECTED, 9 MISSED. All four baselines and 16 controls verified 50 records. |
| Evidence/repeat checks | All exported artifact hashes and input/original copies matched; D had 50 matching anchors. Events, targets, A/B bytes and C/D content/outcomes repeated. Random keys differed. |
| Real-store security gates | Historical C/D rotation, unavailable old keys, missing/mismatched/empty checkpoints, and independent identity executed without store mocks. |

The remaining Windows failures are two `WinError 1314` symlink creation failures
and `test_key_file_is_owner_only` (`0666` reported instead of POSIX `0600`). No
skips, mocks, or permission changes were added to conceal them. The binary-key
fix also resolved nondeterministic corrupted-key and repeat-result failures.
An export assertion now explicitly reads UTF-8 rather than the Windows default
code page. POSIX mode bits are not evidence of Windows owner-only access.
An `icacls` inspection of a disposable key showed inherited full control for
SYSTEM, Administrators, and OWNER RIGHTS, with no additional grants displayed.
This observation does not provision or certify separation from the log account.

Full suites used `python -m pytest -q -rs --tb=short --basetemp FRESH_PATH`.
The installed Ubuntu suite ran outside the checkout with `PYTHONPATH` removed,
`-c /dev/null`, the snapshot tests, and native `/tmp` test storage. Existing CLI
subprocess unit tests intentionally use snapshot source; two separate installed
console-script executions validate the real entry point. Installed Windows runs:

```powershell
& "$reviewRoot\venv\Scripts\tamperlog.exe" experiment --output-dir "$reviewRoot\runs" --event-count 50 --seed 42
```

Here `$reviewRoot` is the external temporary validation root:
`C:\Users\rober\AppData\Local\Temp\tamperlog-final-review-257b88f3985e4de585f22944967d434d`.
It contains `source-manifest.json`, `validation.json`, `final-pytest.xml`,
`linux-pytest.xml`, the isolated source/environment, and reports at
`runs/run-mg7w61cv/results.json` and `runs/run-aazyqzvt/results.json`.
The snapshot includes uncommitted runtime/test fixes; later documentation edits
do not change those validated module bytes. This location is temporary, not a
durable submission archive. Never export its private key stores or entire runs.

### Findings and corrections

- **Medium: checkpoint immutability race.** The regression pauses a trusted
  writer after the existence check, lets another writer publish tag A, then
  resumes the first writer with conflicting tag B. Original `os.replace`
  returns success and replaces A. Unique temporary files plus atomic `os.link`
  now reject conflicting publication and permit identical idempotent retries.
  This is a trusted concurrency defect, not a demonstrated storage-attacker exploit.
- **High for Windows correctness/availability: binary key translation.**
  Persisting synthetic `bytes(range(32))` changed LF into CRLF at offset 10.
  Binary file opening now preserves all 32 bytes. This did not establish HMAC
  forgery; the loader failed closed on the wrong length.
- **Low: short writes and failed persistence.** Both providers ignored the count
  from `os.write`; interrupted creation left retry-blocking files. Write loops
  now complete short writes and reject zero progress; exception paths close
  descriptors and remove owned incomplete key/temp files. Injected write,
  flush, and checkpoint-publication failures exercise cleanup and retry.
- **Low: ambiguous trusted JSON.** Duplicate checkpoint fields were accepted
  with last-value semantics. Loading now rejects duplicates and invalid stored
  tags, including on idempotent create. Regression tests exercise these cases.
- **Environment/deployment gap:** Windows ACL protection is not provisioned or
  certified by `0600`/`0700`. Configure protected storage separately. Do not claim
  native Windows security-isolation readiness from the functional experiment.

Hard-link publication requires filesystem support; it raises on unsupported
storage. It protects complete, non-replacing publication, not power-loss
durability of directory entries. Abrupt process termination can leave temporary
files or a partially created key. Checkpoint retrieval is not a locked snapshot:
use quiescent, protected stores and one trusted logger per stream. Matching stale
prefixes, hostile trusted-directory mutation, and compromised keys remain outside
the established guarantees. No entropy proof or OS credential isolation was
established by these tests. All validation was AI-assisted and tool-executed;
human academic review is still required.

### Human review and merge sequence

PR #4 is not recommended for merge as-is: it lacks the reviewed corrections.
Julian approved committing the reviewed persistence, test, and documentation
changes, publishing this integration branch, and opening a replacement PR to main.
Refresh remote heads and repeat validation if the source base changes. The
integration branch contains all six original Ashton commits plus the reviewed fix
commit. Coordinate superseding PR #4 with the team. Use a merge commit to preserve
contributor history, without squash, rebase, or a push to Ashton's branch.

After the approved integration merge, update a clean local main using
`git fetch origin`, `git switch main`, and `git pull --ff-only origin main`.
Record its new commit, run the complete suite with fresh external test storage,
install that exact revision in a fresh environment, and run the 50-event/seed-42
installed CLI twice. Require the four valid baselines and matrix in
[experiments](experiments.md), retain reviewed nonsecret evidence, and update
report/presentation revision references. Merging either PR remains unauthorized;
coordinate superseding PR #4 without deleting Ashton's branch.

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
