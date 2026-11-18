# AI Usage Disclosure

This record documents AI assistance for the ITIS 6200 Tamper-Evident Logging
project. Team-member attribution identifies who directed the work, not sole
code authorship. Test results and AI reviews do not establish independent human
validation unless explicitly stated.

## Standard for future entries

Use a dated session heading, identify the tool/model (when known) and team
member, and summarize the five fields used below. Separate student instructions
and approvals from AI-proposed designs. Record generated artifacts, substantive
review findings and corrections, validation evidence, and unresolved dependencies.
Consolidate related implementation/remediation work; omit transcript narration,
repeated explanations, and superseded approval requests. Disclose AI-assisted
reviews and documentation work as well as code generation.

## 2026-11-15 — Initial scaffold

**Tool / team member:** Claude Code (Claude Opus 4.6) / Lucas Wheeler.

- **Purpose / prompt:** Inspect the empty repository and create the project
  structure, module interfaces, documentation, and test skeletons.
- **AI contributions:** Generated module stubs with `NotImplementedError`,
  test skeletons, README, `pyproject.toml`, documentation, examples directory,
  and the initial AI usage log. No security logic, attacks, or experiment
  results were generated in this session.
- **Student direction / decisions:** The prompt established ownership: Lucas
  for events/logging, Ashton for keys/checkpoints and Mode D, Julian for verification,
  attacks, experiments, and integration; shared contracts required team review.
  The scaffold was explicitly restricted to structure and interfaces.
- **Review / validation:** Schema, serialization, and threat-model review items
  were recorded; completed review or test results were not documented.
- **Limitations / dependencies:** Implementation and team agreement on shared
  contracts were subsequent work.

## 2026-11-16 — Events, serialization, and logging

**Tool / team member:** Claude (model not recorded) / Lucas Wheeler.

- **Purpose / prompt:** Implement events, serialization hardening, logging
  Modes A-C, and Mode D append calls to Ashton's checkpoint interface.
- **AI contributions:** Generated `events.py`, serialization hardening,
  logging implementations, and matching tests.
- **Student direction / decisions:** Lucas owned events/logging. Implementation
  choices recorded for team review included deterministic event tuples,
  zero-based sequences, the public genesis tag, canonical data excluding floats
  and non-string dictionary keys, and refusal to overwrite existing logs.
- **Review / validation:** Recorded pytest result: **21 passed, 17 skipped**.
- **Limitations / dependencies:** Mode D append depended on Ashton's checkpoint
  implementation; the test result did not establish that integration.

## 2026-11-17 — Sprint 01: Modes A/B, review, and remediation

**Tool / team member:** OpenAI Codex / Julian Roberts.

- **Purpose / prompt:** Verify repository continuity after the macOS migration;
  implement and test plaintext and SHA-256 verification, audit the changes,
  and remediate identified defects within the verifier, tests, and disclosure.
- **AI contributions:** Generated `verifier.py` Mode A/B logic and docstrings,
  `test_verifier.py` checks and local attack demonstrations, review findings,
  remediation, and disclosure entries. Coverage included malformed records,
  independent canonical-byte vectors, field tampering, final-record corruption,
  public rehashing, and truncation.
- **Student direction / decisions:** Julian required shared-interface and
  ownership preservation, explicit security limits, and first-failure reporting.
  Following AI review, he directed strict UTC syntax validation and acceptance
  of finite floats in Mode A while retaining Mode B's canonical restrictions.
- **Review / validation:** AI review found malformed UTC suffixes incorrectly
  passing and untouched plaintext float payloads incorrectly failing. Both were
  corrected with regressions. Pytest progressed from **21 passed, 17 skipped**
  through **172 passed, 14 skipped** to **213 passed, 14 skipped** on Python
  3.13.3; whitespace checks passed. Julian subsequently reported Sprint 01
  complete, committed, and pushed.
- **Limitations / dependencies:** A/B do not prove authenticity or completeness;
  plaintext edits, correctly rehashed SHA-256 rewrites, and valid tail truncation
  can pass. Verification assumes captured, stable artifacts and has no explicit
  resource bounds.

## 2026-11-17 — Sprint 02: Modes C/D verification

**Tool / team member:** OpenAI Codex / Julian Roberts.

- **Purpose / prompt:** Implement historical-key HMAC verification and trusted
  checkpoint verification; test attacks, rotation, dependency failures, and A/B
  regressions without implementing Ashton's modules.
- **AI contributions:** Generated Mode C/D verifier logic, mocked security-store
  tests, adversarial review, and disclosure. Tests used real logger/verifier
  computations and a hard-coded HMAC vector calculated with OpenSSL independently
  of the shared serializer and Python HMAC implementation.
- **Student direction / decisions:** Julian required checkpoint-per-record
  coverage, safe identifier lookup, fail-closed dependency handling, and
  substitution protection. He explicitly approved the AI-proposed required
  keyword-only `expected_log_id` argument for `verify_hmac_checkpoint`; callers
  must supply it from trusted configuration. Other public signatures and result
  fields were preserved.
- **Review / validation:** AI review identified reserved Windows device names
  as a lookup hazard; guards and regression tests were added. Tests demonstrated
  Mode C truncation passing and Mode D rejecting truncation, removal, mismatches,
  and substitution with current trusted anchors. Full pytest: **305 passed,
  11 skipped**, versus **213 passed, 14 skipped** initially; whitespace checks
  passed. Checks against real unimplemented stubs raised “cannot verify.”
- **Limitations / dependencies:** Key/checkpoint persistence remained mocked.
  Ashton must provide retained historical keys and complete, current, stable
  checkpoint retrieval or raise; matching stale log/checkpoint prefixes can pass.
  Store permissions, separation, containment, durability, and real integration
  remain unvalidated. Identifier generation must match the verifier's restricted
  naming profile. Mode C cannot establish completeness; Mode D has no trusted
  empty-history representation. Stable-artifact/resource limitations remain;
  runtime validation covered Python 3.13.3 on macOS.

## 2026-11-17 — Sprint 02 read-only adversarial audit

**Tool / team member:** OpenAI Codex / Julian Roberts.

- **Purpose / prompt:** Attempt substitution, replay, unsafe key lookup, public
  chain reconstruction, checkpoint damage/rollback, removal, and historical-key
  failures; assess mocks, test quality, complexity, and integration requirements.
- **AI contributions:** Produced an audit report and temporary attack probes;
  no repository files were changed. Documented Ashton's required storage-interface
  behavior in the report.
- **Student direction / decisions:** Julian required a read-only audit that
  distinguished implementation defects from the approved threat-model limits.
- **Review / validation:** Reproduced **305 passed, 11 skipped**. Ten unsafe-key
  probes were rejected before lookup; **198 A/B differential cases** matched
  committed Sprint 01 behavior. The AI audit recommended component approval
  under the stated contracts, with integrated-system approval blocked on storage
  implementation and testing. No high/medium implementation defect was found
  under those contracts.
- **Limitations / dependencies:** Replaying both a log prefix and matching stale
  trusted checkpoints passed, confirming the retrieval/freshness boundary.
  Mocks do not establish physical trust separation or persistence correctness.

## 2026-11-17 — Sprint 03: Storage-only attacks

**Tool / team member:** OpenAI Codex / Julian Roberts.

- **Purpose / prompt:** Implement reproducible modification, deletion, reordering,
  truncation, and public SHA-256 reconstruction; test artifacts and verifier
  outcomes within the existing threat model.
- **AI contributions:** Generated `attacks.py`, attack tests, adversarial probes,
  and this entry. Added `repair_sequences` and `rebuild_hash_chain` without
  changing existing public signatures; full-log fabrication remains deferred.
- **Student direction / decisions:** Julian required separate evidence-preserving
  copies, deterministic behavior, invalid-request rejection, no silent overwrite,
  no key/checkpoint access, and unchanged HMAC tags. CLI and experiment
  orchestration remained excluded. AI-proposed helpers make sequence repair
  and hash reconstruction explicit stages; basic attacks preserve labels/tags.
- **Review / validation:** Full pytest: **407 passed, 7 skipped**, versus the
  verified **305 passed, 11 skipped** baseline; 102 attack cases replaced four
  skipped stubs. Tests check exact record effects, source/trusted-file preservation,
  no trusted-interface calls, repeatability, collisions, malformed inputs, and
  actual verifier detection/evasion. Review added cyclic-payload rejection and
  tail-deletion coverage. Additional probes confirmed composed Mode B evasion,
  hard-link overwrite refusal, and that relabelling HMAC data as Mode B does
  not forge a chain accepted by the original Mode C verifier. Existing signature
  comparison and whitespace checks passed.
- **Limitations / dependencies:** C/D persistence remains mocked; integration
  still depends on Ashton's stores. Mode guards inspect unauthenticated field
  shape, so experiments must independently retain the original verification mode.
  Outputs reformat JSON; source bytes are preserved. Stable synthetic artifacts
  are required, input size is unbounded, and failed writes can leave partial
  outputs. Artifact creation does not establish detection evasion or incident
  concealment; tail deletion remains undetectable in A/B/C without trusted anchors.

## 2026-11-17 — Sprint 04: Experiment automation and integration readiness

**Tool / team member:** OpenAI Codex / Julian Roberts.

- **Purpose / prompt:** Automate all 16 mode/attack combinations with reproducible
  inputs, truthful classifications, CLI configuration, and report evidence while
  security persistence remains pending; review main-branch alignment and
  prepare an integration contract and PR proposal.
- **AI contributions:** Generated `experiment.py`, experiment-only CLI wiring,
  `test_experiment.py`, methodology/results documentation, and this entry.
  Added isolated runs, independent attack-effect checks, source/artifact hashes,
  checkpoint snapshots, sanitized errors, and untouched-control verification.
  Continued readiness work preserved existing code/tests and added read-only
  GitHub comparison, interface/merge assessment, and a proposed PR description.
- **Student direction / decisions:** Julian required one shared event stream,
  payroll targeting, A sequence repair/B public reconstruction, preserved C/D
  authentication data, trusted mode/identity selection, no overwrites or secret
  export, and production use of real interfaces with mocks confined to tests.
- **Review / validation:** Full pytest: **436 passed, 7 skipped**, versus the
  verified **407 passed, 7 skipped** baseline; 29 new cases cover orchestration,
  exports, CLI, isolation, reproducibility, and fault classification. Adversarial
  checks prevent no-op attacks, altered originals/checkpoints, changed keys, and
  incomplete controls from yielding false detection claims. Real unmocked CLI
  and repeat API runs with 50 events/seed 42 produced **8 MISSED A/B cells and
  8 BLOCKED C/D cells**; reports matched apart from run directory and exported
  artifact hashes were checked. Revalidation confirmed the same results; live
  refs are 4 ahead/1 behind main, whose merge-only commit has no additional file
  changes from the common base. No current textual conflicts are expected.
  Whitespace checks passed.
- **Limitations / dependencies:** C/D stopped at the actual key-generation stub;
  full-path store-double tests are not integration results. Complete/current
  trusted snapshots, historical keys, permissions, and persistence remain Ashton's
  integration dependencies. Snapshot comparisons do not prove initial freshness;
  artifacts must remain stable and resource bounds remain absent. Reordering
  changes chronology without removing the export. Private trusted stores must
  not be published with report artifacts.

## 2026-11-17 — Sprint 05: Integration gates and reproduction

**Tool / team member:** OpenAI Codex / Julian Roberts.

- **Purpose / prompt:** Audit the cumulative workstream, preserve Sprint 04,
  correct public contracts/docs, prepare real-store integration gates, validate
  clean installation/reproduction, and prepare academic handoff.
- **AI contributions:** Updated README/interfaces/methodology and generated
  `docs/reproduction.md`, five real-store scenarios in `test_integration.py`,
  and a default-output ignore rule. Runtime modules and Sprint 04 tests were
  preserved; no persistence implementation was generated.
- **Student direction / decisions:** Julian required exact known-dependency
  skips, no hidden unexpected failures or fake integration results, independent
  working-tree installation, secret/artifact review, and human approval before
  publication or submission. AI implemented origin/message-specific skip gating.
- **Review / validation:** Local and isolated non-editable package suites both
  report **436 passed, 11 skipped**: five real-store gates replace one placeholder
  and stop at the real key-generation stub; six owner placeholders remain. All
  11 installed module files match source. Installed CLI repeats reproduce **8
  MISSED / 8 BLOCKED** cells with matching evidence hashes. Skip-policy fault
  probes, dependency checks, credential-marker/candidate-file review, and
  whitespace checks passed. Environment/commands are recorded in reproduction docs.
- **Limitations / dependencies:** Actual C/D persistence, physical trust, and
  complete/current snapshot retrieval remain unvalidated and depend on Ashton.
  No student-independent validation is claimed. Only macOS/Python 3.13.3 was
  exercised; dependencies are not locked. No merge, commit, push, or PR was made.

## 2026-11-17 — Final quality gate and publication preparation

**Tool / team member:** OpenAI Codex / Julian Roberts.

- **Purpose / prompt:** Review the cumulative work against live main, validate
  reproducibility and publication candidates, and publish only if no substantive
  defect is found.
- **AI contributions:** Audited source/tests/contracts and attribution, corrected
  revision and approval wording in documentation, prepared the scoped commit/push
  and final PR description, and executed validation and artifact/credential checks.
  Git history and the final handoff record the publication outcome.
- **Student direction / decisions:** Julian authorized staging, committing, and
  pushing intended Sprint 04/05 files after passing gates; substantive defects
  require stopping. Opening a PR, merging, and implementing persistence remain
  excluded. No independent human validation is claimed.
- **Review / validation:** Full suite: **436 passed, 11 skipped**, matching the
  latest baseline. Two fresh installed-CLI runs reproduce **8 MISSED / 8 BLOCKED**
  cells; reports match apart from run directory, hashes/controls agree, and all
  11 installed module files match source. CLI help/argument checks and dependency
  checks passed. No substantive in-scope defect was identified.
- **Limitations / dependencies:** Real C/D integration remains blocked by the
  key-generation stub. Historical keys, complete/current checkpoint retrieval,
  physical trust separation, stable inputs, and absent resource bounds retain
  their documented limits; mocked coverage is not measured C/D integration.
