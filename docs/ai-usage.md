# AI Usage Log

This document records all uses of AI tools in the development of this project,
per ITIS 6200 academic integrity requirements.

## 2026-11-15 — Initial Scaffold Generation

**Tool:** Claude Code (Claude Opus 4.6)  
**Operator:** Lucas Wheeler  
**Prompt:** The full "Codex Prompt" stored in this session (see below).  
**Output:** Project folder structure, module stubs with function signatures and
`NotImplementedError` placeholders, test file skeletons, README, pyproject.toml,
and this AI-usage log.  
**What was NOT generated:** No security logic, no hash/HMAC computations, no
attack implementations, no experiment results. All `raise NotImplementedError`
blocks must be filled by students.

### Codex Prompt Summary

The prompt instructed Claude to:
- Inspect the empty repository and propose a scaffold
- Create the folder layout: `docs/`, `src/tamperlog/`, `tests/`, `examples/`
- Create module files with function signatures and TODOs
- Document the threat model and record format
- Assign ownership: Lucas (events, Modes A–C), Ashton (keys, checkpoints, Mode D), Julian (verification, attacks, experiments)
- NOT implement security logic, complete attacks, or produce results

### Student Review Required

- [ ] All team members review schema.py and serialization.py
- [ ] Confirm JSONL record format and data types
- [ ] Confirm canonical serialization approach
- [ ] Review threat model assumptions in README
- [ ] Verify no security logic was pre-implemented

---

*Future AI interactions should be logged below with date, tool, operator,
prompt summary, and what was generated vs. what students wrote independently.*

## 2026-11-16: Lucas's modules (Claude)
- Tool: Claude. Task: implement events.py, serialization.py hardening, and loggers.py Modes A-C plus the Mode D append that calls Ashton's checkpoints module; write matching tests.
- Design choices to review as a team: events yield (timestamp, event_type, details); seq starts at 0; first chained record uses a public GENESIS_TAG; signed data rejects floats and non-string keys; loggers refuse to overwrite an existing log.
- Verified by: running pytest (21 passed, 17 pending on other teammates' modules). Lucas to review and explain each module in his own words before merge.

For Sprints 01–05, ChatGPT assisted with brainstorming and workflow. OpenAI
Codex generated the code, tests, reviews, and documentation listed below under
Julian's direction. Future entries should use the same six fields.

## 2026-11-17: Sprint 01 — Plaintext and SHA-256 verification

- Tool: OpenAI Codex.
- Operator: Julian Roberts.
- Task: Implement and remediate Mode A/B verification.
- Generated: Verifier logic, regression tests, canonical-byte vectors, attack probes, and documentation.
- Design decisions: Julian required the existing result interface and first-failure reporting; directed strict UTC syntax and finite-float compatibility for plaintext after AI review found defects.
- Validation: pytest **213 passed, 14 skipped** after remediation. Tests demonstrate plaintext edits, public rehashing, and valid tail truncation passing; unrecomputed hash changes fail.

## 2026-11-17: Sprint 02 — HMAC and checkpoint verification

- Tool: OpenAI Codex.
- Operator: Julian Roberts.
- Task: Implement Modes C/D and audit substitution, replay, rotation, and unsafe key lookup.
- Generated: HMAC/checkpoint verifier logic, tests with mocked stores, an independent HMAC vector, adversarial probes, and interface requirements.
- Design decisions: Julian required historical-key lookup, safe identifiers, fail-closed dependencies, and per-record checkpoints; approved the AI-proposed trusted `expected_log_id` parameter.
- Validation: pytest **305 passed, 11 skipped**. Mocked-store tests cover rotation, missing keys, substitution, and truncation. Real persistence remained pending; replaying matching stale log/checkpoint prefixes confirmed the trusted-retrieval limitation.

## 2026-11-17: Sprint 03 — Storage-only attacks

- Tool: OpenAI Codex.
- Operator: Julian Roberts.
- Task: Implement modification, deletion, reordering, and truncation attacks.
- Generated: Attack helpers, explicit sequence repair/public SHA-256 reconstruction, tests, adversarial probes, and documentation.
- Design decisions: Julian required reproducible separate copies, no overwrites or key/checkpoint access, and preserved HMAC tags. AI-proposed repair/reconstruction helpers remain separate from basic attacks.
- Validation: pytest **407 passed, 7 skipped**. Tests check contents, ordering, labels, source preservation, invalid requests, and verifier outcomes; C/D store dependencies were mocked.

## 2026-11-17: Sprint 04 — Experiment automation

- Tool: OpenAI Codex.
- Operator: Julian Roberts.
- Task: Orchestrate all 16 mode/attack combinations and implement the experiment CLI.
- Generated: Runner, CLI wiring, orchestration tests, results exports, methodology, and PR proposal.
- Design decisions: Julian required one seeded event stream, independent attack copies, A sequence repair/B public reconstruction, trusted mode/identity selection, and baseline/control checks. Production uses real store interfaces.
- Validation: pytest **436 passed, 7 skipped**. Real 50-event/seed-42 runs measured **8 MISSED A/B cells and 8 BLOCKED C/D cells** with matching repeat evidence. Full C/D paths passed with test doubles; these were not integrated measurements.

## 2026-11-17: Sprint 05 — Integration readiness and reproduction

- Tool: OpenAI Codex.
- Operator: Julian Roberts.
- Task: Audit the workstream, prepare real-store integration gates, validate clean installation, and consolidate disclosures.
- Generated: README/interface/reproduction documentation, five real-store test scenarios, artifact ignore rule, final audit, and revised AI disclosures.
- Design decisions: Julian required skips only for known unimplemented dependencies, unchanged teammate modules, secret/artifact screening, and separate measured/mocked results.
- Validation: Local and isolated non-editable suites both report **436 passed, 11 skipped**; five real-store scenarios are blocked and six teammate placeholders remain. Installed CLI repeats measured **8 MISSED / 8 BLOCKED** with matching hashes. Historical-key persistence, complete/current checkpoints, and physical trust separation still require real integration validation.

## 2026-11-25: Final persistence and integration review

- Tool: OpenAI Codex.
- Operator: Julian Roberts.
- Task: Independently reproduce Ashton's persistence behavior, validate the checkpoint race, and prepare local corrections and submission evidence.
- Generated: Deterministic concurrency/binary-key regressions; narrow key/checkpoint write and cleanup fixes; strict checkpoint JSON checks; real-store identity/empty-store tests; explicit UTF-8 export assertion; documentation corrections and external validation scripts/receipts. Ashton's implementation and all contributor history are preserved.
- Design decisions: Julian required unchanged public interfaces, real persistence/installed CLI validation, no hidden failures, and human approval before committing or publishing. Codex selected unique temporary files and atomic non-replacing hard links; filesystem support and Windows ACL limitations remain explicit.
- Validation: Original Windows suite **465 passed, 6 failed**. Corrected Windows suite **482 passed, 3 failed, no skips** (two missing symlink privileges and the POSIX permission assertion). Isolated Ubuntu installed suite **485 passed, no skips**. Two installed Windows CLI runs measured **7 DETECTED / 9 MISSED**, matching all 16 expected cells with valid baselines/controls and checked evidence hashes. All execution and review described here were AI-assisted; no independent student verification is claimed. Julian subsequently approved committing and publishing these corrections in a new integration PR, with a supersession note on PR #4. Approval to merge either PR has not been given.
