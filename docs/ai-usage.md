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

## 2026-11-17 — Sprint 01: Mode A/B verifier foundation

**Tool:** OpenAI Codex.

**Operator:** Julian Roberts.
**Prompt summary:** Resume after migration to macOS, verify branch/HEAD and the
previous test baseline, review interfaces, threat model, schema, serialization,
loggers, verifier stubs, and existing tests. Implement and thoroughly test only
Mode A/B verification, preserve `VerificationResult`, demonstrate attacks and
security limits, and stop for human review without committing or pushing.

**Starting state verified:** Clean `julian/testing` at
`3f732e0bde75d016e89ccb67143778483d2231bd`; both the tracking reference and a
read-only live remote lookup matched HEAD. Before implementation,
`python3 -m pytest -q` reproduced **21 passed, 17 skipped**.

**AI-generated work:** Mode A/B verifier implementation and docstrings in
`src/tamperlog/verifier.py`, executable checks and attack demonstrations in
`tests/test_verifier.py`, and this usage entry. No independently student-written
security code is claimed for this session. Julian's explanation and approval
remain pending. Modes C/D, shared modules, dependencies, and attack modules were
left unchanged; test-local attacks demonstrate the limitations.

### Decisions for student review

- Require exactly the eight stored fields, including explicit nulls. Dataclass
  defaults must not conceal missing data; extra fields are rejected because the
  shared serializer would not protect them. Reject duplicate keys recursively
  instead of accepting Python's usual last-value-wins interpretation.
- Validate UTF-8, JSON objects, field types, ISO 8601 UTC timestamps, consistent
  `log_id`, and sequences starting at zero with no gaps. Booleans are not valid
  sequence numbers even though Python treats `bool` as an `int` subclass.
  Timestamp validation checks representation/calendar validity, not truth,
  chronological order, or clock accuracy.
- The initial implementation used `canonical_bytes` for both modes' payload
  validation. The adversarial review identified this as an unjustified
  restriction on plaintext: the documented no-float rule applies to signed
  data. The remediation below removes that restriction from Mode A while
  preserving Mode B's canonical domain. Neither logger validates all field
  types/timestamps; invalid schema values may still fail verification even
  when a logger writes them. No shared logger/parser changes were made.
- Mode A requires null `key_id`, `prev_tag`, and `tag`. Its `valid=True` means
  structural validity only; a changed event can pass without any cryptography.
- Mode B requires null `key_id` and 64 lowercase hexadecimal characters for
  each tag, matching the logger's `hexdigest()` representation. Check the first
  `prev_tag` against the shared public 64-zero genesis value, then check each
  link and independently recompute SHA-256 over canonical bytes excluding
  `tag`. Compare with `hmac.compare_digest`; using this comparison does not
  make SHA-256 keyed or authenticated.
- Stop at the first bad physical line, including malformed or blank lines.
  `first_bad_seq` is its expected zero-based position, since the stored sequence
  may be absent or dishonest. `total_records` counts examined lines including
  the failing line, not the unread suffix. `error` gives a one-based line number
  and reason. `log_id` comes from the first structurally valid record, or is
  empty when unavailable. Result fields and public function signatures remain
  unchanged.
- Empty files return valid with zero records, empty `log_id`, and no error.
  This is vacuous success of the available checks, not proof of an honest empty
  history. Missing/unreadable files raise file-access errors rather than passing
  as empty files. Decode individual binary lines so a later invalid UTF-8 line
  cannot mask an earlier failure through text-reader buffering.

### Evidence and limits

Tests exercise valid logger output, a hash built from independently hand-written
canonical bytes, malformed JSON/UTF-8, missing/extra/duplicate fields, invalid
types/timestamps/tags, nested payloads, sequence damage, genesis/link failures,
and digest mismatches. They demonstrate a hidden payroll export through a
plaintext edit, detection of unrehashed edits, successful malicious rehashing,
deletion plus renumbering/rehashing, replacement of the entire log identity,
and undetected tail truncation (including removal of every record). Canonical
verification tolerates object key order, Unicode storage escaping, CRLF line
endings, and an absent final newline.

Neither mode establishes authenticity or completeness. SHA-256 is public, so an
attacker can rebuild all affected tags; there is no trusted expected identity,
length, or final tag in these APIs. A surviving prefix is consistent without
proving that its tail was retained. Neither mode detects events never recorded.
Verification operates on captured, stable log artifacts. Capture is a procedure
outside these functions; they do not create a snapshot or lock the source.
The attacker retains every capability in the approved threat model before
capture. Results describe the captured input, not a concurrently writable file
or its later contents. Concurrent mutation has no snapshot-consistency guarantee.

There are no explicit limits on line size, payload depth, memory, or CPU use.
A hostile artifact can exhaust memory or processing resources before any result
is returned, even though records are read one line at a time. `RecursionError`
is reported when raised; catching it is not a denial-of-service defense and
does not impose a portable nesting limit. Resource controls remain outside this
sprint, and a valid result is not an availability guarantee.

**Initial validation (before remediation):** `python3 -m pytest -q` completed with **172 passed, 14 skipped**
(0.48 s), compared with **21 passed, 17 skipped** before changes: 151 passing
Mode A/B cases replace three skipped stubs. The remaining skips belong to
unimplemented C/D verification and other pending project modules. Early test
runs exposed a nesting-depth assumption; the test now places deeply nested
data inside a complete record so either parsing or canonical validation can
reject it regardless of the JSON decoder's recursion behavior.

**Review status:** Ready for Julian's review; no commit or push performed.

## 2026-11-17 — Sprint 01 adversarial review and remediation

**Tool:** OpenAI Codex. **Operator:** Julian Roberts.

**Prompt summary:** First conduct a read-only adversarial review of the entire
working-tree diff, logger compatibility, false results, coverage, threat model,
and complexity. Then remediate both medium findings, document the two low
findings, improve the specified tests, run the full suite, perform a final
review, and stop for human approval without committing or pushing.

**Review evidence:** Read-only probes reproduced both medium findings on
Python 3.13.3: malformed timestamp suffixes such as `Z:00` and `Z.5` passed
after global replacement, and an untouched plaintext logger record containing
`1.5` failed canonical validation. The review repeated the initial full-suite
result of 172 passed, 14 skipped. Passing tests had missed both issues.

**AI-generated remediation:** Changes remain restricted to `verifier.py`,
`test_verifier.py`, and this usage log. No independently student-written code
is claimed. Public signatures and result fields, Modes C/D, shared modules,
dependencies, ownership boundaries, and the approved attacker capabilities
remain unchanged.

- Validate timestamp syntax with a full match before parsing calendar values.
  The supported UTC profile is `YYYY-MM-DDTHH:MM:SS[.fraction]` followed by
  uppercase `Z` or exactly `+00:00`, with ASCII digits. Only a terminal `Z` is
  converted for Python parsing. Compact/week dates, missing seconds, other
  offsets (including unknown-offset `-00:00`), and malformed suffixes are
  rejected. This is an explicit supported profile, not a claim to accept every
  ISO 8601 representation. Calendar validation follows Python `datetime`, so
  leap-second representations are not supported. Timestamp truth/order is
  still not established.
- Call `canonical_bytes` only in Mode B. Mode A accepts finite floats in JSON
  details, including nested payloads, matching the plaintext logger. A JSON
  `parse_float` hook rejects overflow to infinity at any depth without a second
  payload traversal. Nonstandard `NaN`/`Infinity` constants remain rejected.
  Mode B still rejects all floats through shared canonical validation.
- Add malformed-suffix and accepted-format regressions, a test of untouched
  plaintext logger output with finite floats, explicit Mode B float rejection,
  and nested positive/negative exponent-overflow tests. Independently alter
  timestamp, event type, and details in middle/final records while preserving
  original tags: Mode A passes; Mode B reports the altered position.
- Extend the hand-written canonical-byte vector with nested arrays/objects,
  booleans, null, integers, and escaped Unicode. Neither the logger nor the
  shared serializer builds its expected digest input. The deep-recursion test
  now targets Mode B's recursive canonical validation; Mode A does not promise
  to reject a particular nesting depth if its JSON parser can handle it.
- Document stable artifact capture and resource-exhaustion limits in both the
  verifier module and this log. No locking, snapshot, or resource-limit
  implementation was added.

**Student review pending:** Explain the UTC profile and calendar checks, why
finite floats are permitted only in plaintext, why parse hooks reject nested
non-finite numbers, and why valid SHA-256 chains still cannot prove authenticity
or completeness. The stable-artifact procedure does not remove any storage
attack capability from the approved threat model.

**Final validation:** `python3 -m pytest -q` reports **213 passed, 14 skipped**
on Python 3.13.3, compared with **172 passed, 14 skipped** before remediation
and the original baseline of **21 passed, 17 skipped**. The verifier file now
has 192 passing cases and three pending C/D cases. `git diff --check` passes.

**Final adversarial review:** Re-read the final implementation and changed
tests/documentation; independently probe malformed suffixes, invalid calendar
values, valid leap-day input, untouched plaintext floats, and nested non-finite
constants/overflow. No remaining high/medium findings were identified within
the documented UTC profile and stable-artifact procedure. Resource exhaustion
and absence of snapshot consistency remain documented low-severity limitations,
not implemented defenses. Runtime behavior has not been tested across every
supported Python version. Expected security limits remain: plaintext edits,
publicly rehashed SHA-256 rewrites, and valid truncation can pass; neither mode
proves authenticity or completeness. No commit or push performed; human
explanation and approval remain pending.
