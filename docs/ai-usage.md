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
