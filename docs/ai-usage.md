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
