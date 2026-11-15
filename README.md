# Tamper-Evident Logging — ITIS 6200 Final Project

Comparing four mechanisms for detecting tampering in security audit logs.

> **Status: SCAFFOLD ONLY** — function signatures and TODOs are in place;
> no security logic has been implemented yet.

## Team

| Member | Responsibility |
|--------|---------------|
| Lucas  | Event generator, Modes A–C (plaintext, hash chain, HMAC chain) |
| Ashton | Key management, rotation, checkpoints, Mode D support |
| Julian | Verification, attacks, experiments, integration |
| ALL    | Schema, serialization, CLI, reviews |

## Logging Modes

| Mode | Mechanism | Key Required | Detects Modification | Detects Rewrite |
|------|-----------|-------------|---------------------|-----------------|
| A    | Plaintext | No  | No  | No  |
| B    | SHA-256 hash chain | No  | Yes | **No** (attacker can recompute) |
| C    | HMAC-SHA256 chain | Yes | Yes | Yes |
| D    | HMAC-SHA256 + checkpoints | Yes | Yes | Yes (with segment detection) |

## Threat Model

**Attacker CAN:**
- Read, modify, delete, reorder, truncate, and rewrite stored log files

**Attacker CANNOT:**
- Access secret HMAC keys
- Modify trusted checkpoints
- Control the trusted logger process
- Change the trusted verifier code

## Record Format (JSONL)

Each line is a JSON object — **awaiting team approval**:

```json
{
  "log_id": "run-001",
  "seq": 0,
  "timestamp": "2026-11-15T12:00:00Z",
  "event_type": "LOGIN",
  "details": {"user": "alice", "ip": "10.0.0.1"},
  "key_id": null,
  "prev_tag": null,
  "tag": null
}
```

The `tag` is computed over all other fields via deterministic JSON serialization
(sorted keys, no whitespace, ensure_ascii=True). The tag is **never** part of
its own hash/HMAC input.

## Installation

```bash
# Clone and install in development mode
git clone <repo-url>
cd tamper-evident-logging
pip install -e ".[dev]"
```

Requires Python 3.10+. Only standard-library modules are used at runtime;
`pytest` is the sole dev dependency.

## Proposed Commands

```bash
tamperlog generate     # Create synthetic events, log in all four modes
tamperlog verify FILE  # Verify integrity of a log file
tamperlog attack FILE  # Apply a named attack
tamperlog experiment   # Run the full mode × attack comparison
tamperlog keys         # Manage HMAC keys
```

> None of these commands work yet — they all raise `NotImplementedError`.

## Running Tests

```bash
pytest -v
```

Currently: 3 schema/serialization tests pass; all other tests are marked
`skip` (PENDING implementation).

## File Structure

```
tamper-evident-logging/
├── docs/
│   └── ai-usage.md          # AI tool usage log
├── examples/
│   └── .gitkeep
├── src/
│   └── tamperlog/
│       ├── __init__.py
│       ├── schema.py         # LogRecord dataclass        (ALL)
│       ├── serialization.py  # Deterministic JSON + JSONL  (ALL)
│       ├── events.py         # Synthetic event generator   (Lucas)
│       ├── loggers.py        # Modes A–D                   (Lucas + Ashton)
│       ├── keyring.py        # HMAC key management         (Ashton)
│       ├── checkpoints.py    # Trusted checkpoint store    (Ashton)
│       ├── verifier.py       # Log verification            (Julian)
│       ├── attacks.py        # Simulated tampering         (Julian)
│       ├── experiment.py     # Full comparison runner      (Julian)
│       └── cli.py            # CLI entry point             (ALL)
├── tests/
│   ├── test_schema.py
│   ├── test_loggers.py
│   ├── test_verifier.py
│   └── test_keyring.py
├── .gitignore
├── pyproject.toml
└── README.md
```

## AI Usage

All AI tool usage is documented in [docs/ai-usage.md](docs/ai-usage.md).
The initial scaffold was generated with Claude Code; no security logic,
attack implementations, or experiment results were AI-generated.
