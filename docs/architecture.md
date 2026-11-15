# Architecture

> Status: draft, awaiting team approval.

## Components
| # | Component | Module | Owner | Trusted? |
|---|---|---|---|---|
| 1 | Event generator | `events.py` | Lucas | yes |
| 2 | Logger (Modes A-D) | `loggers.py` | Lucas (A-C), Lucas + Ashton (D) | yes |
| 3 | Log file (JSONL) | written by `loggers.py` | - | **no, attacker-writable** |
| 4 | Trusted vault: keys + checkpoints | `keyring.py`, `checkpoints.py` | Ashton | yes |
| 5 | Attacker | `attacks.py` | Julian | - |
| 6 | Verifier | `verifier.py` | Julian | yes |

Shared by everyone: `schema.py` (record format) and `serialization.py` (canonical bytes).
`experiment.py` and `cli.py` (Julian) run every attack against every mode.

## Data flow
```
events -> logger -> log file  <- attacks
             |
             +-> vault (HMAC keys, checkpoints)
                          |
verifier reads log file + vault -> "valid" / "tampered at seq N" / "cannot verify"
```

## Key rule
The log file is the only thing the attacker can touch. Keys and checkpoints
live in a separate directory the attacker functions never open.
