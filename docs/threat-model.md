# Threat Model

> Matches the approved proposal.

**Attacker:** has compromised the log storage account.

| Attacker CAN | Attacker CANNOT |
|---|---|
| Read the log file | Read the HMAC keys |
| Modify entries | Modify trusted checkpoints |
| Delete entries | Control the trusted logger |
| Reorder entries | Change the verifier |
| Truncate the log | |
| Rewrite the whole file | |

**Why the CANNOT column holds:** keys and checkpoints are kept on a separate
system (in this prototype, a separate directory) that the storage account cannot access.

**Goal:** hide an unauthorized `payroll.db` export.

**Out of scope:** stolen HMAC key; full admin compromise (logger, verifier, or vault).

**Honest limits:** cannot detect events that were never logged; does not hide log
contents; assumes no attacker action between a log write and its checkpoint.
