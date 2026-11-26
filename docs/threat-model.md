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

Mode D additionally requires a complete, current, stable checkpoint set and an
independently supplied expected log identity. Matching stale log/checkpoint
prefixes can pass; the format has no separate trusted freshness marker. Directory
separation in this prototype does not establish separate credentials. POSIX
creation modes do not enforce Windows ACLs, and existing directories retain their
permissions. Provision the trusted stores with independent access controls.

The November 25 checkpoint publication race was reproduced between trusted
writers, not through the approved storage-only attacker. The local correction
prevents conflicting concurrent publication; it does not add store snapshot
locking, multiwriter logger support, or a transaction spanning log and checkpoint.
File flushing/publication is not a power-loss durability guarantee for directory
entries; abrupt termination may leave temporary files or incomplete key creation.
