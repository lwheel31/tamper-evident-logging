# Experiments

> Status: planned. No results yet. Do not record a result without real verifier output.

Same synthetic events, run through every combination of mode and attack:

| Attack | A: Plain | B: SHA-256 chain | C: HMAC chain | D: HMAC + checkpoints |
|---|---|---|---|---|
| Modify | TBD | TBD | TBD | TBD |
| Delete | TBD | TBD | TBD | TBD |
| Reorder | TBD | TBD | TBD | TBD |
| Truncate | TBD | TBD | TBD | TBD |

Also planned: key rotation test (old key retained, still verifies; missing old key gives "cannot verify").

For each cell, save the verifier's actual output for the report.
