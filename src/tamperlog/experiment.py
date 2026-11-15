"""Experiment runner — applies attacks to all modes and records outcomes.

Runs the same synthetic events through all four logging modes, applies
each attack to each mode's output, verifies, and collects a results table.

Owner: Julian
"""

from __future__ import annotations


def run_experiment() -> None:
    """Execute the full comparison experiment.

    TODO (Julian):
    1. Generate synthetic events via events.generate_events().
    2. Log them through all four modes (PlaintextLogger, HashChainLogger,
       HMACChainLogger, HMACCheckpointLogger).
    3. For each mode, apply each attack function from attacks.py.
    4. Verify each tampered log with the corresponding verifier.
    5. Collect results into a table: mode × attack → detected (bool).
    6. Print or save the results table.
    """
    raise NotImplementedError("Julian: implement experiment runner")
