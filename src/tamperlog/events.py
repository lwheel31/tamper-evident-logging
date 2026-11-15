"""Synthetic event generator.

Produces identical event sequences so all four logging modes receive
the same input and results are directly comparable.

Owner: Lucas
"""

from __future__ import annotations

from typing import Any, Iterator


def generate_events(count: int = 50, seed: int = 42) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (event_type, details) tuples for synthetic log entries.

    The sequence is deterministic for a given *seed* so experiments are
    reproducible.

    TODO (Lucas): Implement a realistic mix of event types — LOGIN,
    LOGOUT, FILE_ACCESS, ADMIN_CMD, ERROR — with plausible payloads.
    Use the random module seeded with *seed* for reproducibility.
    """
    raise NotImplementedError("Lucas: implement synthetic event generation")
