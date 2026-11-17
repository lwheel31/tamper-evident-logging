"""Synthetic event generator.

Produces the SAME event sequence every time for a given seed, so all four
logging modes receive identical input and the comparison is fair.

Owner: Lucas
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

# Fixed start time so timestamps are reproducible (no "now").
BASE_TIME = datetime(2026, 11, 1, 9, 0, 0, tzinfo=timezone.utc)

USERS = ["alice", "bob", "carol", "dave", "admin"]
FILES = ["reports/q3.xlsx", "hr/handbook.pdf", "eng/design.md", "sales/leads.csv"]
SOURCE_IPS = ["10.0.0.12", "10.0.0.23", "10.0.0.31", "10.0.0.44"]

# The incident our attacker will try to hide. Always present at a known spot.
ATTACK_EVENTS: list[tuple[str, dict[str, Any]]] = [
    ("LOGIN_SUCCESS", {"user": "admin", "source_ip": "203.0.113.7"}),
    ("FILE_ACCESS", {"user": "admin", "file": "payroll.db", "action": "read"}),
    ("DATA_EXPORT", {"user": "admin", "file": "payroll.db", "destination": "203.0.113.7"}),
    ("SESSION_END", {"user": "admin"}),
]


def _normal_event(rng: random.Random) -> tuple[str, dict[str, Any]]:
    """Pick one ordinary, harmless-looking event."""
    user = rng.choice(USERS[:-1])  # normal traffic comes from regular users
    kind = rng.choices(
        ["LOGIN_SUCCESS", "LOGIN_FAILURE", "FILE_ACCESS", "SESSION_END"],
        weights=[3, 1, 5, 2],
    )[0]
    if kind in ("LOGIN_SUCCESS", "LOGIN_FAILURE"):
        return kind, {"user": user, "source_ip": rng.choice(SOURCE_IPS)}
    if kind == "FILE_ACCESS":
        return kind, {"user": user, "file": rng.choice(FILES), "action": "read"}
    return kind, {"user": user}


def generate_events(count: int = 50, seed: int = 42) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield (timestamp, event_type, details) for *count* synthetic events.

    - Deterministic: same count + seed -> identical output, every run.
    - The 4-event payroll export incident is placed in the middle of the log,
      so attacks can target it and there are entries before AND after it.
    - Timestamps start at BASE_TIME and move forward 1-30 seconds per event.
    """
    if count < len(ATTACK_EVENTS):
        raise ValueError(f"count must be at least {len(ATTACK_EVENTS)}")

    rng = random.Random(seed)  # private generator: doesn't touch global random
    attack_start = (count - len(ATTACK_EVENTS)) // 2
    t = BASE_TIME

    for i in range(count):
        t += timedelta(seconds=rng.randint(1, 30))
        if attack_start <= i < attack_start + len(ATTACK_EVENTS):
            event_type, details = ATTACK_EVENTS[i - attack_start]
            details = dict(details)  # copy so callers can't edit the template
        else:
            event_type, details = _normal_event(rng)
        yield t.strftime("%Y-%m-%dT%H:%M:%SZ"), event_type, details
