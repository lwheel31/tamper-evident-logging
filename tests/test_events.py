"""Tests for the synthetic event generator. Owner: Lucas"""

import pytest
from tamperlog.events import generate_events


def test_same_seed_same_events():
    assert list(generate_events(50, seed=7)) == list(generate_events(50, seed=7))


def test_different_seed_different_events():
    assert list(generate_events(50, seed=1)) != list(generate_events(50, seed=2))


def test_count_and_shape():
    events = list(generate_events(30))
    assert len(events) == 30
    for ts, event_type, details in events:
        assert ts.endswith("Z") and isinstance(event_type, str) and isinstance(details, dict)


def test_incident_is_present_and_in_the_middle():
    events = list(generate_events(50))
    types = [e[1] for e in events]
    i = types.index("DATA_EXPORT")
    assert events[i][2]["file"] == "payroll.db"
    assert 0 < i < len(events) - 1  # entries before and after it


def test_timestamps_move_forward():
    stamps = [e[0] for e in generate_events(50)]
    assert stamps == sorted(stamps)


def test_too_few_events_rejected():
    with pytest.raises(ValueError):
        list(generate_events(2))
