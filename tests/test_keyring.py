"""Tests for key management.

Owner: Ashton
"""

import pytest


@pytest.mark.skip(reason="PENDING — keyring not yet implemented")
def test_generate_and_load_key():
    pass


@pytest.mark.skip(reason="PENDING — keyring not yet implemented")
def test_missing_key_raises():
    """load_key for a nonexistent key must raise KeyError."""
    pass


@pytest.mark.skip(reason="PENDING — keyring not yet implemented")
def test_rotate_key_preserves_old():
    pass
