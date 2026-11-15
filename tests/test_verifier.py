"""Tests for verification.

Owner: Julian
"""

import pytest


@pytest.mark.skip(reason="PENDING — verifier not yet implemented")
def test_verify_plaintext():
    pass


@pytest.mark.skip(reason="PENDING — verifier not yet implemented")
def test_verify_hash_chain_valid():
    pass


@pytest.mark.skip(reason="PENDING — verifier not yet implemented")
def test_verify_hash_chain_tampered():
    pass


@pytest.mark.skip(reason="PENDING — verifier not yet implemented")
def test_verify_hmac_chain_valid():
    pass


@pytest.mark.skip(reason="PENDING — verifier not yet implemented")
def test_verify_hmac_missing_key_is_not_valid():
    """A missing historical key must NOT produce valid=True."""
    pass


@pytest.mark.skip(reason="PENDING — verifier not yet implemented")
def test_verify_hmac_checkpoint():
    pass
