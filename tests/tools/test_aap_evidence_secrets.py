"""Regressions for safe access-state evidence and hidden credential material."""

import pytest

from tests.bdd.adapters.agent_access_and_permissions import _assert_secret_free


def test_access_state_is_not_a_plaintext_access_token():
    _assert_secret_free({"access": {"status": "revoked", "revision": 3, "revokedAt": None}})


@pytest.mark.parametrize("payload", [
    {"access_token": "opaque-value"},
    {"nested": {"clientSecret": "opaque-value"}},
    {"unrelatedLabel": "aap1_" + "x" * 43},
    {"nested": ["Bearer opaque-value"]},
])
def test_credential_material_is_rejected_regardless_of_container(payload):
    with pytest.raises(AssertionError):
        _assert_secret_free(payload)
