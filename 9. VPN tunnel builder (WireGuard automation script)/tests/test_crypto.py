import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.core.crypto import (
    fingerprint,
    generate_preshared_key,
    generate_private_key,
    public_from_private,
)
from app.core.validate import is_wg_key


def test_key_generation_shape():
    priv = generate_private_key()
    assert is_wg_key(priv)
    assert len(priv) == 44
    assert generate_preshared_key() != generate_preshared_key()


def test_public_derivation_matches_rfc7748_vector():
    # RFC 7748 §6.1 X25519 test vector (Alice)
    alice_private = (
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    expected_public = (
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    import base64
    priv_b64 = base64.b64encode(bytes.fromhex(alice_private)).decode()
    pub_hex = bytes.fromhex(expected_public)
    pub_b64 = base64.b64encode(pub_hex).decode()
    assert public_from_private(priv_b64) == pub_b64


def test_public_is_wg_key_and_deterministic():
    priv = generate_private_key()
    pub1 = public_from_private(priv)
    pub2 = public_from_private(priv)
    assert pub1 == pub2
    assert is_wg_key(pub1)


def test_fingerprint_stable_and_short():
    import base64
    import os
    pk = base64.b64encode(os.urandom(32)).decode()
    fp = fingerprint(pk)
    assert len(fp) == 12
    assert fp == fingerprint(pk)


def test_invalid_private_rejected():
    with pytest.raises(ValueError):
        public_from_private("abcdefghijklmnopqrstuvwxyz012345")