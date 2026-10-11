import pytest
from src.crypto.signatures import generate_signing_keypair, sign, verify, SIG_ALGORITHM

def test_keypair_generation():
    pub, priv = generate_signing_keypair()
    assert isinstance(pub, bytes)
    assert isinstance(priv, bytes)

def test_sign_verify_valid():
    pub, priv = generate_signing_keypair()
    msg = b"test message"
    sig = sign(priv, msg)
    assert verify(pub, msg, sig)

def test_altered_message_rejected():
    pub, priv = generate_signing_keypair()
    msg = b"test message"
    sig = sign(priv, msg)
    assert not verify(pub, b"test messagf", sig)

def test_wrong_key_rejected():
    pub1, priv1 = generate_signing_keypair()
    pub2, priv2 = generate_signing_keypair()
    msg = b"test message"
    sig = sign(priv1, msg)
    assert not verify(pub2, msg, sig)

def test_altered_signature_rejected():
    pub, priv = generate_signing_keypair()
    msg = b"test message"
    sig = sign(priv, msg)
    invalid_sig = sig[:-1] + bytes([(sig[-1] + 1) % 256])
    assert not verify(pub, msg, invalid_sig)
