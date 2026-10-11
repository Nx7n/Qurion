import os
from src.crypto.kdf import derive_key

def test_derive_key_deterministic():
    ss = os.urandom(32)
    info = b"info"
    salt = os.urandom(16)
    k1 = derive_key(ss, info, salt)
    k2 = derive_key(ss, info, salt)
    assert k1 == k2

def test_different_info_different_keys():
    ss = os.urandom(32)
    salt = os.urandom(16)
    k1 = derive_key(ss, b"info1", salt)
    k2 = derive_key(ss, b"info2", salt)
    assert k1 != k2

def test_different_salt_different_keys():
    ss = os.urandom(32)
    info = b"info"
    k1 = derive_key(ss, info, os.urandom(16))
    k2 = derive_key(ss, info, os.urandom(16))
    assert k1 != k2

def test_custom_length():
    ss = os.urandom(32)
    info = b"info"
    k = derive_key(ss, info, None, 64)
    assert len(k) == 64
