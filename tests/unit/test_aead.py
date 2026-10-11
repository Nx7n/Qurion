import os
import pytest
from src.crypto.aead import encrypt, decrypt
from cryptography.exceptions import InvalidTag

def test_encrypt_decrypt_roundtrip():
    key = os.urandom(32)
    pt = b"secret data"
    nonce, ct, tag = encrypt(key, pt)
    assert decrypt(key, nonce, ct, tag) == pt

def test_associated_data_binding():
    key = os.urandom(32)
    pt = b"secret data"
    ad = b"associated data"
    nonce, ct, tag = encrypt(key, pt, ad)
    assert decrypt(key, nonce, ct, tag, ad) == pt

def test_tampered_ciphertext_rejected():
    key = os.urandom(32)
    pt = b"secret data"
    nonce, ct, tag = encrypt(key, pt)
    invalid_ct = ct[:-1] + bytes([(ct[-1] + 1) % 256])
    with pytest.raises(InvalidTag):
        decrypt(key, nonce, invalid_ct, tag)

def test_tampered_tag_rejected():
    key = os.urandom(32)
    pt = b"secret data"
    nonce, ct, tag = encrypt(key, pt)
    invalid_tag = tag[:-1] + bytes([(tag[-1] + 1) % 256])
    with pytest.raises(InvalidTag):
        decrypt(key, nonce, ct, invalid_tag)

def test_tampered_nonce_rejected():
    key = os.urandom(32)
    pt = b"secret data"
    nonce, ct, tag = encrypt(key, pt)
    invalid_nonce = nonce[:-1] + bytes([(nonce[-1] + 1) % 256])
    with pytest.raises(InvalidTag):
        decrypt(key, invalid_nonce, ct, tag)

def test_tampered_associated_data_rejected():
    key = os.urandom(32)
    pt = b"secret data"
    ad = b"associated data"
    nonce, ct, tag = encrypt(key, pt, ad)
    invalid_ad = b"associated datb"
    with pytest.raises(InvalidTag):
        decrypt(key, nonce, ct, tag, invalid_ad)

def test_fresh_nonce_each_encryption():
    key = os.urandom(32)
    pt = b"secret data"
    nonce1, ct1, tag1 = encrypt(key, pt)
    nonce2, ct2, tag2 = encrypt(key, pt)
    assert nonce1 != nonce2

def test_invalid_key_length_rejected():
    key = os.urandom(16)
    pt = b"secret data"
    with pytest.raises(ValueError):
        encrypt(key, pt)
