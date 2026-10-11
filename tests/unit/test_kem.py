import pytest
from src.crypto.kem import generate_keypair, encapsulate, decapsulate, KEM_ALGORITHM

def test_keypair_generation():
    pub, priv = generate_keypair()
    assert isinstance(pub, bytes)
    assert isinstance(priv, bytes)

def test_encapsulate_decapsulate_consistency():
    pub, priv = generate_keypair()
    ct, ss1 = encapsulate(pub)
    ss2 = decapsulate(priv, ct)
    assert ss1 == ss2

def test_different_keypairs_different_secrets():
    pub1, priv1 = generate_keypair()
    pub2, priv2 = generate_keypair()
    ct1, ss1 = encapsulate(pub1)
    ct2, ss2 = encapsulate(pub2)
    assert ss1 != ss2
    assert pub1 != pub2
    assert priv1 != priv2

def test_invalid_ciphertext_produces_different_secret():
    """ML-KEM uses implicit rejection: invalid ciphertexts produce a
    pseudorandom shared secret that does not match the sender's."""
    pub, priv = generate_keypair()
    ct, ss_sender = encapsulate(pub)
    invalid_ct = ct[:-1] + bytes([(ct[-1] + 1) % 256])
    ss_invalid = decapsulate(priv, invalid_ct)
    # The decapsulation succeeds but produces a different shared secret
    assert ss_invalid != ss_sender

def test_invalid_secret_key_produces_different_secret():
    """Using a modified secret key produces a different shared secret.
    
    We mutate bytes in the polynomial vector area (offset 100-131) rather
    than the rejection seed at the tail, ensuring the lattice decoding
    changes and a different implicit-rejection secret is produced.
    """
    pub, priv = generate_keypair()
    ct, ss_sender = encapsulate(pub)
    # Flip multiple bytes in the polynomial coefficient region
    priv_arr = bytearray(priv)
    for i in range(100, 132):
        priv_arr[i] ^= 0xFF
    invalid_priv = bytes(priv_arr)
    ss_invalid = decapsulate(invalid_priv, ct)
    assert ss_invalid != ss_sender

def test_shared_secret_length():
    """ML-KEM-768 shared secret is 32 bytes."""
    pub, priv = generate_keypair()
    ct, ss = encapsulate(pub)
    assert len(ss) == 32

def test_ciphertext_length():
    """ML-KEM-768 ciphertext is 1088 bytes."""
    pub, priv = generate_keypair()
    ct, ss = encapsulate(pub)
    assert len(ct) == 1088

def test_public_key_length():
    """ML-KEM-768 public key is 1184 bytes."""
    pub, priv = generate_keypair()
    assert len(pub) == 1184
