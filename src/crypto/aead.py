"""AES-256-GCM using cryptography library."""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return nonce, ciphertext, tag

def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes | None = None) -> bytes:
    """Decrypt ciphertext using AES-256-GCM."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, associated_data)
