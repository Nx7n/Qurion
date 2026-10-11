"""HKDF-SHA-256 using cryptography library."""
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_key(shared_secret: bytes, info: bytes, salt: bytes | None = None, length: int = 32) -> bytes:
    """Derive a key from a shared secret using HKDF-SHA-256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)
