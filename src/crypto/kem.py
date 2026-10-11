"""ML-KEM-768 wrapper using liboqs-python."""
import oqs

KEM_ALGORITHM = 'ML-KEM-768'

def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a keypair for ML-KEM-768."""
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return public_key, secret_key

def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret for a given public key."""
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate the shared secret using the secret key."""
    # Pass secret_key via constructor to avoid liboqs-python ctypes bug
    # where setting .secret_key as bytes causes free() to crash.
    kem = oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=secret_key)
    try:
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret
    finally:
        kem.free()
