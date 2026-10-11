"""ML-DSA-65 wrapper using liboqs-python."""
import oqs

SIG_ALGORITHM = 'ML-DSA-65'

def generate_signing_keypair() -> tuple[bytes, bytes]:
    """Generate a keypair for ML-DSA-65."""
    with oqs.Signature(SIG_ALGORITHM) as sig:
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        return public_key, secret_key

def sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message using the secret key."""
    # Pass secret_key via constructor to avoid liboqs-python ctypes bug.
    sig = oqs.Signature(SIG_ALGORITHM, secret_key=secret_key)
    try:
        signature = sig.sign(message)
        return signature
    finally:
        sig.free()

def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature for a given message and public key."""
    with oqs.Signature(SIG_ALGORITHM) as sig:
        try:
            return sig.verify(message, signature, public_key)
        except Exception:
            return False
