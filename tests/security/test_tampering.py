
import pytest

from src.crypto.kem import generate_keypair
from src.crypto.signatures import generate_signing_keypair
from src.protocol.protected_avp import (
    MAX_ENVELOPE_SIZE,
    ProtectedAVP,
)


@pytest.fixture
def protected_context():
    recipient_kem_pub, recipient_kem_priv = generate_keypair()
    sender_sign_pub, sender_sign_priv = generate_signing_keypair()

    envelope = ProtectedAVP.create(
        sender_id="hss.localdomain",
        recipient_id="mme.localdomain",
        plaintext_av=b"test authentication vector",
        recipient_kem_pub=recipient_kem_pub,
        sender_signing_key=sender_sign_priv,
        key_id="test-key",
        transcript_ref=b"test-transcript",
    )

    return envelope, recipient_kem_priv, sender_sign_pub


def flip_first_byte(value: bytes) -> bytes:
    assert value, "Cannot tamper with an empty field"
    return bytes([value[0] ^ 0x01]) + value[1:]


def test_modified_ciphertext_rejected(protected_context):
    envelope, kem_priv, sign_pub = protected_context
    envelope.encrypted_payload = flip_first_byte(
        envelope.encrypted_payload
    )

    with pytest.raises(ValueError):
        envelope.open(kem_priv, sign_pub)


def test_modified_tag_rejected(protected_context):
    envelope, kem_priv, sign_pub = protected_context
    envelope.auth_tag = flip_first_byte(envelope.auth_tag)

    with pytest.raises(ValueError):
        envelope.open(kem_priv, sign_pub)


def test_modified_nonce_rejected(protected_context):
    envelope, kem_priv, sign_pub = protected_context
    envelope.nonce = flip_first_byte(envelope.nonce)

    with pytest.raises(ValueError):
        envelope.open(kem_priv, sign_pub)


def test_modified_sender_id_rejected(protected_context):
    envelope, kem_priv, sign_pub = protected_context
    envelope.sender_id = "attacker.localdomain"

    with pytest.raises(ValueError):
        envelope.open(kem_priv, sign_pub)


def test_modified_signature_rejected(protected_context):
    envelope, kem_priv, sign_pub = protected_context
    envelope.signature = flip_first_byte(envelope.signature)

    with pytest.raises(ValueError):
        envelope.open(kem_priv, sign_pub)


def test_truncated_envelope_rejected(protected_context):
    envelope, _, _ = protected_context
    serialized = envelope.serialize()

    with pytest.raises(ValueError, match="Truncated|Malformed"):
        ProtectedAVP.deserialize(serialized[:-1])


def test_oversized_envelope_rejected():
    oversized = b"X" * (MAX_ENVELOPE_SIZE + 1)

    with pytest.raises(ValueError, match="maximum size"):
        ProtectedAVP.deserialize(oversized)
