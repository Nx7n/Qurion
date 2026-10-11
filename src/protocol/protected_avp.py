import struct
import uuid
from dataclasses import dataclass

from src.crypto.kem import encapsulate, decapsulate
from src.crypto.signatures import sign, verify
from src.crypto.aead import encrypt, decrypt
from src.crypto.kdf import derive_key


MAGIC = b"QURION\x01"
VERSION = 1
ALGORITHM_SUITE = "QURION-ML-KEM-768-ML-DSA-65-AES256GCM"
KDF_CONTEXT = b"qurion-avp-aead-v1"
AAD_DOMAIN = b"QURION-PROTECTED-AV-AAD-V1\x00"
SIGN_DOMAIN = b"QURION-PROTECTED-AV-SIGN-V1\x00"
MAX_ENVELOPE_SIZE = 65535
NONCE_SIZE = 12
TAG_SIZE = 16


@dataclass
class ProtectedAVP:
    version: int = VERSION
    algorithm_suite: str = ALGORITHM_SUITE
    sender_id: str = ""
    recipient_id: str = ""
    transaction_id: str = ""
    key_id: str = ""
    kem_ciphertext: bytes = b""
    nonce: bytes = b""
    encrypted_payload: bytes = b""
    auth_tag: bytes = b""
    signature: bytes = b""
    transcript_ref: bytes = b""

    @staticmethod
    def _encode_bytes(value: bytes) -> bytes:
        if not isinstance(value, bytes):
            raise TypeError("Binary fields must be bytes")
        if len(value) > 65535:
            raise ValueError("Binary field exceeds 65535 bytes")
        return struct.pack(">H", len(value)) + value

    @staticmethod
    def _encode_str(value: str) -> bytes:
        if not isinstance(value, str):
            raise TypeError("Text fields must be strings")

        encoded = value.encode("utf-8")
        if len(encoded) > 65535:
            raise ValueError("Text field exceeds 65535 bytes")

        return struct.pack(">H", len(encoded)) + encoded

    def _metadata_encoding(self) -> bytes:
        """Canonical, unambiguous encoding of envelope metadata."""
        return (
            struct.pack(">H", self.version)
            + self._encode_str(self.algorithm_suite)
            + self._encode_str(self.sender_id)
            + self._encode_str(self.recipient_id)
            + self._encode_str(self.transaction_id)
            + self._encode_str(self.key_id)
        )

    def _build_associated_data(self) -> bytes:
        return AAD_DOMAIN + self._metadata_encoding()

    def _signable_content(self) -> bytes:
        """Canonical signed content; the signature itself is excluded."""
        return (
            SIGN_DOMAIN
            + self._metadata_encoding()
            + self._encode_bytes(self.kem_ciphertext)
            + self._encode_bytes(self.nonce)
            + self._encode_bytes(self.encrypted_payload)
            + self._encode_bytes(self.auth_tag)
            + self._encode_bytes(self.transcript_ref)
        )

    def validate(self) -> bool:
        if self.version != VERSION:
            raise ValueError("Unsupported version")

        if self.algorithm_suite != ALGORITHM_SUITE:
            raise ValueError("Unsupported algorithm suite")

        for name in (
            "sender_id",
            "recipient_id",
            "transaction_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must not be empty")

        if not isinstance(self.key_id, str):
            raise ValueError("key_id must be a string")

        for name in (
            "kem_ciphertext",
            "nonce",
            "encrypted_payload",
            "auth_tag",
            "signature",
            "transcript_ref",
        ):
            if not isinstance(getattr(self, name), bytes):
                raise ValueError(f"{name} must be bytes")

        if not self.kem_ciphertext:
            raise ValueError("Missing KEM ciphertext")

        if len(self.nonce) != NONCE_SIZE:
            raise ValueError(f"Nonce must be exactly {NONCE_SIZE} bytes")

        if len(self.auth_tag) != TAG_SIZE:
            raise ValueError(f"Authentication tag must be exactly {TAG_SIZE} bytes")

        if not self.encrypted_payload:
            raise ValueError("Encrypted payload must not be empty")

        if not self.signature:
            raise ValueError("Missing digital signature")

        # Also enforce the encoding's per-field size limits.
        self._metadata_encoding()
        self._encode_bytes(self.kem_ciphertext)
        self._encode_bytes(self.nonce)
        self._encode_bytes(self.encrypted_payload)
        self._encode_bytes(self.auth_tag)
        self._encode_bytes(self.transcript_ref)
        self._encode_bytes(self.signature)

        return True

    def serialize(self) -> bytes:
        self.validate()

        body = (
            struct.pack(">H", self.version)
            + self._encode_str(self.algorithm_suite)
            + self._encode_str(self.sender_id)
            + self._encode_str(self.recipient_id)
            + self._encode_str(self.transaction_id)
            + self._encode_str(self.key_id)
            + self._encode_bytes(self.kem_ciphertext)
            + self._encode_bytes(self.nonce)
            + self._encode_bytes(self.encrypted_payload)
            + self._encode_bytes(self.auth_tag)
            + self._encode_bytes(self.transcript_ref)
            + self._encode_bytes(self.signature)
        )

        envelope = MAGIC + body
        if len(envelope) > MAX_ENVELOPE_SIZE:
            raise ValueError("Envelope exceeds maximum size")

        return envelope

    @classmethod
    def deserialize(cls, data: bytes) -> "ProtectedAVP":
        if not isinstance(data, bytes):
            raise TypeError("Envelope must be bytes")

        if len(data) > MAX_ENVELOPE_SIZE:
            raise ValueError("Envelope exceeds maximum size")

        if not data.startswith(MAGIC):
            raise ValueError("Invalid Qurion envelope magic/version")

        offset = len(MAGIC)

        def read_exact(size: int) -> bytes:
            nonlocal offset
            if size < 0 or offset + size > len(data):
                raise ValueError("Truncated Qurion envelope")
            result = data[offset:offset + size]
            offset += size
            return result

        def read_length_prefixed() -> bytes:
            length = struct.unpack(">H", read_exact(2))[0]
            return read_exact(length)

        def read_str() -> str:
            try:
                return read_length_prefixed().decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ValueError("Invalid UTF-8 in envelope") from exc

        try:
            version = struct.unpack(">H", read_exact(2))[0]
            algorithm_suite = read_str()
            sender_id = read_str()
            recipient_id = read_str()
            transaction_id = read_str()
            key_id = read_str()
            kem_ciphertext = read_length_prefixed()
            nonce = read_length_prefixed()
            encrypted_payload = read_length_prefixed()
            auth_tag = read_length_prefixed()
            transcript_ref = read_length_prefixed()
            signature = read_length_prefixed()
        except struct.error as exc:
            raise ValueError("Malformed Qurion envelope") from exc

        # Reject appended garbage and ambiguous alternate encodings.
        if offset != len(data):
            raise ValueError("Trailing data after Qurion envelope")

        result = cls(
            version=version,
            algorithm_suite=algorithm_suite,
            sender_id=sender_id,
            recipient_id=recipient_id,
            transaction_id=transaction_id,
            key_id=key_id,
            kem_ciphertext=kem_ciphertext,
            nonce=nonce,
            encrypted_payload=encrypted_payload,
            auth_tag=auth_tag,
            transcript_ref=transcript_ref,
            signature=signature,
        )
        result.validate()
        return result

    @classmethod
    def create(
        cls,
        sender_id: str,
        recipient_id: str,
        plaintext_av: bytes,
        recipient_kem_pub: bytes,
        sender_signing_key: bytes,
        key_id: str = "",
        transcript_ref: bytes = b"",
    ) -> "ProtectedAVP":
        if not plaintext_av:
            raise ValueError("Cannot protect an empty payload")

        if not sender_id or not recipient_id:
            raise ValueError("Sender and recipient identities are required")

        if not isinstance(transcript_ref, bytes):
            raise TypeError("transcript_ref must be bytes")

        kem_ciphertext, shared_secret = encapsulate(recipient_kem_pub)

        avp = cls(
            sender_id=sender_id,
            recipient_id=recipient_id,
            transaction_id=str(uuid.uuid4()),
            key_id=key_id,
            kem_ciphertext=kem_ciphertext,
            transcript_ref=transcript_ref,
        )

        aes_key = derive_key(shared_secret, KDF_CONTEXT, b"", 32)
        nonce, encrypted_payload, auth_tag = encrypt(
            aes_key,
            plaintext_av,
            avp._build_associated_data(),
        )

        avp.nonce = nonce
        avp.encrypted_payload = encrypted_payload
        avp.auth_tag = auth_tag

        avp.signature = sign(
            sender_signing_key,
            avp._signable_content(),
        )

        avp.validate()
        return avp

    def open(
        self,
        recipient_kem_secret_key: bytes,
        sender_signing_pub: bytes,
    ) -> bytes:
        self.validate()

        try:
            signature_valid = verify(
                sender_signing_pub,
                self._signable_content(),
                self.signature,
            )
        except Exception as exc:
            raise ValueError("Signature verification failed") from exc

        if not signature_valid:
            raise ValueError("Invalid signature")

        shared_secret = decapsulate(
            recipient_kem_secret_key,
            self.kem_ciphertext,
        )
        if not shared_secret:
            raise ValueError("KEM decapsulation failed")

        aes_key = derive_key(shared_secret, KDF_CONTEXT, b"", 32)

        try:
            return decrypt(
                aes_key,
                self.nonce,
                self.encrypted_payload,
                self.auth_tag,
                self._build_associated_data(),
            )
        except Exception as exc:
            raise ValueError("Decryption failed") from exc