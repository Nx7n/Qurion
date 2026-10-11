"""Operator certificates for Qurion's experimental S6a protection.

This is a project-specific signed certificate format, not an X.509 certificate.
Issuer public keys must be provisioned through an out-of-band trust mechanism.
"""
from __future__ import annotations

import base64
import binascii
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional, Any

from src.crypto.signatures import sign, verify


class KeyUsage(str, Enum):
    SIGNING = "SIGNING"
    KEM = "KEM"
    BOTH = "BOTH"


# liboqs algorithm sizes for the project's configured algorithms.
ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_KEM_768_PUBLIC_KEY_BYTES = 1184
MAX_CERTIFICATE_BYTES = 16 * 1024


def _aware_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _b64decode_strict(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a Base64 string")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError(f"Invalid Base64 in {field_name}") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"Non-canonical Base64 in {field_name}")
    return decoded


@dataclass
class OperatorCertificate:
    """Signed operator identity and ML-DSA/ML-KEM public-key binding."""

    operator_id: str
    realm: str
    issuer_id: str
    signing_pub: bytes
    kem_pub: bytes
    key_usage: KeyUsage
    not_before: datetime
    not_after: datetime
    serial: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: int = 1
    signature: Optional[bytes] = None

    def _get_tbs_dict(self) -> dict:
        return {
            "issuer_id": self.issuer_id,
            "kem_pub": base64.b64encode(self.kem_pub).decode("ascii"),
            "key_usage": self.key_usage.value,
            "not_after": _aware_utc(self.not_after, "not_after").isoformat(),
            "not_before": _aware_utc(self.not_before, "not_before").isoformat(),
            "operator_id": self.operator_id,
            "realm": self.realm,
            "serial": self.serial,
            "signing_pub": base64.b64encode(self.signing_pub).decode("ascii"),
            "version": self.version,
        }

    def validate_structure(self, *, check_validity: bool = True, now: Optional[datetime] = None) -> None:
        for name, value in (("operator_id", self.operator_id), ("realm", self.realm), ("issuer_id", self.issuer_id), ("serial", self.serial)):
            if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 512:
                raise ValueError(f"Invalid certificate {name}")
        if type(self.version) is not int or self.version != 1:
            raise ValueError("Unsupported certificate version")
        if not isinstance(self.key_usage, KeyUsage):
            raise ValueError("Invalid certificate key usage")
        if not isinstance(self.signing_pub, bytes) or len(self.signing_pub) != ML_DSA_65_PUBLIC_KEY_BYTES:
            raise ValueError("Invalid ML-DSA-65 public key length")
        if not isinstance(self.kem_pub, bytes) or len(self.kem_pub) != ML_KEM_768_PUBLIC_KEY_BYTES:
            raise ValueError("Invalid ML-KEM-768 public key length")
        before = _aware_utc(self.not_before, "not_before")
        after = _aware_utc(self.not_after, "not_after")
        if before >= after:
            raise ValueError("Certificate not_before must precede not_after")
        if self.signature is not None and (not isinstance(self.signature, bytes) or not self.signature):
            raise ValueError("Invalid certificate signature")
        if check_validity and not self.is_valid(now):
            raise ValueError("Certificate is not currently valid")

    def get_tbs_data(self) -> bytes:
        return json.dumps(self._get_tbs_dict(), separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")

    def serialize(self) -> bytes:
        self.validate_structure(check_validity=False)
        data = self._get_tbs_dict()
        if self.signature is not None:
            data["signature"] = base64.b64encode(self.signature).decode("ascii")
        encoded = json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_CERTIFICATE_BYTES:
            raise ValueError("Certificate exceeds maximum serialized size")
        return encoded

    @classmethod
    def deserialize(cls, data: bytes) -> "OperatorCertificate":
        if not isinstance(data, bytes) or not data or len(data) > MAX_CERTIFICATE_BYTES:
            raise ValueError("Invalid certificate input size")
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Malformed certificate JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("Certificate must be a JSON object")
        required = {"operator_id", "realm", "issuer_id", "signing_pub", "kem_pub", "key_usage", "not_before", "not_after", "serial", "version"}
        if set(parsed) not in (required, required | {"signature"}):
            raise ValueError("Certificate has missing or unexpected fields")
        try:
            cert = cls(
                operator_id=parsed["operator_id"],
                realm=parsed["realm"],
                issuer_id=parsed["issuer_id"],
                signing_pub=_b64decode_strict(parsed["signing_pub"], "signing_pub"),
                kem_pub=_b64decode_strict(parsed["kem_pub"], "kem_pub"),
                key_usage=KeyUsage(parsed["key_usage"]),
                not_before=datetime.fromisoformat(parsed["not_before"]),
                not_after=datetime.fromisoformat(parsed["not_after"]),
                serial=parsed["serial"],
                version=parsed["version"],
                signature=_b64decode_strict(parsed["signature"], "signature") if "signature" in parsed else None,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Invalid certificate fields") from exc
        cert.validate_structure(check_validity=False)
        # Enforce canonical serialized form to avoid multiple encodings of the same certificate.
        if cert.serialize() != data:
            raise ValueError("Certificate serialization is not canonical")
        return cert

    @classmethod
    def issue(cls, operator_id: str, realm: str, signing_pub: bytes, kem_pub: bytes,
              key_usage: KeyUsage, validity_days: int, issuer_id: str,
              issuer_signing_key: bytes) -> "OperatorCertificate":
        """Issue a certificate signed by the configured issuer key."""
        if not isinstance(validity_days, int) or isinstance(validity_days, bool) or validity_days <= 0:
            raise ValueError("validity_days must be a positive integer")
        now = datetime.now(timezone.utc)
        cert = cls(
            operator_id=operator_id, realm=realm, issuer_id=issuer_id,
            signing_pub=signing_pub, kem_pub=kem_pub, key_usage=key_usage,
            not_before=now, not_after=now + timedelta(days=validity_days),
        )
        cert.validate_structure(check_validity=False)
        cert.signature = sign(issuer_signing_key, cert.get_tbs_data())
        return cert

    def verify_signature(self, issuer_signing_pub: bytes) -> bool:
        try:
            self.validate_structure(check_validity=False)
            if not isinstance(issuer_signing_pub, bytes) or not self.signature:
                return False
            return verify(issuer_signing_pub, self.get_tbs_data(), self.signature)
        except (TypeError, ValueError, AttributeError):
            return False

    def is_valid(self, now: Optional[datetime] = None) -> bool:
        try:
            current = _aware_utc(now or datetime.now(timezone.utc), "now")
            before = _aware_utc(self.not_before, "not_before")
            after = _aware_utc(self.not_after, "not_after")
            return before <= current <= after
        except (TypeError, ValueError, AttributeError):
            return False

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        try:
            current = _aware_utc(now or datetime.now(timezone.utc), "now")
            return current > _aware_utc(self.not_after, "not_after")
        except (TypeError, ValueError, AttributeError):
            return True

    def check_realm(self, expected_realm: str) -> bool:
        return isinstance(expected_realm, str) and self.realm == expected_realm

    def check_key_usage(self, required_usage: str) -> bool:
        try:
            required = KeyUsage(required_usage)
        except (ValueError, TypeError):
            return False
        return self.key_usage == KeyUsage.BOTH or self.key_usage == required
