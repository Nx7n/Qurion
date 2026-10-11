"""In-memory trust store for Qurion operator certificates."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Mapping

from src.certificates.operator_cert import OperatorCertificate


class TrustStore:
    """Store operator certificates after validating them against trusted issuers.

    ``trusted_issuers`` maps issuer IDs to public keys provisioned out of band.
    For backwards compatibility, ``add_trusted_certificate(cert, issuer_pub)``
    remains supported; deployments should configure ``trusted_issuers`` so the
    issuer_id is cryptographically bound to a preconfigured issuer key.
    """

    def __init__(self, trusted_issuers: Optional[Mapping[str, bytes]] = None):
        self._certs: dict[str, OperatorCertificate] = {}
        self._trusted_issuers: dict[str, bytes] = dict(trusted_issuers or {})
        # Retain the verifying key for legacy call sites that pass issuer_pub
        # to add_trusted_certificate().
        self._issuer_keys_by_serial: dict[str, bytes] = {}

    def add_trusted_certificate(self, cert: OperatorCertificate, issuer_pub: Optional[bytes] = None) -> bool:
        if not isinstance(cert, OperatorCertificate):
            return False
        trusted_key = self._trusted_issuers.get(cert.issuer_id)
        if trusted_key is not None:
            if issuer_pub is not None and issuer_pub != trusted_key:
                return False
            issuer_pub = trusted_key
        elif self._trusted_issuers:
            # Once an issuer allowlist is configured, unknown issuer IDs fail closed.
            return False
        if not isinstance(issuer_pub, bytes) or not cert.verify_signature(issuer_pub):
            return False
        if not cert.is_valid():
            return False
        try:
            cert.validate_structure(check_validity=True)
        except (ValueError, TypeError):
            return False

        # Do not allow a serial collision to silently replace another identity.
        serial_owner = self._certs.get(cert.serial)
        if serial_owner is not None and (serial_owner.operator_id, serial_owner.realm) != (cert.operator_id, cert.realm):
            return False

        # Validate everything before mutating the store. Keep one active cert per identity.
        replacement_serials = [
            serial for serial, old in self._certs.items()
            if old.operator_id == cert.operator_id and old.realm == cert.realm and serial != cert.serial
        ]
        for serial in replacement_serials:
            del self._certs[serial]
            self._issuer_keys_by_serial.pop(serial, None)
        self._certs[cert.serial] = cert
        self._issuer_keys_by_serial[cert.serial] = issuer_pub
        return True

    def remove_certificate(self, serial: str) -> bool:
        removed = self._certs.pop(serial, None) is not None
        self._issuer_keys_by_serial.pop(serial, None)
        return removed

    def get_certificate(self, operator_id: str, realm: str) -> Optional[OperatorCertificate]:
        for cert in self._certs.values():
            if cert.operator_id == operator_id and cert.realm == realm:
                return cert
        return None

    def get_by_serial(self, serial: str) -> Optional[OperatorCertificate]:
        return self._certs.get(serial)

    def verify_peer(self, operator_id: str, realm: str, required_usage: str,
                    now: Optional[datetime] = None) -> Optional[OperatorCertificate]:
        cert = self.get_certificate(operator_id, realm)
        if cert is None or not cert.is_valid(now) or not cert.check_realm(realm) or not cert.check_key_usage(required_usage):
            return None
        # Re-check the issuer signature at use time, including when an issuer allowlist is configured.
        issuer_pub = self._trusted_issuers.get(cert.issuer_id) or self._issuer_keys_by_serial.get(cert.serial)
        if issuer_pub is None or not cert.verify_signature(issuer_pub):
            return None
        return cert

    def list_certificates(self) -> list[OperatorCertificate]:
        return list(self._certs.values())

    def cleanup_expired(self, now: Optional[datetime] = None) -> int:
        now = now or datetime.now(timezone.utc)
        expired = [serial for serial, cert in self._certs.items() if cert.is_expired(now)]
        for serial in expired:
            del self._certs[serial]
            self._issuer_keys_by_serial.pop(serial, None)
        return len(expired)
