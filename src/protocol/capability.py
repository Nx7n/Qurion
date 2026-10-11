"""Strict, signed Qurion capability advertisement and negotiation primitives."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum, Flag, auto
from typing import Iterable


class AlgorithmSuite(Enum):
    QURION_V1 = "QURION-ML-KEM-768-ML-DSA-65-AES256GCM"


class CapabilityFlags(Flag):
    PROTECTED_AV = auto()
    KEY_EXCHANGE = auto()
    TRANSCRIPT_MAC = auto()
    OPERATOR_AUTH = auto()


KNOWN_FLAG_MASK = (
    CapabilityFlags.PROTECTED_AV
    | CapabilityFlags.KEY_EXCHANGE
    | CapabilityFlags.TRANSCRIPT_MAC
    | CapabilityFlags.OPERATOR_AUTH
).value
MAX_CAPABILITY_SIZE = 16 * 1024
MAX_TEXT_SIZE = 1024
MAX_FINGERPRINT_SIZE = 128
MAX_SIGNATURE_SIZE = 8192


class CapabilityState(Enum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    INVALID = "invalid"
    DOWNGRADE = "downgrade"


class NegotiationAction(Enum):
    PROTECT = "protect"
    FALLBACK = "fallback"
    PASSTHROUGH = "passthrough"
    REJECT = "reject"


@dataclass(frozen=True)
class NegotiatedParams:
    protocol_version: int
    selected_suite: AlgorithmSuite
    flags: CapabilityFlags
    initiator_id: str
    responder_id: str


@dataclass
class QurionCapability:
    supported_suites: list[AlgorithmSuite | str]
    flags: CapabilityFlags
    operator_id: str
    realm: str
    cert_fingerprint: bytes
    protocol_version: int = 1
    signature: bytes = b""

    def _encode_unsigned(self) -> bytes:
        if not 0 <= self.protocol_version <= 255:
            raise ValueError("Unsupported protocol version encoding")
        if self.flags.value & ~KNOWN_FLAG_MASK:
            raise ValueError("Unknown capability flag bits")
        if not self.operator_id or not self.realm:
            raise ValueError("Capability identity must not be empty")
        op = self.operator_id.encode("utf-8")
        realm = self.realm.encode("utf-8")
        if len(op) > MAX_TEXT_SIZE or len(realm) > MAX_TEXT_SIZE:
            raise ValueError("Capability identity field too large")
        if len(self.cert_fingerprint) > MAX_FINGERPRINT_SIZE:
            raise ValueError("Certificate fingerprint too large")
        if len(set(self.supported_suites)) != len(self.supported_suites):
            raise ValueError("Duplicate algorithm suites")
        suite_data = b"|".join((s.value if isinstance(s, AlgorithmSuite) else s).encode("ascii") for s in self.supported_suites)
        if len(suite_data) > MAX_TEXT_SIZE:
            raise ValueError("Algorithm suite list too large")

        out = struct.pack("!BIH", self.protocol_version, self.flags.value, len(self.cert_fingerprint))
        out += self.cert_fingerprint
        out += struct.pack("!H", len(op)) + op
        out += struct.pack("!H", len(realm)) + realm
        out += struct.pack("!H", len(suite_data)) + suite_data
        return out

    def signing_bytes(self) -> bytes:
        return b"QURION-CAPABILITY-SIGN-V1\x00" + self._encode_unsigned()

    def serialize(self) -> bytes:
        if not isinstance(self.signature, bytes) or len(self.signature) > MAX_SIGNATURE_SIZE:
            raise ValueError("Invalid capability signature")
        data = self._encode_unsigned() + struct.pack("!H", len(self.signature)) + self.signature
        if len(data) > MAX_CAPABILITY_SIZE:
            raise ValueError("Capability payload too large")
        return data

    def sign(self, signing_private_key: bytes) -> None:
        from src.crypto.signatures import sign
        self.signature = sign(signing_private_key, self.signing_bytes())

    def verify_signature(self, signing_public_key: bytes) -> bool:
        if not self.signature:
            return False
        from src.crypto.signatures import verify
        try:
            return bool(verify(signing_public_key, self.signing_bytes(), self.signature))
        except Exception:
            return False

    @classmethod
    def deserialize(cls, data: bytes) -> "QurionCapability":
        if not isinstance(data, bytes) or not data or len(data) > MAX_CAPABILITY_SIZE:
            raise ValueError("Invalid capability payload size")
        offset = 0

        def read(size: int) -> bytes:
            nonlocal offset
            if size < 0 or offset + size > len(data):
                raise ValueError("Truncated capability payload")
            result = data[offset:offset + size]
            offset += size
            return result

        def read_u16() -> int:
            return struct.unpack("!H", read(2))[0]

        version, flags_value, fp_len = struct.unpack("!BIH", read(7))
        if flags_value & ~KNOWN_FLAG_MASK:
            raise ValueError("Unknown capability flag bits")
        fingerprint = read(fp_len)
        operator_id = read(read_u16()).decode("utf-8", errors="strict")
        realm = read(read_u16()).decode("utf-8", errors="strict")
        suite_data = read(read_u16()).decode("ascii", errors="strict")
        signature = read(read_u16())
        if offset != len(data):
            raise ValueError("Trailing data in capability payload")
        if len(signature) > MAX_SIGNATURE_SIZE:
            raise ValueError("Capability signature too large")
        suites: list[AlgorithmSuite] = []
        if suite_data:
            for name in suite_data.split("|"):
                try:
                    suite: AlgorithmSuite | str = AlgorithmSuite(name)
                except ValueError:
                    # Preserve unknown, signed suite names so a valid peer with
                    # no common suite can fall back instead of being malformed.
                    if not name or len(name) > 256:
                        raise ValueError("Invalid advertised algorithm suite")
                    suite = name
                if suite in suites:
                    raise ValueError("Duplicate algorithm suite")
                suites.append(suite)
        result = cls(
            supported_suites=suites,
            flags=CapabilityFlags(flags_value),
            operator_id=operator_id,
            realm=realm,
            cert_fingerprint=fingerprint,
            protocol_version=version,
            signature=signature,
        )
        # Reuse all field and canonical encoding validation.
        result._encode_unsigned()
        return result

    def is_compatible(self, other: "QurionCapability") -> bool:
        return (
            self.protocol_version == other.protocol_version
            and bool(set(self.supported_suites) & set(other.supported_suites))
            and bool(self.flags & CapabilityFlags.PROTECTED_AV)
            and bool(other.flags & CapabilityFlags.PROTECTED_AV)
        )

    def negotiate(self, other: "QurionCapability") -> NegotiatedParams | None:
        if not self.is_compatible(other):
            return None
        common = set(self.supported_suites) & set(other.supported_suites)
        selected = AlgorithmSuite.QURION_V1 if AlgorithmSuite.QURION_V1 in common else sorted(common, key=lambda s: s.value if isinstance(s, AlgorithmSuite) else s)[0]
        return NegotiatedParams(
            protocol_version=self.protocol_version,
            selected_suite=selected,
            flags=self.flags & other.flags,
            initiator_id=self.operator_id,
            responder_id=other.operator_id,
        )


def decide_action(local_enabled: bool, peer_state: CapabilityState) -> NegotiationAction:
    """Map the three-state peer result to an explicit data-plane policy."""
    if peer_state in (CapabilityState.INVALID, CapabilityState.DOWNGRADE):
        return NegotiationAction.REJECT
    if local_enabled and peer_state is CapabilityState.SUPPORTED:
        return NegotiationAction.PROTECT
    if local_enabled or peer_state is CapabilityState.SUPPORTED:
        return NegotiationAction.FALLBACK
    return NegotiationAction.PASSTHROUGH
