"""Authenticated, transcript-bound ML-KEM session establishment for Qurion.

The offer/response dictionaries are an internal API; callers must transport them
with integrity protection. Peer signing keys must come from TrustStore, not from
an unauthenticated message field.
"""
from __future__ import annotations

import hashlib
import os
import struct
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.crypto.kem import generate_keypair, encapsulate, decapsulate
from src.crypto.signatures import sign, verify
from src.crypto.kdf import derive_key


MAX_CLOCK_SKEW_SECONDS = 300
MAX_ID_BYTES = 512


class KeyExchangeRole(Enum):
    INITIATOR = "initiator"
    RESPONDER = "responder"


@dataclass
class SessionKeys:
    encryption_key: bytes
    mac_key: bytes
    key_id: str
    created_at: float
    expires_at: float


def _lp(data: bytes) -> bytes:
    if not isinstance(data, bytes) or len(data) > 0xFFFFFFFF:
        raise ValueError("Invalid key-exchange field")
    return struct.pack(">I", len(data)) + data


def _text(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_ID_BYTES:
        raise ValueError(f"Invalid {field}")
    return value.encode("utf-8")


def _bytes(value: Any, field: str, *, exact_len: int | None = None) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise ValueError(f"Invalid {field}")
    if exact_len is not None and len(value) != exact_len:
        raise ValueError(f"Invalid {field} length")
    return value


def _timestamp(value: Any, label: str, now: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Invalid {label} timestamp")
    value = float(value)
    current = time.time() if now is None else now
    if not (current - MAX_CLOCK_SKEW_SECONDS <= value <= current + MAX_CLOCK_SKEW_SECONDS):
        raise ValueError(f"{label} expired or timestamp outside accepted window")
    return value


def _offer_tbs(offer: dict) -> bytes:
    return b"QURION-KEY-OFFER-v1" + b"".join((
        _lp(_text(offer.get("operator_id"), "offer operator_id")),
        _lp(_text(offer.get("realm"), "offer realm")),
        _lp(_bytes(offer.get("kem_pub"), "offer KEM public key", exact_len=1184)),
        _lp(_bytes(offer.get("nonce"), "offer nonce", exact_len=32)),
        struct.pack(">d", _timestamp(offer.get("timestamp"), "Offer")),
    ))


def _response_tbs(response: dict, offer: dict) -> bytes:
    return b"QURION-KEY-RESPONSE-v1" + b"".join((
        _lp(_text(offer.get("operator_id"), "offer operator_id")),
        _lp(_text(offer.get("realm"), "offer realm")),
        _lp(_bytes(offer.get("kem_pub"), "offer KEM public key", exact_len=1184)),
        _lp(_bytes(offer.get("nonce"), "offer nonce", exact_len=32)),
        _lp(_text(response.get("operator_id"), "response operator_id")),
        _lp(_text(response.get("realm"), "response realm")),
        _lp(_bytes(response.get("kem_ciphertext"), "KEM ciphertext", exact_len=1088)),
        _lp(_bytes(response.get("nonce"), "response nonce", exact_len=32)),
        struct.pack(">d", _timestamp(response.get("timestamp"), "Response")),
        _lp(_bytes(offer.get("signature"), "offer signature")),
    ))


class KeyExchange:
    def __init__(self, role: KeyExchangeRole, operator_id: str, realm: str,
                 signing_key: bytes, signing_pub: bytes,
                 kem_key: bytes | None = None, kem_pub: bytes | None = None,
                 ttl: int = 3600, *, expected_peer_operator_id: str | None = None,
                 expected_peer_realm: str | None = None):
        if not isinstance(role, KeyExchangeRole):
            raise ValueError("Invalid key-exchange role")
        _text(operator_id, "operator_id")
        _text(realm, "realm")
        _bytes(signing_key, "signing private key")
        _bytes(signing_pub, "signing public key")
        if expected_peer_operator_id is not None:
            _text(expected_peer_operator_id, "expected peer operator_id")
        if expected_peer_realm is not None:
            _text(expected_peer_realm, "expected peer realm")
        if not isinstance(ttl, (int, float)) or isinstance(ttl, bool):
            raise ValueError("ttl must be numeric")

        self.role = role
        self.operator_id = operator_id
        self.realm = realm
        self.signing_key = signing_key
        self.signing_pub = signing_pub
        self.kem_key = kem_key
        self.kem_pub = kem_pub
        self.ttl = ttl
        self.expected_peer_operator_id = expected_peer_operator_id
        self.expected_peer_realm = expected_peer_realm
        self.session_keys: SessionKeys | None = None
        self._nonce = os.urandom(32)
        self._processed_offer_nonces: dict[bytes, float] = {}
        self._offer: dict | None = None
        self._response_processed = False

        if self.role == KeyExchangeRole.INITIATOR and not self.kem_pub:
            self.kem_pub, self.kem_key = generate_keypair()
        if self.role == KeyExchangeRole.INITIATOR:
            _bytes(self.kem_pub, "initiator KEM public key", exact_len=1184)
            _bytes(self.kem_key, "initiator KEM secret key")

    def create_offer(self) -> dict:
        if self.role != KeyExchangeRole.INITIATOR:
            raise ValueError("Only initiator can create offer")
        if self._offer is not None:
            raise ValueError("Offer already created for this exchange instance")
        offer = {
            "kem_pub": self.kem_pub,
            "operator_id": self.operator_id,
            "realm": self.realm,
            "nonce": self._nonce,
            "timestamp": time.time(),
        }
        offer["signature"] = sign(self.signing_key, _offer_tbs(offer))
        self._offer = offer
        return dict(offer)

    def process_offer(self, offer: dict, peer_signing_pub: bytes) -> dict:
        if self.role != KeyExchangeRole.RESPONDER:
            raise ValueError("Only responder can process offer")
        if not isinstance(offer, dict):
            raise ValueError("Malformed offer")
        try:
            timestamp = _timestamp(offer.get("timestamp"), "Offer")
            nonce = _bytes(offer.get("nonce"), "offer nonce", exact_len=32)
            _text(offer.get("operator_id"), "offer operator_id")
            _text(offer.get("realm"), "offer realm")
            _bytes(offer.get("kem_pub"), "offer KEM public key", exact_len=1184)
            signature = _bytes(offer.get("signature"), "offer signature")
            tbs = _offer_tbs(offer)
        except (TypeError, KeyError) as exc:
            raise ValueError("Malformed offer") from exc
        if self.expected_peer_operator_id is not None and offer["operator_id"] != self.expected_peer_operator_id:
            raise ValueError("Unexpected offer operator identity")
        if self.expected_peer_realm is not None and offer["realm"] != self.expected_peer_realm:
            raise ValueError("Unexpected offer realm")
        if not verify(peer_signing_pub, tbs, signature):
            raise ValueError("Invalid offer signature")
        # Keep only nonces that could still pass the timestamp window. This
        # bounds memory without evicting live replay markers arbitrarily.
        cutoff = time.time() - MAX_CLOCK_SKEW_SECONDS
        self._processed_offer_nonces = {
            seen_nonce: seen_at
            for seen_nonce, seen_at in self._processed_offer_nonces.items()
            if seen_at >= cutoff
        }
        if nonce in self._processed_offer_nonces:
            raise ValueError("Replayed offer")

        kem_ciphertext, shared_secret = encapsulate(offer["kem_pub"])
        responder_nonce = os.urandom(32)
        response = {
            "kem_ciphertext": kem_ciphertext,
            "operator_id": self.operator_id,
            "realm": self.realm,
            "nonce": responder_nonce,
            "timestamp": time.time(),
        }
        response["signature"] = sign(self.signing_key, _response_tbs(response, offer))
        salt = hashlib.sha256(b"QURION-KEX-SALT-v1" + offer["nonce"] + responder_nonce).digest()
        self._derive_keys(shared_secret, salt)
        self._processed_offer_nonces[nonce] = timestamp
        return response

    def process_response(self, response: dict, peer_signing_pub: bytes) -> SessionKeys:
        if self.role != KeyExchangeRole.INITIATOR:
            raise ValueError("Only initiator can process response")
        if self._offer is None:
            raise ValueError("No outstanding offer")
        if self._response_processed:
            raise ValueError("Response already processed")
        if not isinstance(response, dict):
            raise ValueError("Malformed response")
        try:
            _timestamp(response.get("timestamp"), "Response")
            _text(response.get("operator_id"), "response operator_id")
            _text(response.get("realm"), "response realm")
            _bytes(response.get("kem_ciphertext"), "KEM ciphertext", exact_len=1088)
            _bytes(response.get("nonce"), "response nonce", exact_len=32)
            signature = _bytes(response.get("signature"), "response signature")
            tbs = _response_tbs(response, self._offer)
        except (TypeError, KeyError) as exc:
            raise ValueError("Malformed response") from exc
        if self.expected_peer_operator_id is not None and response["operator_id"] != self.expected_peer_operator_id:
            raise ValueError("Unexpected response operator identity")
        if self.expected_peer_realm is not None and response["realm"] != self.expected_peer_realm:
            raise ValueError("Unexpected response realm")
        if not verify(peer_signing_pub, tbs, signature):
            raise ValueError("Invalid signature")
        shared_secret = decapsulate(self.kem_key, response["kem_ciphertext"])
        if not isinstance(shared_secret, bytes) or not shared_secret:
            raise ValueError("Decapsulation failed")
        salt = hashlib.sha256(b"QURION-KEX-SALT-v1" + self._offer["nonce"] + response["nonce"]).digest()
        self._derive_keys(shared_secret, salt)
        self._response_processed = True
        return self.session_keys

    def _derive_keys(self, shared_secret: bytes, salt: bytes) -> None:
        enc_key = derive_key(shared_secret, b"qurion-session-encrypt-v1", salt, 32)
        mac_key = derive_key(shared_secret, b"qurion-session-mac-v1", salt, 32)
        now = time.time()
        key_id = hashlib.sha256(b"QURION-KEY-ID-v1" + enc_key + mac_key).hexdigest()[:16]
        self.session_keys = SessionKeys(enc_key, mac_key, key_id, now, now + self.ttl)

    def get_session_keys(self) -> SessionKeys | None:
        return self.session_keys

    def is_session_valid(self) -> bool:
        return bool(self.session_keys and time.time() < self.session_keys.expires_at)
