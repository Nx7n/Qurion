import logging
import time

from src.diameter.avp_codec import (
    DiameterMessage,
    DiameterAVP,
    AVP_QURION_PROTECTED_AV,
    QURION_VENDOR_ID,
    AVP_AUTH_INFO,
    AVP_E_UTRAN_VECTOR,
)
from src.protocol.protected_avp import ProtectedAVP

logger = logging.getLogger(__name__)

class MMEAgent:
    """MME-side Qurion agent.

    Opens protected authentication vectors using the canonical
    ProtectedAVP format. No legacy decoding or plaintext fallback
    is performed.
    """

    def __init__(
        self,
        operator_id: str,
        realm: str,
        signing_key: bytes,
        signing_pub: bytes,
        kem_key: bytes,
        kem_pub: bytes,
        trust_store,
        peer_cache,
        anomaly_detector,
        peer_operator_id: str | None = None,
        peer_realm: str | None = None,
        peer_signing_pub: bytes | None = None,
    ):
        self.operator_id = operator_id
        self.realm = realm
        self.signing_key = signing_key
        self.signing_pub = signing_pub
        self.kem_key = kem_key
        self.kem_pub = kem_pub
        self.trust_store = trust_store
        self.peer_cache = peer_cache
        self.anomaly_detector = anomaly_detector

        self.peer_operator_id = peer_operator_id
        self.peer_realm = peer_realm
        self.peer_signing_pub = peer_signing_pub

    @staticmethod
    def _identity(operator_id: str, realm: str) -> str:
        if not operator_id or not realm:
            raise ValueError("Operator identity and realm are required")
        return f"{operator_id}@{realm}"

    def process_outgoing_air(
        self, message: DiameterMessage
    ) -> DiameterMessage:
        return message

    
    def process_incoming_aia(
        self, message: DiameterMessage
    ) -> DiameterMessage:
        total_start = time.perf_counter()

        if message.command_code != 318 or message.application_id != 16777251:
            raise ValueError("Expected an S6a AIA message")

        if message.is_request:
            raise ValueError("Expected an AIA answer, not a request")

        protected_avps = [
            avp for avp in message.avps
            if (
                avp.code == AVP_QURION_PROTECTED_AV
                and avp.vendor_id == QURION_VENDOR_ID
            )
        ]

        if len(protected_avps) != 1:
            raise ValueError("Expected exactly one Qurion protected AVP")

        # Reject plaintext authentication vectors, including grouped containers
        # that could carry unprotected nested vectors.
        plaintext_vector_codes = {
            AVP_AUTH_INFO,
            AVP_E_UTRAN_VECTOR,
            1447,  # RAND
            1415,  # XRES
            1449,  # AUTN
            1450,  # KASME
        }

        if any(
            avp.code in plaintext_vector_codes
            for avp in message.avps
        ):
            raise ValueError("Unexpected plaintext authentication-vector AVP")

        if self.peer_operator_id is None or self.peer_realm is None:
            raise ValueError("Trusted HSS identity is required")

        # Resolve the HSS signing key from the trust store when configured.
        # Never allow an untrusted message to nominate its own verification key.
        if self.trust_store is not None:
            peer_cert = self.trust_store.verify_peer(
                self.peer_operator_id, self.peer_realm, "SIGNING"
            )
            if peer_cert is None:
                raise ValueError(
                    "HSS has no trusted, valid signing certificate"
                )
            if (
                self.peer_signing_pub is not None
                and self.peer_signing_pub != peer_cert.signing_pub
            ):
                raise ValueError(
                    "HSS signing key does not match trusted certificate"
                )
            self.peer_signing_pub = peer_cert.signing_pub

        if self.peer_signing_pub is None:
            raise ValueError("Trusted HSS signing key is required")

        envelope_data = protected_avps[0].data
        envelope = ProtectedAVP.deserialize(envelope_data)

        expected_sender = self._identity(
            self.peer_operator_id, self.peer_realm
        )
        expected_recipient = self._identity(self.operator_id, self.realm)

        if envelope.sender_id != expected_sender:
            raise ValueError("Protected AVP sender identity mismatch")

        if envelope.recipient_id != expected_recipient:
            raise ValueError("Protected AVP recipient identity mismatch")

        # Verify signature, decapsulate the KEM secret, and decrypt the AEAD
        # payload. If any check fails, the exception propagates and the proxy
        # drops the message.
        crypto_start = time.perf_counter()
        plaintext = envelope.open(
            recipient_kem_secret_key=self.kem_key,
            sender_signing_pub=self.peer_signing_pub,
        )
        crypto_open_ms = (time.perf_counter() - crypto_start) * 1000

        # Decode inner AVPs only after successful cryptographic verification.
        decode_start = time.perf_counter()
        decoded_avps = DiameterAVP.decode_all(plaintext)
        avp_decode_ms = (time.perf_counter() - decode_start) * 1000

        if not decoded_avps:
            raise ValueError("Protected payload contains no AVPs")

        # Remove the envelope and restore the decoded AVPs.
        message.avps = [
            avp for avp in message.avps
            if not (
                avp.code == AVP_QURION_PROTECTED_AV
                and avp.vendor_id == QURION_VENDOR_ID
            )
        ]
        message.avps.extend(decoded_avps)

        total_ms = (time.perf_counter() - total_start) * 1000

        logger.info(
            "QURION_METRIC operation=mme_aia_protection "
            "crypto_open_ms=%.3f avp_decode_ms=%.3f total_ms=%.3f "
            "envelope_bytes=%d plaintext_bytes=%d decoded_avp_count=%d "
            "outcome=success",
            crypto_open_ms,
            avp_decode_ms,
            total_ms,
            len(envelope_data),
            len(plaintext),
            len(decoded_avps),
        )

        return message


    def handle_capability_exchange(self, peer_capability_data: bytes):
        # Capability negotiation will be implemented in a later step.
        return None

    def get_session_for_peer(self, peer_id: str, peer_realm: str):
        return None

    def establish_session(
        self,
        peer_id: str,
        peer_realm: str,
        peer_signing_pub: bytes,
        peer_kem_pub: bytes,
    ):
        # Session establishment will be implemented in a later step.
        raise NotImplementedError(
            "Qurion session establishment is not implemented yet"
        )