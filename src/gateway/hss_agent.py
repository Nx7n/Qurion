from src.diameter.avp_codec import (
    DiameterMessage,
    AVPBuilder,
    AVP_AUTH_INFO,
    AVP_E_UTRAN_VECTOR,
)
from src.protocol.protected_avp import ProtectedAVP


class HSSAgent:
    """HSS-side Qurion agent.

    Protects authentication-vector AVPs in outgoing S6a AIA messages.
    All protected payloads use the canonical ProtectedAVP format.
    """

    # Existing direct vector AVP codes used by this project.
    VECTOR_CODES = {
        AVP_AUTH_INFO,
        AVP_E_UTRAN_VECTOR,
        1447,  # RAND
        1415,  # XRES
        1449,  # AUTN
        1450,  # KASME
    }

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

    @staticmethod
    def _identity(operator_id: str, realm: str) -> str:
        if not operator_id or not realm:
            raise ValueError("Operator identity and realm are required")
        return f"{operator_id}@{realm}"

    def process_incoming_air(
        self, message: DiameterMessage
    ) -> DiameterMessage:
        # AIR requests do not contain the authentication vectors to protect.
        return message

    def process_outgoing_aia(
        self,
        message: DiameterMessage,
        peer_kem_pub: bytes,
    ) -> DiameterMessage:
        if message.command_code != 318 or message.application_id != 16777251:
            raise ValueError("Expected an S6a AIA message")

        if message.is_request:
            raise ValueError("Cannot protect an AIR request as an AIA response")

        if self.peer_operator_id is None or self.peer_realm is None:
            raise ValueError("Recipient identity is not configured")

        # In a configured deployment, resolve the recipient KEM key from the
        # trusted certificate store. The explicit argument remains supported
        # for legacy tests/development, but must agree with the trusted cert.
        if self.trust_store is not None:
            peer_cert = self.trust_store.verify_peer(
                self.peer_operator_id, self.peer_realm, "KEM"
            )
            if peer_cert is None:
                raise ValueError("Recipient has no trusted, valid KEM certificate")
            if peer_kem_pub is not None and peer_kem_pub != peer_cert.kem_pub:
                raise ValueError("Recipient KEM key does not match trusted certificate")
            peer_kem_pub = peer_cert.kem_pub
        if not isinstance(peer_kem_pub, bytes) or not peer_kem_pub:
            raise ValueError("Recipient KEM public key is required")

        auth_avps = [
            avp for avp in message.avps
            if avp.code in self.VECTOR_CODES
        ]

        if not auth_avps:
            raise ValueError("AIA contains no recognized authentication-vector AVPs")

        # Preserve the original AVP wire encoding inside the protected payload.
        plaintext = b"".join(avp.encode() for avp in auth_avps)

        protected = ProtectedAVP.create(
            sender_id=self._identity(self.operator_id, self.realm),
            recipient_id=self._identity(
                self.peer_operator_id, self.peer_realm
            ),
            plaintext_av=plaintext,
            recipient_kem_pub=peer_kem_pub,
            sender_signing_key=self.signing_key,
        )

        protected_data = protected.serialize()
        protected_avp = AVPBuilder.build_protected_av_avp(protected_data)

        # Replace only the AVPs selected for protection.
        message.avps = [
            avp for avp in message.avps
            if avp.code not in self.VECTOR_CODES
        ]
        message.avps.append(protected_avp)

        return message

    def handle_capability_exchange(self, peer_capability_data: bytes):
        # Capability negotiation will be implemented in a later step.
        return None
