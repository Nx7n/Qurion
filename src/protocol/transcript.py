import hashlib
import hmac
from .capability import QurionCapability, NegotiatedParams

class TranscriptBuilder:
    def __init__(self) -> None:
        self._entries: list[tuple[str, bytes]] = []

    def add_entry(self, label: str, data: bytes) -> None:
        """Adds labeled entry to transcript."""
        self._entries.append((label, data))

    def add_capability(self, cap: QurionCapability) -> None:
        self.add_entry(f"capability_{cap.operator_id}", cap.serialize())

    def add_negotiated_params(self, params: NegotiatedParams) -> None:
        data = f"{params.protocol_version}:{params.selected_suite.value}:{params.flags.value}:{params.initiator_id}:{params.responder_id}".encode()
        self.add_entry("negotiated_params", data)

    def add_nonce(self, role: str, nonce: bytes) -> None:
        self.add_entry(f"nonce_{role}", nonce)

    def add_key_context(self, key_id: str, kem_pub_hash: bytes) -> None:
        self.add_entry(f"key_context_{key_id}", kem_pub_hash)

    def get_hash(self) -> bytes:
        """SHA-256 of canonical transcript."""
        h = hashlib.sha256()
        for label, data in self._entries:
            lbl = label.encode('utf-8')
            h.update(len(lbl).to_bytes(4, 'big'))
            h.update(lbl)
            h.update(len(data).to_bytes(4, 'big'))
            h.update(data)
        return h.digest()

    def compute_mac(self, mac_key: bytes) -> bytes:
        """HMAC-SHA-256."""
        thash = self.get_hash()
        return hmac.new(mac_key, thash, hashlib.sha256).digest()

    def verify_mac(self, mac_key: bytes, expected_mac: bytes) -> bool:
        computed = self.compute_mac(mac_key)
        return hmac.compare_digest(computed, expected_mac)

    def get_entries(self) -> list[tuple[str, bytes]]:
        """For debugging/logging."""
        return list(self._entries)
