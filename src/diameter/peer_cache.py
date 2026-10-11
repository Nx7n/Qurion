import time
from dataclasses import dataclass

@dataclass
class PeerCacheEntry:
    operator_id: str
    realm: str
    protocol_versions: list[int]
    supported_suites: list[str]
    last_negotiation: float
    key_id: str | None
    cert_fingerprint: bytes
    created_at: float
    expires_at: float
    anomaly_count: int = 0

class PeerCapabilityCache:
    def __init__(self, default_ttl: float = 3600.0) -> None:
        self.default_ttl = default_ttl
        self._cache: dict[tuple[str, str], PeerCacheEntry] = {}
        self._history: dict[tuple[str, str], PeerCacheEntry] = {}

    def update(self, entry: PeerCacheEntry) -> None:
        key = (entry.operator_id, entry.realm)
        if key in self._cache:
            self._history[key] = self._cache[key]
        self._cache[key] = entry

    def get(self, operator_id: str, realm: str) -> PeerCacheEntry | None:
        key = (operator_id, realm)
        entry = self._cache.get(key)
        if entry:
            if time.time() > entry.expires_at:
                del self._cache[key]
                return None
            return entry
        return None

    def remove(self, operator_id: str, realm: str) -> bool:
        key = (operator_id, realm)
        if key in self._cache:
            del self._cache[key]
            return True
        return False

    def is_known_peer(self, operator_id: str, realm: str) -> bool:
        return self.get(operator_id, realm) is not None

    def get_previous_capabilities(self, operator_id: str, realm: str) -> PeerCacheEntry | None:
        return self._history.get((operator_id, realm))

    def cleanup_expired(self) -> int:
        now = time.time()
        expired_keys = [k for k, v in self._cache.items() if now > v.expires_at]
        for k in expired_keys:
            del self._cache[k]
        return len(expired_keys)

    def invalidate_all(self) -> None:
        self._cache.clear()
        self._history.clear()

    def size(self) -> int:
        return len(self._cache)
