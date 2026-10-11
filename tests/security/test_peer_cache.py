import pytest
import time
from src.diameter.peer_cache import PeerCapabilityCache, PeerCacheEntry

def test_peer_cache():
    cache = PeerCapabilityCache()
    
    entry = PeerCacheEntry(
        operator_id="op1",
        realm="example.com",
        protocol_versions=[1],
        supported_suites=["QURION-ML-KEM-768-ML-DSA-65-AES256GCM"],
        last_negotiation=time.time(),
        key_id="key1",
        cert_fingerprint=b"fp",
        created_at=time.time(),
        expires_at=time.time() + 3600
    )
    
    cache.update(entry)
    assert cache.is_known_peer("op1", "example.com")
    
    retrieved = cache.get("op1", "example.com")
    assert retrieved is not None
    assert retrieved.operator_id == "op1"
    
    cache.remove("op1", "example.com")
    assert not cache.is_known_peer("op1", "example.com")

def test_cache_expiration():
    cache = PeerCapabilityCache()
    entry = PeerCacheEntry(
        operator_id="op1",
        realm="example.com",
        protocol_versions=[1],
        supported_suites=[],
        last_negotiation=time.time(),
        key_id=None,
        cert_fingerprint=b"",
        created_at=time.time(),
        expires_at=time.time() - 100 # Already expired
    )
    cache.update(entry)
    
    assert cache.get("op1", "example.com") is None
    
    cache.update(entry)
    removed = cache.cleanup_expired()
    assert removed == 1
