import pytest
import time
from src.diameter.anomaly import AnomalyDetector, AnomalyType, AnomalyAction
from src.protocol.capability import QurionCapability, CapabilityFlags, AlgorithmSuite
from src.diameter.peer_cache import PeerCacheEntry

def test_version_downgrade():
    detector = AnomalyDetector()
    
    current_cap = QurionCapability(
        supported_suites=[AlgorithmSuite.QURION_V1],
        flags=CapabilityFlags.PROTECTED_AV,
        operator_id="op1",
        realm="test",
        cert_fingerprint=b"fp",
        protocol_version=1
    )
    
    cached_entry = PeerCacheEntry(
        operator_id="op1",
        realm="test",
        protocol_versions=[2], # Expected version 2
        supported_suites=[AlgorithmSuite.QURION_V1.value],
        last_negotiation=time.time(),
        key_id=None,
        cert_fingerprint=b"fp",
        created_at=time.time(),
        expires_at=time.time() + 3600
    )
    
    event = detector.check_capability_downgrade("op1", "test", current_cap, cached_entry)
    assert event is not None
    assert event.anomaly_type == AnomalyType.VERSION_DOWNGRADE
    assert event.action_taken == AnomalyAction.REJECT
    assert len(detector.get_events()) == 1

def test_transcript_mac_failure():
    detector = AnomalyDetector()
    event = detector.check_transcript_mac("op1", "test", False, "corr1")
    assert event is not None
    assert event.anomaly_type == AnomalyType.TRANSCRIPT_MAC_FAILURE

def test_cert_change():
    detector = AnomalyDetector()
    cached_entry = PeerCacheEntry(
        operator_id="op1",
        realm="test",
        protocol_versions=[1],
        supported_suites=[],
        last_negotiation=time.time(),
        key_id=None,
        cert_fingerprint=b"old_fp",
        created_at=time.time(),
        expires_at=time.time() + 3600
    )
    
    event = detector.check_cert_change("op1", "test", b"new_fp", cached_entry, "corr1")
    assert event is not None
    assert event.anomaly_type == AnomalyType.CERT_CHANGE
    assert event.action_taken == AnomalyAction.LOG_AND_CONTINUE
