import pytest
from src.protocol.capability import QurionCapability, CapabilityFlags, AlgorithmSuite

def test_capability_serialization():
    cap = QurionCapability(
        supported_suites=[AlgorithmSuite.QURION_V1],
        flags=CapabilityFlags.PROTECTED_AV | CapabilityFlags.KEY_EXCHANGE,
        operator_id="op1",
        realm="example.com",
        cert_fingerprint=b"dummy_fingerprint"
    )
    data = cap.serialize()
    cap2 = QurionCapability.deserialize(data)
    assert cap.protocol_version == cap2.protocol_version
    assert cap.supported_suites == cap2.supported_suites
    assert cap.flags == cap2.flags
    assert cap.operator_id == cap2.operator_id
    assert cap.realm == cap2.realm
    assert cap.cert_fingerprint == cap2.cert_fingerprint

def test_negotiation():
    cap1 = QurionCapability(
        supported_suites=[AlgorithmSuite.QURION_V1],
        flags=CapabilityFlags.PROTECTED_AV | CapabilityFlags.KEY_EXCHANGE,
        operator_id="op1",
        realm="example.com",
        cert_fingerprint=b"dummy_fingerprint1"
    )
    cap2 = QurionCapability(
        supported_suites=[AlgorithmSuite.QURION_V1],
        flags=CapabilityFlags.PROTECTED_AV,
        operator_id="op2",
        realm="example.com",
        cert_fingerprint=b"dummy_fingerprint2"
    )
    
    params = cap1.negotiate(cap2)
    assert params is not None
    assert params.selected_suite == AlgorithmSuite.QURION_V1
    assert params.flags == CapabilityFlags.PROTECTED_AV
