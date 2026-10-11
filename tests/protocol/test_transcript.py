import pytest
from src.protocol.transcript import TranscriptBuilder
from src.protocol.capability import QurionCapability, CapabilityFlags, AlgorithmSuite

def test_transcript_mac():
    builder = TranscriptBuilder()
    builder.add_entry("test", b"data")
    
    mac_key = b"supersecretkey"
    mac = builder.compute_mac(mac_key)
    
    assert builder.verify_mac(mac_key, mac)
    assert not builder.verify_mac(mac_key, b"wrongmac")
    
def test_transcript_determinism():
    b1 = TranscriptBuilder()
    b1.add_entry("a", b"1")
    b1.add_entry("b", b"2")
    
    b2 = TranscriptBuilder()
    b2.add_entry("a", b"1")
    b2.add_entry("b", b"2")
    
    assert b1.get_hash() == b2.get_hash()

def test_transcript_tamper():
    b1 = TranscriptBuilder()
    b1.add_entry("a", b"1")
    
    b2 = TranscriptBuilder()
    b2.add_entry("a", b"2")
    
    assert b1.get_hash() != b2.get_hash()
