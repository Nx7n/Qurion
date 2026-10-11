import pytest
from src.gateway.relay import DiameterRelay
from src.diameter.avp_codec import DiameterMessage, AVPBuilder, AVP_QURION_PROTECTED_AV, QURION_VENDOR_ID

def test_relay_forwards_messages():
    relay = DiameterRelay()
    msg = DiameterMessage(command_code=318)
    
    forwarded = relay.forward(msg, "hss_to_mme")
    assert forwarded.command_code == 318
    assert len(relay.logs) == 1
    assert relay.logs[0]["direction"] == "hss_to_mme"
    
def test_relay_detects_protected_avp():
    relay = DiameterRelay()
    
    msg_plain = DiameterMessage()
    msg_protected = DiameterMessage(avps=[
        AVPBuilder.build_protected_av_avp(b"encrypted_data")
    ])
    
    assert relay.has_protected_avp(msg_plain) is False
    assert relay.has_protected_avp(msg_protected) is True
    
def test_relay_cannot_access_plaintext():
    relay = DiameterRelay()
    msg_protected = DiameterMessage(avps=[
        AVPBuilder.build_protected_av_avp(b"encrypted_data")
    ])
    
    forwarded = relay.forward(msg_protected, "mme_to_hss")
    assert forwarded.avps[0].data == b"encrypted_data"
    assert "has_protected_avp" in relay.logs[-1]["metadata"]
    assert relay.logs[-1]["metadata"]["has_protected_avp"] is True
