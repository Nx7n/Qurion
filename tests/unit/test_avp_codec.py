import pytest
from src.diameter.avp_codec import (
    DiameterAVP, AVPBuilder, DiameterMessage,
    AVP_RAND, AVP_XRES, AVP_AUTN, AVP_KASME,
    QURION_VENDOR_ID, AVP_QURION_PROTECTED_AV
)

def test_avp_encode_decode_roundtrip():
    avp = DiameterAVP(code=123, flags=0x40, vendor_id=None, data=b"testdata")
    encoded = avp.encode()
    decoded, consumed = DiameterAVP.decode(encoded)
    assert decoded.code == 123
    assert decoded.flags == 0x40
    assert decoded.vendor_id is None
    assert decoded.data == b"testdata"
    assert consumed == len(encoded)

def test_vendor_specific_avp():
    avp = DiameterAVP(code=AVP_QURION_PROTECTED_AV, flags=0x80, vendor_id=QURION_VENDOR_ID, data=b"secret")
    encoded = avp.encode()
    decoded, consumed = DiameterAVP.decode(encoded)
    assert decoded.code == AVP_QURION_PROTECTED_AV
    assert decoded.flags == 0x80
    assert decoded.vendor_id == QURION_VENDOR_ID
    assert decoded.data == b"secret"

def test_diameter_message_roundtrip():
    avp1 = DiameterAVP(code=1, flags=0x40, vendor_id=None, data=b"a")
    avp2 = DiameterAVP(code=2, flags=0x80, vendor_id=99, data=b"b")
    
    msg = DiameterMessage(
        command_code=318,
        application_id=16777251,
        hop_by_hop_id=10,
        end_to_end_id=20,
        is_request=True,
        avps=[avp1, avp2]
    )
    
    encoded = msg.encode()
    decoded = DiameterMessage.decode(encoded)
    
    assert decoded.command_code == 318
    assert decoded.application_id == 16777251
    assert decoded.hop_by_hop_id == 10
    assert decoded.end_to_end_id == 20
    assert decoded.is_request is True
    assert len(decoded.avps) == 2
    assert decoded.avps[0].code == 1
    assert decoded.avps[1].vendor_id == 99

def test_s6a_auth_vector():
    rand, xres, autn, kasme = b"1"*16, b"2"*8, b"3"*16, b"4"*32
    avps = AVPBuilder.build_s6a_auth_vector(rand, xres, autn, kasme)
    assert len(avps) == 4
    
    parsed = AVPBuilder.parse_s6a_auth_vector(avps)
    assert parsed["RAND"] == rand
    assert parsed["XRES"] == xres
    assert parsed["AUTN"] == autn
    assert parsed["KASME"] == kasme

def test_padding_correctness():
    # 1 byte data requires 3 bytes padding
    avp = DiameterAVP(code=1, flags=0, vendor_id=None, data=b"x")
    encoded = avp.encode()
    assert len(encoded) == 12 # 8 header + 1 data + 3 pad
    
    # 4 bytes data requires 0 bytes padding
    avp2 = DiameterAVP(code=1, flags=0, vendor_id=None, data=b"xxxx")
    encoded2 = avp2.encode()
    assert len(encoded2) == 12 # 8 header + 4 data + 0 pad
    
def test_invalid_data():
    with pytest.raises(ValueError):
        DiameterAVP.decode(b"short")


def test_xres_uses_standard_s6a_avp_code():
    assert AVP_XRES == 1415


def test_rejects_truncated_avp_padding():
    # AVP declares a 9-byte length, so three padding bytes must be present.
    avp = DiameterAVP(code=1, flags=0, vendor_id=None, data=b"x").encode()
    with pytest.raises(ValueError, match="Truncated AVP or padding"):
        DiameterAVP.decode(avp[:-1])


def test_rejects_nonzero_avp_padding():
    avp = bytearray(DiameterAVP(code=1, flags=0, vendor_id=None, data=b"x").encode())
    avp[-1] = 1
    with pytest.raises(ValueError, match="padding must be zero"):
        DiameterAVP.decode(bytes(avp))


def test_rejects_diameter_message_with_trailing_bytes():
    msg = DiameterMessage(command_code=318, application_id=16777251).encode()
    with pytest.raises(ValueError, match="buffer length"):
        DiameterMessage.decode(msg + b"\x00")


def test_rejects_invalid_diameter_message_length():
    msg = bytearray(DiameterMessage(command_code=318, application_id=16777251).encode())
    msg[1:4] = (19).to_bytes(3, "big")
    with pytest.raises(ValueError, match="Invalid Diameter message length"):
        DiameterMessage.decode(bytes(msg))
