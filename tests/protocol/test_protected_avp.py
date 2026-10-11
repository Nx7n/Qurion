import pytest
from src.protocol.protected_avp import ProtectedAVP
from src.crypto.kem import generate_keypair
from src.crypto.signatures import generate_signing_keypair

@pytest.fixture
def keys():
    kem_pub, kem_priv = generate_keypair()
    sign_pub, sign_priv = generate_signing_keypair()
    return kem_pub, kem_priv, sign_pub, sign_priv

def test_protected_avp_roundtrip(keys):
    kem_pub, kem_priv, sign_pub, sign_priv = keys
    av = b"secret authentication vector data"
    
    avp = ProtectedAVP.create(
        sender_id="mme.epc.mnc001.mcc001.3gppnetwork.org",
        recipient_id="hss.epc.mnc001.mcc001.3gppnetwork.org",
        plaintext_av=av,
        recipient_kem_pub=kem_pub,
        sender_signing_key=sign_priv
    )
    
    serialized = avp.serialize()
    deserialized = ProtectedAVP.deserialize(serialized)
    
    decrypted = deserialized.open(kem_priv, sign_pub)
    assert decrypted == av

def test_protected_avp_tampered_ciphertext(keys):
    kem_pub, kem_priv, sign_pub, sign_priv = keys
    av = b"secret authentication vector data"
    
    avp = ProtectedAVP.create("sender", "receiver", av, kem_pub, sign_priv)
    serialized = avp.serialize()
    
    deserialized = ProtectedAVP.deserialize(serialized)
    deserialized.encrypted_payload = b"0" + deserialized.encrypted_payload[1:]
    
    with pytest.raises(ValueError):
        deserialized.open(kem_priv, sign_pub)

def test_protected_avp_tampered_signature(keys):
    kem_pub, kem_priv, sign_pub, sign_priv = keys
    avp = ProtectedAVP.create("sender", "receiver", b"av", kem_pub, sign_priv)
    avp.signature = b"0" + avp.signature[1:]
    
    with pytest.raises(ValueError, match="Invalid signature"):
        avp.open(kem_priv, sign_pub)

def test_protected_avp_wrong_recipient_key(keys):
    kem_pub, kem_priv, sign_pub, sign_priv = keys
    _, wrong_kem_priv = generate_keypair()
    
    avp = ProtectedAVP.create("sender", "receiver", b"av", kem_pub, sign_priv)
    
    with pytest.raises(ValueError, match="Decryption failed"):
        avp.open(wrong_kem_priv, sign_pub)

def test_protected_avp_invalid_envelope(keys):
    kem_pub, kem_priv, sign_pub, sign_priv = keys
    avp = ProtectedAVP.create("sender", "receiver", b"av", kem_pub, sign_priv)
    avp.version = 99
    with pytest.raises(ValueError, match="Unsupported version"):
        avp.serialize()
