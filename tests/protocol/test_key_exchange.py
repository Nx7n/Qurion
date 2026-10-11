import pytest
import time
from src.protocol.key_exchange import KeyExchange, KeyExchangeRole
from src.crypto.signatures import generate_signing_keypair
from src.crypto.kem import generate_keypair

@pytest.fixture
def keys():
    init_sign_pub, init_sign_priv = generate_signing_keypair()
    resp_sign_pub, resp_sign_priv = generate_signing_keypair()
    resp_kem_pub, resp_kem_priv = generate_keypair()
    return init_sign_pub, init_sign_priv, resp_sign_pub, resp_sign_priv, resp_kem_pub, resp_kem_priv

def test_key_exchange_success(keys):
    init_sign_pub, init_sign_priv, resp_sign_pub, resp_sign_priv, resp_kem_pub, resp_kem_priv = keys
    
    initiator = KeyExchange(
        role=KeyExchangeRole.INITIATOR,
        operator_id="init",
        realm="realm",
        signing_key=init_sign_priv,
        signing_pub=init_sign_pub
    )
    
    responder = KeyExchange(
        role=KeyExchangeRole.RESPONDER,
        operator_id="resp",
        realm="realm",
        signing_key=resp_sign_priv,
        signing_pub=resp_sign_pub,
        kem_key=resp_kem_priv,
        kem_pub=resp_kem_pub
    )
    
    offer = initiator.create_offer()
    response = responder.process_offer(offer, init_sign_pub)
    session_keys = initiator.process_response(response, resp_sign_pub)
    
    resp_keys = responder.get_session_keys()
    assert session_keys.encryption_key == resp_keys.encryption_key
    assert session_keys.mac_key == resp_keys.mac_key
    assert initiator.is_session_valid()
    assert responder.is_session_valid()

def test_key_exchange_expired_offer(keys):
    init_sign_pub, init_sign_priv, resp_sign_pub, resp_sign_priv, resp_kem_pub, resp_kem_priv = keys
    
    initiator = KeyExchange(
        role=KeyExchangeRole.INITIATOR,
        operator_id="init",
        realm="realm",
        signing_key=init_sign_priv,
        signing_pub=init_sign_pub
    )
    
    responder = KeyExchange(
        role=KeyExchangeRole.RESPONDER,
        operator_id="resp",
        realm="realm",
        signing_key=resp_sign_priv,
        signing_pub=resp_sign_pub,
        kem_key=resp_kem_priv,
        kem_pub=resp_kem_pub
    )
    
    offer = initiator.create_offer()
    offer['timestamp'] -= 400
    
    with pytest.raises(ValueError, match="Offer expired"):
        responder.process_offer(offer, init_sign_pub)

def test_key_exchange_wrong_signing_key(keys):
    init_sign_pub, init_sign_priv, resp_sign_pub, resp_sign_priv, resp_kem_pub, resp_kem_priv = keys
    _, wrong_sign_priv = generate_signing_keypair()
    
    initiator = KeyExchange(
        role=KeyExchangeRole.INITIATOR,
        operator_id="init",
        realm="realm",
        signing_key=init_sign_priv,
        signing_pub=init_sign_pub
    )
    
    responder = KeyExchange(
        role=KeyExchangeRole.RESPONDER,
        operator_id="resp",
        realm="realm",
        signing_key=wrong_sign_priv,  # wrong key
        signing_pub=resp_sign_pub,
        kem_key=resp_kem_priv,
        kem_pub=resp_kem_pub
    )
    
    offer = initiator.create_offer()
    response = responder.process_offer(offer, init_sign_pub)
    
    with pytest.raises(ValueError, match="Invalid signature"):
        initiator.process_response(response, resp_sign_pub)

def test_key_exchange_session_expiration(keys):
    init_sign_pub, init_sign_priv, resp_sign_pub, resp_sign_priv, resp_kem_pub, resp_kem_priv = keys
    
    initiator = KeyExchange(
        role=KeyExchangeRole.INITIATOR,
        operator_id="init",
        realm="realm",
        signing_key=init_sign_priv,
        signing_pub=init_sign_pub,
        ttl=-1 # already expired
    )
    
    responder = KeyExchange(
        role=KeyExchangeRole.RESPONDER,
        operator_id="resp",
        realm="realm",
        signing_key=resp_sign_priv,
        signing_pub=resp_sign_pub,
        kem_key=resp_kem_priv,
        kem_pub=resp_kem_pub,
        ttl=-1
    )
    
    offer = initiator.create_offer()
    response = responder.process_offer(offer, init_sign_pub)
    initiator.process_response(response, resp_sign_pub)
    
    assert not initiator.is_session_valid()
