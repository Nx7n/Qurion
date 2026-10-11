import pytest
from src.protocol.key_exchange import KeyExchange, KeyExchangeRole
from src.crypto.signatures import generate_signing_keypair


def make_peers():
    init_pub, init_priv = generate_signing_keypair()
    resp_pub, resp_priv = generate_signing_keypair()
    initiator = KeyExchange(KeyExchangeRole.INITIATOR, "init", "example.net", init_priv, init_pub,
                            expected_peer_operator_id="resp", expected_peer_realm="example.net")
    responder = KeyExchange(KeyExchangeRole.RESPONDER, "resp", "example.net", resp_priv, resp_pub,
                            expected_peer_operator_id="init", expected_peer_realm="example.net")
    return initiator, responder, init_pub, resp_pub


def test_offer_tampering_is_rejected():
    initiator, responder, init_pub, _ = make_peers()
    offer = initiator.create_offer()
    offer["operator_id"] = "attacker"
    with pytest.raises(ValueError, match="Invalid offer signature|Unexpected offer operator identity"):
        responder.process_offer(offer, init_pub)


def test_offer_replay_is_rejected():
    initiator, responder, init_pub, _ = make_peers()
    offer = initiator.create_offer()
    responder.process_offer(offer, init_pub)
    with pytest.raises(ValueError, match="Replayed offer"):
        responder.process_offer(offer, init_pub)


def test_response_identity_and_signature_are_bound():
    initiator, responder, init_pub, resp_pub = make_peers()
    offer = initiator.create_offer()
    response = responder.process_offer(offer, init_pub)
    response["realm"] = "attacker.invalid"
    with pytest.raises(ValueError, match="Unexpected response realm|Invalid signature"):
        initiator.process_response(response, resp_pub)


def test_response_can_only_be_processed_once():
    initiator, responder, init_pub, resp_pub = make_peers()
    offer = initiator.create_offer()
    response = responder.process_offer(offer, init_pub)
    initiator.process_response(response, resp_pub)
    with pytest.raises(ValueError, match="Response already processed"):
        initiator.process_response(response, resp_pub)
