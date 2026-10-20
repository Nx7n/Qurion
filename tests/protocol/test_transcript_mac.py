import pytest

from src.crypto.signatures import generate_signing_keypair, sign
from src.crypto.kem import generate_keypair
from src.protocol.key_exchange import (
    KeyExchange, KeyExchangeRole, _response_tbs,
)


def make_peers():
    init_pub, init_priv = generate_signing_keypair()
    resp_pub, resp_priv = generate_signing_keypair()
    init = KeyExchange(
        KeyExchangeRole.INITIATOR, "init", "example.net", init_priv, init_pub,
        expected_peer_operator_id="resp", expected_peer_realm="example.net",
    )
    resp = KeyExchange(
        KeyExchangeRole.RESPONDER, "resp", "example.net", resp_priv, resp_pub,
        expected_peer_operator_id="init", expected_peer_realm="example.net",
    )
    return init, resp, init_pub, resp_pub, resp_priv


def test_transcript_mac_is_generated_and_verified():
    init, resp, init_pub, resp_pub, _ = make_peers()
    offer = init.create_offer()
    response = resp.process_offer(offer, init_pub)

    assert len(response["transcript_hash"]) == 32
    assert len(response["transcript_mac"]) == 32
    init_keys = init.process_response(response, resp_pub)
    resp_keys = resp.get_session_keys()
    assert resp_keys is not None
    assert init_keys.transcript_hash == resp_keys.transcript_hash
    assert init_keys.encryption_key == resp_keys.encryption_key
    assert init_keys.mac_key == resp_keys.mac_key


def test_transcript_mac_invalid_even_with_valid_signature_is_rejected():
    init, resp, init_pub, resp_pub, resp_priv = make_peers()
    offer = init.create_offer()
    response = resp.process_offer(offer, init_pub)

    # Re-sign the altered response to prove the MAC check itself rejects it,
    # rather than only relying on the response signature to detect tampering.
    response["transcript_mac"] = bytes([response["transcript_mac"][0] ^ 1]) + response["transcript_mac"][1:]
    response["signature"] = sign(resp_priv, _response_tbs(response, offer))

    with pytest.raises(ValueError, match="Invalid transcript MAC"):
        init.process_response(response, resp_pub)


def test_transcript_hash_mismatch_is_rejected_even_with_valid_signature():
    init, resp, init_pub, resp_pub, resp_priv = make_peers()
    offer = init.create_offer()
    response = resp.process_offer(offer, init_pub)

    response["transcript_hash"] = bytes([response["transcript_hash"][0] ^ 1]) + response["transcript_hash"][1:]
    response["signature"] = sign(resp_priv, _response_tbs(response, offer))

    with pytest.raises(ValueError, match="Transcript hash mismatch"):
        init.process_response(response, resp_pub)
