import pytest

from src.gateway.mme_agent import MMEAgent
from src.gateway.hss_agent import HSSAgent
from src.crypto.kem import generate_keypair as kem_generate_keypair
from src.crypto.signatures import generate_signing_keypair
from src.diameter.avp_codec import (
    DiameterMessage, DiameterAVP, AVP_AUTH_INFO, AVP_E_UTRAN_VECTOR,
    AVP_RAND, AVP_XRES, AVP_AUTN, AVP_KASME,
    AVP_QURION_PROTECTED_AV, QURION_VENDOR_ID,
)


def result_code(value=2001):
    return DiameterAVP(268, 0x40, None, value.to_bytes(4, "big"))


def make_aia():
    children = [
        DiameterAVP(AVP_RAND, 0x40, None, b"R" * 16),
        DiameterAVP(AVP_XRES, 0x40, None, b"X" * 8),
        DiameterAVP(AVP_AUTN, 0x40, None, b"A" * 16),
        DiameterAVP(AVP_KASME, 0x40, None, b"K" * 32),
    ]
    vector = DiameterAVP(
        AVP_E_UTRAN_VECTOR, 0x40, None,
        b"".join(avp.encode() for avp in children),
    )
    auth_info = DiameterAVP(AVP_AUTH_INFO, 0x40, None, vector.encode())
    return DiameterMessage(
        command_code=318,
        application_id=16777251,
        hop_by_hop_id=10,
        end_to_end_id=20,
        is_request=False,
        is_proxiable=True,
        avps=[result_code(), auth_info],
    )


@pytest.fixture
def keypairs():
    hss_kem_pub, hss_kem_priv = kem_generate_keypair()
    mme_kem_pub, mme_kem_priv = kem_generate_keypair()
    hss_sign_pub, hss_sign_priv = generate_signing_keypair()
    mme_sign_pub, mme_sign_priv = generate_signing_keypair()
    return locals()


@pytest.fixture
def agents(keypairs):
    hss = HSSAgent(
        "hss.localdomain", "localdomain",
        keypairs["hss_sign_priv"], keypairs["hss_sign_pub"],
        keypairs["hss_kem_priv"], keypairs["hss_kem_pub"],
        None, None, None,
        peer_operator_id="mme.localdomain", peer_realm="localdomain",
    )
    mme = MMEAgent(
        "mme.localdomain", "localdomain",
        keypairs["mme_sign_priv"], keypairs["mme_sign_pub"],
        keypairs["mme_kem_priv"], keypairs["mme_kem_pub"],
        None, None, None,
        peer_operator_id="hss.localdomain", peer_realm="localdomain",
        peer_signing_pub=keypairs["hss_sign_pub"],
    )
    return hss, mme


def test_protected_aia_round_trip(agents, keypairs):
    hss, mme = agents
    aia = make_aia()
    original_auth_info = next(a.encode() for a in aia.avps if a.code == AVP_AUTH_INFO)

    protected = hss.process_outgoing_aia(aia, keypairs["mme_kem_pub"])
    assert sum(a.code == AVP_QURION_PROTECTED_AV and a.vendor_id == QURION_VENDOR_ID for a in protected.avps) == 1
    assert not any(a.code == AVP_AUTH_INFO for a in protected.avps)

    restored = mme.process_incoming_aia(protected)
    restored_auth_info = [a for a in restored.avps if a.code == AVP_AUTH_INFO]
    assert len(restored_auth_info) == 1
    assert restored_auth_info[0].encode() == original_auth_info
    assert not any(a.code == AVP_QURION_PROTECTED_AV for a in restored.avps)


def test_tampered_envelope_is_rejected(agents, keypairs):
    hss, mme = agents
    protected = hss.process_outgoing_aia(make_aia(), keypairs["mme_kem_pub"])
    env = next(a for a in protected.avps if a.code == AVP_QURION_PROTECTED_AV)
    tampered = bytearray(env.data)
    tampered[-1] ^= 0x01
    env.data = bytes(tampered)
    with pytest.raises(Exception):
        mme.process_incoming_aia(protected)


def test_success_aia_without_envelope_is_rejected(agents):
    _, mme = agents
    with pytest.raises(ValueError):
        mme.process_incoming_aia(make_aia())



def test_hss_protects_aia_and_mme_recovers_original_vectors():
    from src.crypto.kem import generate_keypair
    from src.crypto.signatures import generate_signing_keypair
    from src.diameter.avp_codec import (
        AVPBuilder,
        AVP_QURION_PROTECTED_AV,
        QURION_VENDOR_ID,
        DiameterMessage,
    )
    from src.gateway.hss_agent import HSSAgent
    from src.gateway.mme_agent import MMEAgent

    # Generate independent keys for the HSS and MME.
    mme_kem_pub, mme_kem_priv = generate_keypair()
    hss_sign_pub, hss_sign_priv = generate_signing_keypair()
    mme_sign_pub, mme_sign_priv = generate_signing_keypair()

    hss = HSSAgent(
        operator_id="hss.localdomain",
        realm="localdomain",
        signing_key=hss_sign_priv,
        signing_pub=hss_sign_pub,
        kem_key=b"",
        kem_pub=b"",
        trust_store=None,
        peer_cache=None,
        anomaly_detector=None,
        peer_operator_id="mme.localdomain",
        peer_realm="localdomain",
    )

    mme = MMEAgent(
        operator_id="mme.localdomain",
        realm="localdomain",
        signing_key=mme_sign_priv,
        signing_pub=mme_sign_pub,
        kem_key=mme_kem_priv,
        kem_pub=mme_kem_pub,
        trust_store=None,
        peer_cache=None,
        anomaly_detector=None,
        peer_operator_id="hss.localdomain",
        peer_realm="localdomain",
        peer_signing_pub=hss_sign_pub,
    )

    # Construct an AIA containing a representative authentication vector.
    vector_avps = AVPBuilder.build_s6a_auth_vector(
        rand=b"R" * 16,
        xres=b"X" * 8,
        autn=b"A" * 16,
        kasme=b"K" * 32,
    )

    aia = DiameterMessage(
        command_code=318,
        application_id=16777251,
        is_request=False,
        avps=vector_avps.copy(),
    )

    original_encoding = [avp.encode() for avp in vector_avps]

    # HSS protects the vector using the MME's KEM public key.
    protected_aia = hss.process_outgoing_aia(aia, mme_kem_pub)

    protected_avps = [
        avp for avp in protected_aia.avps
        if avp.code == AVP_QURION_PROTECTED_AV
        and avp.vendor_id == QURION_VENDOR_ID
    ]

    assert len(protected_avps) == 1

    vector_codes = {1447, 1415, 1449, 1450}
    assert not any(
        avp.code in vector_codes
        for avp in protected_aia.avps
    )

    # MME verifies the HSS signature, decrypts, and restores the vectors.
    recovered_aia = mme.process_incoming_aia(protected_aia)

    recovered_encoding = [
        avp.encode()
        for avp in recovered_aia.avps
        if avp.code in vector_codes
    ]

    assert recovered_encoding == original_encoding
    assert not any(
        avp.code == AVP_QURION_PROTECTED_AV
        and avp.vendor_id == QURION_VENDOR_ID
        for avp in recovered_aia.avps
    )
