import pytest
from datetime import datetime, timezone, timedelta
from src.certificates.operator_cert import OperatorCertificate, KeyUsage
from src.certificates.trust_store import TrustStore
from src.crypto.signatures import generate_signing_keypair
from src.crypto.kem import generate_keypair as generate_kem_keypair

@pytest.fixture
def issuer_keys():
    return generate_signing_keypair()

@pytest.fixture
def dummy_operator_keys():
    signing_pub, _ = generate_signing_keypair()
    kem_pub, _ = generate_kem_keypair()
    return signing_pub, kem_pub

def test_certificate_creation_and_serialization(issuer_keys, dummy_operator_keys):
    issuer_pub, issuer_priv = issuer_keys
    signing_pub, kem_pub = dummy_operator_keys
    
    cert = OperatorCertificate.issue(
        operator_id="op1",
        realm="example.com",
        signing_pub=signing_pub,
        kem_pub=kem_pub,
        key_usage=KeyUsage.BOTH,
        validity_days=30,
        issuer_id="issuer1",
        issuer_signing_key=issuer_priv
    )
    
    assert cert.operator_id == "op1"
    assert cert.realm == "example.com"
    assert cert.issuer_id == "issuer1"
    assert cert.verify_signature(issuer_pub)
    
    serialized = cert.serialize()
    deserialized = OperatorCertificate.deserialize(serialized)
    
    assert deserialized.operator_id == cert.operator_id
    assert deserialized.realm == cert.realm
    assert deserialized.serial == cert.serial
    assert deserialized.verify_signature(issuer_pub)

def test_signature_verification_invalid(issuer_keys, dummy_operator_keys):
    issuer_pub, issuer_priv = issuer_keys
    signing_pub, kem_pub = dummy_operator_keys
    
    cert = OperatorCertificate.issue(
        operator_id="op1",
        realm="example.com",
        signing_pub=signing_pub,
        kem_pub=kem_pub,
        key_usage=KeyUsage.BOTH,
        validity_days=30,
        issuer_id="issuer1",
        issuer_signing_key=issuer_priv
    )
    
    # Tamper with the certificate
    cert.operator_id = "op2"
    assert not cert.verify_signature(issuer_pub)

def test_expired_certificate_rejection(issuer_keys, dummy_operator_keys):
    issuer_pub, issuer_priv = issuer_keys
    signing_pub, kem_pub = dummy_operator_keys
    
    cert = OperatorCertificate.issue(
        operator_id="op1",
        realm="example.com",
        signing_pub=signing_pub,
        kem_pub=kem_pub,
        key_usage=KeyUsage.BOTH,
        validity_days=30,
        issuer_id="issuer1",
        issuer_signing_key=issuer_priv
    )
    
    future_time = datetime.now(timezone.utc) + timedelta(days=31)
    assert not cert.is_valid(future_time)
    assert cert.is_expired(future_time)

def test_wrong_realm_and_key_usage(issuer_keys, dummy_operator_keys):
    issuer_pub, issuer_priv = issuer_keys
    signing_pub, kem_pub = dummy_operator_keys
    
    cert = OperatorCertificate.issue(
        operator_id="op1",
        realm="example.com",
        signing_pub=signing_pub,
        kem_pub=kem_pub,
        key_usage=KeyUsage.SIGNING,
        validity_days=30,
        issuer_id="issuer1",
        issuer_signing_key=issuer_priv
    )
    
    assert cert.check_realm("example.com")
    assert not cert.check_realm("wrong.com")
    
    assert cert.check_key_usage("SIGNING")
    assert not cert.check_key_usage("KEM")

def test_trust_store_operations(issuer_keys, dummy_operator_keys):
    issuer_pub, issuer_priv = issuer_keys
    signing_pub, kem_pub = dummy_operator_keys
    
    store = TrustStore()
    
    cert = OperatorCertificate.issue(
        operator_id="op1",
        realm="example.com",
        signing_pub=signing_pub,
        kem_pub=kem_pub,
        key_usage=KeyUsage.BOTH,
        validity_days=30,
        issuer_id="issuer1",
        issuer_signing_key=issuer_priv
    )
    
    assert store.add_trusted_certificate(cert, issuer_pub)
    assert store.get_certificate("op1", "example.com") == cert
    assert store.get_by_serial(cert.serial) == cert
    
    # Valid peer verification
    assert store.verify_peer("op1", "example.com", "SIGNING") == cert
    
    # Unknown operator
    assert store.verify_peer("op2", "example.com", "SIGNING") is None
    
    # Wrong key usage
    cert2 = OperatorCertificate.issue(
        operator_id="op2",
        realm="example.com",
        signing_pub=signing_pub,
        kem_pub=kem_pub,
        key_usage=KeyUsage.KEM,
        validity_days=30,
        issuer_id="issuer1",
        issuer_signing_key=issuer_priv
    )
    store.add_trusted_certificate(cert2, issuer_pub)
    assert store.verify_peer("op2", "example.com", "SIGNING") is None
    
    store.remove_certificate(cert.serial)
    assert store.get_certificate("op1", "example.com") is None

def test_expired_cleanup(issuer_keys, dummy_operator_keys):
    issuer_pub, issuer_priv = issuer_keys
    signing_pub, kem_pub = dummy_operator_keys
    
    store = TrustStore()
    cert = OperatorCertificate.issue(
        operator_id="op1",
        realm="example.com",
        signing_pub=signing_pub,
        kem_pub=kem_pub,
        key_usage=KeyUsage.BOTH,
        validity_days=1,
        issuer_id="issuer1",
        issuer_signing_key=issuer_priv
    )
    
    store.add_trusted_certificate(cert, issuer_pub)
    
    future_time = datetime.now(timezone.utc) + timedelta(days=2)
    assert store.cleanup_expired(future_time) == 1
    assert len(store.list_certificates()) == 0

def test_key_rotation(issuer_keys, dummy_operator_keys):
    issuer_pub, issuer_priv = issuer_keys
    signing_pub, kem_pub = dummy_operator_keys
    
    store = TrustStore()
    
    cert1 = OperatorCertificate.issue(
        operator_id="op1",
        realm="example.com",
        signing_pub=signing_pub,
        kem_pub=kem_pub,
        key_usage=KeyUsage.BOTH,
        validity_days=30,
        issuer_id="issuer1",
        issuer_signing_key=issuer_priv
    )
    
    store.add_trusted_certificate(cert1, issuer_pub)
    assert len(store.list_certificates()) == 1
    
    cert2 = OperatorCertificate.issue(
        operator_id="op1",
        realm="example.com",
        signing_pub=signing_pub, # pretend it's a new key
        kem_pub=kem_pub,
        key_usage=KeyUsage.BOTH,
        validity_days=30,
        issuer_id="issuer1",
        issuer_signing_key=issuer_priv
    )
    
    store.add_trusted_certificate(cert2, issuer_pub)
    assert len(store.list_certificates()) == 1
    assert store.get_certificate("op1", "example.com").serial == cert2.serial

def test_tampered_cert_rejection(issuer_keys, dummy_operator_keys):
    issuer_pub, issuer_priv = issuer_keys
    signing_pub, kem_pub = dummy_operator_keys
    
    store = TrustStore()
    
    cert = OperatorCertificate.issue(
        operator_id="op1",
        realm="example.com",
        signing_pub=signing_pub,
        kem_pub=kem_pub,
        key_usage=KeyUsage.BOTH,
        validity_days=30,
        issuer_id="issuer1",
        issuer_signing_key=issuer_priv
    )
    
    cert.key_usage = KeyUsage.SIGNING
    
    assert not store.add_trusted_certificate(cert, issuer_pub)
    assert len(store.list_certificates()) == 0
