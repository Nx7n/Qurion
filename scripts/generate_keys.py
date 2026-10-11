#!/usr/bin/env python3
"""Generate PQC operator keys and certificates for Qurion deployment.

Creates ML-KEM-768 and ML-DSA-65 keypairs for both HSS and MME operators,
then issues mutual operator certificates and writes everything to
configs/qurion/ and configs/certificates/.
"""

import os
import sys
import json
import base64
from datetime import datetime, timezone

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.crypto.kem import generate_keypair as kem_keygen
from src.crypto.signatures import generate_signing_keypair as sig_keygen
from src.certificates.operator_cert import OperatorCertificate, KeyUsage


def write_key_file(filepath: str, data: dict):
    """Write a key file as JSON with base64-encoded binary fields."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    os.chmod(filepath, 0o600)
    print(f"  Wrote {filepath}")


def main():
    realm = "localdomain"
    cert_dir = os.path.join(os.path.dirname(__file__), '..', 'configs', 'certificates')
    qurion_dir = os.path.join(os.path.dirname(__file__), '..', 'configs', 'qurion')
    os.makedirs(cert_dir, exist_ok=True)
    os.makedirs(qurion_dir, exist_ok=True)

    print("=== Qurion PQC Key Generation ===\n")

    # --- HSS Keys ---
    print("[1/4] Generating HSS ML-KEM-768 keypair...")
    hss_kem_pub, hss_kem_priv = kem_keygen()

    print("[2/4] Generating HSS ML-DSA-65 signing keypair...")
    hss_sign_pub, hss_sign_priv = sig_keygen()

    write_key_file(os.path.join(qurion_dir, 'hss_keys.json'), {
        'operator_id': 'hss.localdomain',
        'realm': realm,
        'kem_public_key': base64.b64encode(hss_kem_pub).decode(),
        'kem_secret_key': base64.b64encode(hss_kem_priv).decode(),
        'signing_public_key': base64.b64encode(hss_sign_pub).decode(),
        'signing_secret_key': base64.b64encode(hss_sign_priv).decode(),
        'kem_algorithm': 'ML-KEM-768',
        'sig_algorithm': 'ML-DSA-65',
        'generated_at': datetime.now(timezone.utc).isoformat(),
    })

    # --- MME Keys ---
    print("[3/4] Generating MME ML-KEM-768 keypair...")
    mme_kem_pub, mme_kem_priv = kem_keygen()

    print("[4/4] Generating MME ML-DSA-65 signing keypair...")
    mme_sign_pub, mme_sign_priv = sig_keygen()

    write_key_file(os.path.join(qurion_dir, 'mme_keys.json'), {
        'operator_id': 'mme.localdomain',
        'realm': realm,
        'kem_public_key': base64.b64encode(mme_kem_pub).decode(),
        'kem_secret_key': base64.b64encode(mme_kem_priv).decode(),
        'signing_public_key': base64.b64encode(mme_sign_pub).decode(),
        'signing_secret_key': base64.b64encode(mme_sign_priv).decode(),
        'kem_algorithm': 'ML-KEM-768',
        'sig_algorithm': 'ML-DSA-65',
        'generated_at': datetime.now(timezone.utc).isoformat(),
    })

    # --- Issue Operator Certificates ---
    print("\n=== Issuing Operator Certificates ===\n")

    # HSS certificate (self-signed, used by MME to verify HSS)
    hss_cert = OperatorCertificate.issue(
        operator_id='hss.localdomain',
        realm=realm,
        signing_pub=hss_sign_pub,
        kem_pub=hss_kem_pub,
        key_usage=KeyUsage.BOTH,
        validity_days=365,
        issuer_id='hss.localdomain',
        issuer_signing_key=hss_sign_priv,
    )
    hss_cert_path = os.path.join(cert_dir, 'hss_operator_cert.json')
    with open(hss_cert_path, 'wb') as f:
        f.write(hss_cert.serialize())
    print(f"  Issued HSS certificate: {hss_cert_path}")
    print(f"    Serial: {hss_cert.serial}")
    print(f"    Valid: {hss_cert.not_before.isoformat()} → {hss_cert.not_after.isoformat()}")

    # MME certificate (self-signed, used by HSS to verify MME)
    mme_cert = OperatorCertificate.issue(
        operator_id='mme.localdomain',
        realm=realm,
        signing_pub=mme_sign_pub,
        kem_pub=mme_kem_pub,
        key_usage=KeyUsage.BOTH,
        validity_days=365,
        issuer_id='mme.localdomain',
        issuer_signing_key=mme_sign_priv,
    )
    mme_cert_path = os.path.join(cert_dir, 'mme_operator_cert.json')
    with open(mme_cert_path, 'wb') as f:
        f.write(mme_cert.serialize())
    print(f"  Issued MME certificate: {mme_cert_path}")
    print(f"    Serial: {mme_cert.serial}")
    print(f"    Valid: {mme_cert.not_before.isoformat()} → {mme_cert.not_after.isoformat()}")

    # Verify certificates
    print("\n=== Verification ===\n")
    assert hss_cert.verify_signature(hss_sign_pub), "HSS cert verification failed!"
    print("  ✓ HSS certificate signature valid")
    assert mme_cert.verify_signature(mme_sign_pub), "MME cert verification failed!"
    print("  ✓ MME certificate signature valid")
    assert hss_cert.is_valid(), "HSS cert not valid!"
    print("  ✓ HSS certificate is within validity period")
    assert mme_cert.is_valid(), "MME cert not valid!"
    print("  ✓ MME certificate is within validity period")

    print("\n=== Key Generation Complete ===")
    print(f"\nKey files:   {qurion_dir}/")
    print(f"Cert files:  {cert_dir}/")
    print(f"\nKey sizes:")
    print(f"  ML-KEM-768 public key:  {len(hss_kem_pub)} bytes")
    print(f"  ML-KEM-768 secret key:  {len(hss_kem_priv)} bytes")
    print(f"  ML-DSA-65 public key:   {len(hss_sign_pub)} bytes")
    print(f"  ML-DSA-65 secret key:   {len(hss_sign_priv)} bytes")


if __name__ == '__main__':
    main()
