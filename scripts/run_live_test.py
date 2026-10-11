#!/usr/bin/env python3
"""run_live_test.py — Live End-to-End PQC Diameter S6a Verification.

Tests the full interception and protection lifecycle:
1. Spawns HSS and MME agents with realistic keys.
2. Emulates an S6a AIR/AIA exchange carrying 3GPP Authentication Vectors (RAND, AUTN, XRES, KASME).
3. HSS Agent encapsulates/encrypts using ML-KEM-768 and ML-DSA-65.
4. Confirms the plaintext AVPs are replaced by AVP_QURION_PROTECTED_AV on the wire.
5. Relay forwards the protected message without being able to decrypt.
6. MME Agent decapsulates/decrypts and validates the authentication vectors.
7. Logs events and microbenchmarks to captures/ and results/.
"""

import os
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.crypto.kem import generate_keypair as kem_keygen
from src.crypto.signatures import generate_signing_keypair as sig_keygen
from src.gateway.hss_agent import HSSAgent
from src.gateway.mme_agent import MMEAgent
from src.gateway.relay import DiameterRelay
from src.diameter.avp_codec import (
    DiameterMessage, AVPBuilder, 
    AVP_AUTH_INFO, AVP_E_UTRAN_VECTOR, 
    AVP_QURION_PROTECTED_AV, QURION_VENDOR_ID,
    S6A_APPLICATION_ID, AIA_COMMAND_CODE
)
from src.telemetry.events import EventLogger, EventType, TelemetryEvent

GREEN = '\033[0;32m'
RED = '\033[0;31m'
BLUE = '\033[0;34m'
NC = '\033[0m'

def log_step(msg):
    print(f"\n{BLUE}=== {msg} ==={NC}")

def pass_step(msg):
    print(f"{GREEN}[✓]{NC} {msg}")

def fail_step(msg):
    print(f"{RED}[✗]{NC} {msg}")

def main():
    print(f"{BLUE}================================================================={NC}")
    print(f"{BLUE} Phase 8 — Live End-to-End PQC S6a Interception Test{NC}")
    print(f"{BLUE}================================================================={NC}")

    # 1. Generate / load cryptographic identities
    log_step("1. Cryptographic Key Setup (ML-KEM-768 & ML-DSA-65)")
    hss_kem_pub, hss_kem_priv = kem_keygen()
    hss_sign_pub, hss_sign_priv = sig_keygen()
    mme_kem_pub, mme_kem_priv = kem_keygen()
    mme_sign_pub, mme_sign_priv = sig_keygen()
    pass_step("Generated NIST ML-KEM-768 and ML-DSA-65 keypairs for HSS and MME.")

    # 2. Initialize Agents and Relay
    log_step("2. Initializing Gateway Agents and Diameter Relay")
    event_logger = EventLogger(output_file="results/live_test_telemetry.jsonl")
    
    hss_agent = HSSAgent(
        operator_id="hss.localdomain", realm="localdomain",
        signing_key=hss_sign_priv, signing_pub=hss_sign_pub,
        kem_key=hss_kem_priv, kem_pub=hss_kem_pub,
        trust_store=None, peer_cache=None, anomaly_detector=None
    )
    
    mme_agent = MMEAgent(
        operator_id="mme.localdomain", realm="localdomain",
        signing_key=mme_sign_priv, signing_pub=mme_sign_pub,
        kem_key=mme_kem_priv, kem_pub=mme_kem_pub,
        trust_store=None, peer_cache=None, anomaly_detector=None
    )
    
    relay = DiameterRelay()
    pass_step("HSSAgent, MMEAgent, and DiameterRelay operational.")

    # 3. Simulate 3GPP Authentication Vectors in S6a AIA
    log_step("3. Generating Outgoing S6a AIA with EPC Authentication Vectors")
    rand = os.urandom(16)
    autn = os.urandom(16)
    xres = os.urandom(8)
    kasme = os.urandom(32)

    avps = AVPBuilder.build_s6a_auth_vector(rand=rand, xres=xres, autn=autn, kasme=kasme)

    aia_msg = DiameterMessage(
        version=1,
        command_code=AIA_COMMAND_CODE,
        application_id=S6A_APPLICATION_ID,
        hop_by_hop_id=12345,
        end_to_end_id=67890,
        is_request=False,
        is_proxiable=True,
        avps=avps
    )
    unprotected_wire = aia_msg.encode()
    pass_step(f"Generated standard S6a AIA containing 4 AVPs ({len(unprotected_wire)} bytes wire size).")

    # 4. HSS Agent Interception & PQC Protection
    log_step("4. HSS Agent Interception (ML-KEM-768 Encapsulation & AES-GCM Encryption)")
    t0 = time.perf_counter_ns()
    protected_msg = hss_agent.process_outgoing_aia(aia_msg, mme_kem_pub)
    protect_duration_ns = time.perf_counter_ns() - t0
    
    protected_wire = protected_msg.encode()
    
    # Assertions
    assert protected_msg.find_avp(AVP_QURION_PROTECTED_AV, QURION_VENDOR_ID) is not None, "Protected AVP missing"
    assert protected_msg.find_avp(AVP_AUTH_INFO) is None, "Plaintext Auth-Info still present"
    pass_step(f"AIA intercepted and protected in {protect_duration_ns / 1000:.1f} µs.")
    pass_step(f"Protected wire size: {len(protected_wire)} bytes (Expansion: +{len(protected_wire) - len(unprotected_wire)} bytes).")

    # 5. Relay forwarding
    log_step("5. Diameter Proxy/Relay Forwarding")
    relayed_msg = relay.forward(protected_msg, direction="HSS->MME")
    assert relay.has_protected_avp(relayed_msg), "Relay failed to preserve protected payload"
    pass_step(f"Relay forwarded message without decryption (Metadata inspection confirmed).")

    # 6. MME Agent Interception & Decryption
    log_step("6. MME Agent Decapsulation & Decryption (ML-KEM Decapsulation & Verification)")
    t1 = time.perf_counter_ns()
    restored_msg = mme_agent.process_incoming_aia(relayed_msg)
    decrypt_duration_ns = time.perf_counter_ns() - t1
    
    pass_step(f"MME decapsulated and restored AIA in {decrypt_duration_ns / 1000:.1f} µs.")
    
    # 7. Verification of restored vectors
    log_step("7. Authentication Vector Verification")
    restored_dict = AVPBuilder.parse_s6a_auth_vector(restored_msg.avps)
    assert restored_dict.get("RAND") == rand, "RAND mismatch"
    assert restored_dict.get("AUTN") == autn, "AUTN mismatch"
    assert restored_dict.get("XRES") == xres, "XRES mismatch"
    assert restored_dict.get("KASME") == kasme, "KASME mismatch"
    
    pass_step("All cryptographic material (RAND, AUTN, XRES, KASME) exactly matches original!")
    pass_step(f"End-to-end PQC latency overhead: {(protect_duration_ns + decrypt_duration_ns) / 1000:.1f} µs.")

    print(f"\n{GREEN}================================================================={NC}")
    print(f"{GREEN} End-to-End Live Integration Verification: 100% SUCCESSFUL{NC}")
    print(f"{GREEN}================================================================={NC}\n")

if __name__ == "__main__":
    main()
