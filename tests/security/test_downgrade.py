from src.protocol.capability import CapabilityState, NegotiationAction, decide_action


def test_capability_downgrade_detected():
    # A first-time legacy peer may use classical fallback; a peer previously
    # known to support Qurion is mapped to DOWNGRADE and must be rejected.
    assert decide_action(True, CapabilityState.UNSUPPORTED) is NegotiationAction.FALLBACK
    assert decide_action(True, CapabilityState.DOWNGRADE) is NegotiationAction.REJECT


def test_version_downgrade_detected():
    # A version downgrade must not negotiate a protected session.
    assert decide_action(True, CapabilityState.INVALID) is NegotiationAction.REJECT


def test_unexpected_plaintext_detected():
    # Data-plane enforcement is only allowed after successful negotiation.
    assert decide_action(True, CapabilityState.UNSUPPORTED) is not NegotiationAction.PROTECT


def test_transcript_mac_failure_detected():
    # Invalid security context is a reject condition, never a fallback.
    assert decide_action(True, CapabilityState.INVALID) is NegotiationAction.REJECT


def test_certificate_change_detected():
    # A certificate/fingerprint mismatch is classified INVALID by validation.
    assert decide_action(True, CapabilityState.INVALID) is NegotiationAction.REJECT


def test_enforcement_policy_applied_correctly():
    assert decide_action(True, CapabilityState.SUPPORTED) is NegotiationAction.PROTECT
    assert decide_action(True, CapabilityState.UNSUPPORTED) is NegotiationAction.FALLBACK
    assert decide_action(False, CapabilityState.UNSUPPORTED) is NegotiationAction.PASSTHROUGH
