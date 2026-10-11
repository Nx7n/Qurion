import time
from enum import Enum
from dataclasses import dataclass
from src.protocol.capability import QurionCapability
from src.diameter.peer_cache import PeerCacheEntry

class AnomalyType(Enum):
    CAPABILITY_DOWNGRADE = 'capability_downgrade'
    VERSION_DOWNGRADE = 'version_downgrade'
    SUITE_DOWNGRADE = 'suite_downgrade'
    UNEXPECTED_PLAINTEXT = 'unexpected_plaintext'
    TRANSCRIPT_MAC_FAILURE = 'transcript_mac_failure'
    CERT_CHANGE = 'cert_change'
    INVALID_CAPABILITY = 'invalid_capability'

class AnomalyAction(Enum):
    REJECT = 'reject'
    LOG_AND_CONTINUE = 'log_and_continue'
    TERMINATE_SESSION = 'terminate_session'
    REQUIRE_INTERVENTION = 'require_intervention'

@dataclass
class AnomalyEvent:
    timestamp: float
    anomaly_type: AnomalyType
    peer_operator_id: str
    peer_realm: str
    description: str
    correlation_id: str
    action_taken: AnomalyAction
    details: dict

class AnomalyDetector:
    DEFAULT_POLICY = {
        AnomalyType.CAPABILITY_DOWNGRADE: AnomalyAction.REJECT,
        AnomalyType.VERSION_DOWNGRADE: AnomalyAction.REJECT,
        AnomalyType.SUITE_DOWNGRADE: AnomalyAction.REJECT,
        AnomalyType.UNEXPECTED_PLAINTEXT: AnomalyAction.LOG_AND_CONTINUE,
        AnomalyType.TRANSCRIPT_MAC_FAILURE: AnomalyAction.REJECT,
        AnomalyType.CERT_CHANGE: AnomalyAction.LOG_AND_CONTINUE,
        AnomalyType.INVALID_CAPABILITY: AnomalyAction.REJECT,
    }

    def __init__(self, policy: dict[AnomalyType, AnomalyAction] | None = None) -> None:
        self.policy = policy or self.DEFAULT_POLICY.copy()
        self._events: list[AnomalyEvent] = []

    def _log_event(self, event: AnomalyEvent) -> None:
        self._events.append(event)

    def check_capability_downgrade(self, peer_id: str, realm: str, current_cap: QurionCapability, cached: PeerCacheEntry | None) -> AnomalyEvent | None:
        if not cached:
            return None
        
        # Check version downgrade
        if current_cap.protocol_version < max(cached.protocol_versions):
            action = self.get_policy(AnomalyType.VERSION_DOWNGRADE)
            event = AnomalyEvent(
                timestamp=time.time(),
                anomaly_type=AnomalyType.VERSION_DOWNGRADE,
                peer_operator_id=peer_id,
                peer_realm=realm,
                description="Protocol version downgrade detected",
                correlation_id="",
                action_taken=action,
                details={'cached_versions': cached.protocol_versions, 'current': current_cap.protocol_version}
            )
            self._log_event(event)
            return event
            
        # Check suite downgrade
        current_suites = [s.value for s in current_cap.supported_suites]
        missing = set(cached.supported_suites) - set(current_suites)
        if missing:
            action = self.get_policy(AnomalyType.SUITE_DOWNGRADE)
            event = AnomalyEvent(
                timestamp=time.time(),
                anomaly_type=AnomalyType.SUITE_DOWNGRADE,
                peer_operator_id=peer_id,
                peer_realm=realm,
                description="Algorithm suite downgrade detected",
                correlation_id="",
                action_taken=action,
                details={'missing_suites': list(missing)}
            )
            self._log_event(event)
            return event
            
        return None

    def check_transcript_mac(self, peer_id: str, realm: str, mac_valid: bool, correlation_id: str) -> AnomalyEvent | None:
        if not mac_valid:
            action = self.get_policy(AnomalyType.TRANSCRIPT_MAC_FAILURE)
            event = AnomalyEvent(
                timestamp=time.time(),
                anomaly_type=AnomalyType.TRANSCRIPT_MAC_FAILURE,
                peer_operator_id=peer_id,
                peer_realm=realm,
                description="Transcript MAC verification failed",
                correlation_id=correlation_id,
                action_taken=action,
                details={}
            )
            self._log_event(event)
            return event
        return None

    def check_unexpected_plaintext(self, peer_id: str, realm: str, cached: PeerCacheEntry | None, correlation_id: str) -> AnomalyEvent | None:
        if cached:
            action = self.get_policy(AnomalyType.UNEXPECTED_PLAINTEXT)
            event = AnomalyEvent(
                timestamp=time.time(),
                anomaly_type=AnomalyType.UNEXPECTED_PLAINTEXT,
                peer_operator_id=peer_id,
                peer_realm=realm,
                description="Received unexpected plaintext from known secure peer",
                correlation_id=correlation_id,
                action_taken=action,
                details={}
            )
            self._log_event(event)
            return event
        return None

    def check_cert_change(self, peer_id: str, realm: str, new_fingerprint: bytes, cached: PeerCacheEntry | None, correlation_id: str) -> AnomalyEvent | None:
        if cached and cached.cert_fingerprint != new_fingerprint:
            action = self.get_policy(AnomalyType.CERT_CHANGE)
            event = AnomalyEvent(
                timestamp=time.time(),
                anomaly_type=AnomalyType.CERT_CHANGE,
                peer_operator_id=peer_id,
                peer_realm=realm,
                description="Peer certificate fingerprint changed",
                correlation_id=correlation_id,
                action_taken=action,
                details={'old': cached.cert_fingerprint.hex(), 'new': new_fingerprint.hex()}
            )
            self._log_event(event)
            return event
        return None

    def get_events(self, peer_id: str | None = None) -> list[AnomalyEvent]:
        if peer_id:
            return [e for e in self._events if e.peer_operator_id == peer_id]
        return list(self._events)

    def get_policy(self, anomaly_type: AnomalyType) -> AnomalyAction:
        return self.policy.get(anomaly_type, AnomalyAction.LOG_AND_CONTINUE)

    def clear_events(self) -> None:
        self._events.clear()
