import json
import time
from enum import Enum
from dataclasses import dataclass, field, asdict

class EventType(Enum):
    KEY_EXCHANGE_START = 'key_exchange_start'
    KEY_EXCHANGE_COMPLETE = 'key_exchange_complete'
    KEY_EXCHANGE_FAILED = 'key_exchange_failed'
    AV_PROTECTION_START = 'av_protection_start'
    AV_PROTECTION_COMPLETE = 'av_protection_complete'
    AV_DECRYPTION_START = 'av_decryption_start'
    AV_DECRYPTION_COMPLETE = 'av_decryption_complete'
    AV_DECRYPTION_FAILED = 'av_decryption_failed'
    CAPABILITY_NEGOTIATION = 'capability_negotiation'
    CAPABILITY_DOWNGRADE = 'capability_downgrade'
    PQC_DOWNGRADE_DETECTED = 'pqc_downgrade_detected'
    CAPABILITY_INVALID = 'capability_invalid'
    ANOMALY_DETECTED = 'anomaly_detected'
    SESSION_ESTABLISHED = 'session_established'
    SESSION_EXPIRED = 'session_expired'
    CERT_VALIDATION = 'cert_validation'

@dataclass
class TelemetryEvent:
    event_type: EventType
    timestamp: float
    wall_clock: float
    correlation_id: str
    peer_id: str | None = None
    duration_ns: int | None = None
    metadata: dict = field(default_factory=dict)
    success: bool = True

class EventLogger:
    def __init__(self, output_file: str | None = None):
        self.output_file = output_file
        self.events: list[TelemetryEvent] = []

    def log(self, event: TelemetryEvent) -> None:
        self.events.append(event)
        if self.output_file:
            with open(self.output_file, "a") as f:
                event_dict = asdict(event)
                event_dict['event_type'] = event.event_type.value
                f.write(json.dumps(event_dict) + "\n")

    def get_events(self, event_type: EventType | None = None) -> list[TelemetryEvent]:
        if event_type is None:
            return list(self.events)
        return [e for e in self.events if e.event_type == event_type]

    def clear(self) -> None:
        self.events.clear()

    def export_json(self, filepath: str) -> None:
        with open(filepath, "w") as f:
            data = []
            for event in self.events:
                event_dict = asdict(event)
                event_dict['event_type'] = event.event_type.value
                data.append(event_dict)
            json.dump(data, f, indent=2)

    def summary(self) -> dict:
        counts = {}
        for event in self.events:
            name = event.event_type.value
            counts[name] = counts.get(name, 0) + 1
        return counts
