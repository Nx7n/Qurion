from typing import Dict, Any
from src.diameter.avp_codec import DiameterMessage, AVP_QURION_PROTECTED_AV, QURION_VENDOR_ID

class DiameterRelay:
    """Diameter relay/proxy.
    
    Forwards S6a messages between MME agent and HSS agent.
    Cannot decrypt Qurion protected AVPs.
    Logs message metadata for telemetry.
    """
    def __init__(self):
        self.logs = []

    def forward(self, message: DiameterMessage, direction: str) -> DiameterMessage:
        metadata = self.inspect_metadata(message)
        self.logs.append({
            "direction": direction,
            "metadata": metadata
        })
        return message

    def inspect_metadata(self, message: DiameterMessage) -> Dict[str, Any]:
        return {
            "command_code": message.command_code,
            "application_id": message.application_id,
            "is_request": message.is_request,
            "is_error": message.is_error,
            "avp_count": len(message.avps),
            "has_protected_avp": self.has_protected_avp(message)
        }

    def has_protected_avp(self, message: DiameterMessage) -> bool:
        return message.find_avp(AVP_QURION_PROTECTED_AV, QURION_VENDOR_ID) is not None
