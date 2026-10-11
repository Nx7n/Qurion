import struct
from src.protocol.capability import QurionCapability, NegotiatedParams

QURION_VENDOR_ID = 99999
QURION_CAPABILITY_AVP_CODE = 1001

class CERCEAProcessor:
    def __init__(self, local_capability: QurionCapability):
        self.local_capability = local_capability

    def build_capability_avp(self) -> bytes:
        cap_data = self.local_capability.serialize()
        flags = 0x80 # V bit
        length = 8 + 4 + len(cap_data) # Header(8) + Vendor(4) + Data
        avp_header = struct.pack('!I B', QURION_CAPABILITY_AVP_CODE, flags)
        avp_header += length.to_bytes(3, 'big')
        avp_header += struct.pack('!I', QURION_VENDOR_ID)
        avp = avp_header + cap_data
        
        pad_len = (4 - (len(avp) % 4)) % 4
        avp += b'\x00' * pad_len
        return avp

    @classmethod
    def parse_capability_avp(cls, avp_data: bytes) -> QurionCapability | None:
        if len(avp_data) < 12:
            return None
            
        code, flags = struct.unpack_from('!I B', avp_data, 0)
        if code != QURION_CAPABILITY_AVP_CODE:
            return None
        if not (flags & 0x80):
            return None
            
        length = int.from_bytes(avp_data[5:8], 'big')
        vendor_id = struct.unpack_from('!I', avp_data, 8)[0]
        
        if vendor_id != QURION_VENDOR_ID:
            return None
            
        cap_data = avp_data[12:length]
        try:
            return QurionCapability.deserialize(cap_data)
        except Exception:
            return None

    def process_peer_capability(self, peer_cap: QurionCapability) -> NegotiatedParams | None:
        return self.local_capability.negotiate(peer_cap)

    def build_cer_extension(self) -> bytes:
        return self.build_capability_avp()

    def process_cea_extension(self, data: bytes) -> NegotiatedParams | None:
        peer_cap = self.parse_capability_avp(data)
        if not peer_cap:
            return None
        return self.process_peer_capability(peer_cap)
