import struct
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict

QURION_VENDOR_ID = 99999

AVP_QURION_PROTECTED_AV = 1002
AVP_QURION_CAPABILITY = 1001
AVP_QURION_KEY_EXCHANGE = 1003

AVP_AUTH_SESSION_STATE = 277
AVP_VISITED_PLMN_ID = 1407
AVP_AUTH_INFO = 1413
AVP_E_UTRAN_VECTOR = 1414
AVP_RAND = 1447
AVP_XRES = 1415
AVP_AUTN = 1449
AVP_KASME = 1450

S6A_APPLICATION_ID = 16777251
AIR_COMMAND_CODE = 318
AIA_COMMAND_CODE = 318

def _pad(length: int) -> bytes:
    pad_len = (4 - (length % 4)) % 4
    return b'\x00' * pad_len

@dataclass
class DiameterAVP:
    code: int
    flags: int
    vendor_id: Optional[int]
    data: bytes

    def encode(self) -> bytes:
        v_flag = (self.flags & 0x80) != 0
        hdr_len = 12 if v_flag else 8
        total_len = hdr_len + len(self.data)
        
        len_bytes = total_len.to_bytes(3, 'big')
        code_bytes = struct.pack("!I", self.code)
        
        hdr = code_bytes + bytes([self.flags]) + len_bytes
        if v_flag:
            if self.vendor_id is None:
                raise ValueError("Vendor ID required if V flag is set")
            hdr += struct.pack("!I", self.vendor_id)
            
        res = hdr + self.data
        res += _pad(total_len)
        return res
        
    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> Tuple["DiameterAVP", int]:
        if len(data) - offset < 8:
            raise ValueError("Not enough data for AVP header")
            
        code = struct.unpack("!I", data[offset:offset+4])[0]
        flags = data[offset+4]
        length = int.from_bytes(data[offset+5:offset+8], 'big')
        
        v_flag = (flags & 0x80) != 0
        hdr_len = 12 if v_flag else 8
        
        if length < hdr_len:
            raise ValueError("Invalid AVP length")

        padded_length = length + ((4 - (length % 4)) % 4)
        if len(data) - offset < padded_length:
            raise ValueError("Truncated AVP or padding")

        padding = data[offset + length:offset + padded_length]
        if any(padding):
            raise ValueError("AVP padding must be zero")

        vendor_id = None
        if v_flag:
            vendor_id = struct.unpack("!I", data[offset+8:offset+12])[0]

        avp_data = data[offset+hdr_len:offset+length]
        return cls(code, flags, vendor_id, avp_data), padded_length

    @classmethod
    def decode_all(cls, data: bytes) -> List["DiameterAVP"]:
        avps = []
        offset = 0
        while offset < len(data):
            avp, consumed = cls.decode(data, offset)
            avps.append(avp)
            offset += consumed
        return avps

    @property
    def is_vendor_specific(self) -> bool:
        return (self.flags & 0x80) != 0

    @property
    def is_mandatory(self) -> bool:
        return (self.flags & 0x40) != 0

    @property
    def total_length(self) -> int:
        hdr_len = 12 if self.is_vendor_specific else 8
        raw_len = hdr_len + len(self.data)
        return raw_len + ((4 - (raw_len % 4)) % 4)

class AVPBuilder:
    @staticmethod
    def build_protected_av_avp(protected_avp_bytes: bytes) -> DiameterAVP:
        return DiameterAVP(AVP_QURION_PROTECTED_AV, 0x80, QURION_VENDOR_ID, protected_avp_bytes)
        
    @staticmethod
    def build_capability_avp(capability_bytes: bytes) -> DiameterAVP:
        return DiameterAVP(AVP_QURION_CAPABILITY, 0x80, QURION_VENDOR_ID, capability_bytes)
        
    @staticmethod
    def build_key_exchange_avp(key_exchange_bytes: bytes) -> DiameterAVP:
        return DiameterAVP(AVP_QURION_KEY_EXCHANGE, 0x80, QURION_VENDOR_ID, key_exchange_bytes)
        
    @staticmethod
    def parse_s6a_auth_vector(avp_list: List[DiameterAVP]) -> Dict[str, bytes]:
        res = {}
        for avp in avp_list:
            if avp.code == AVP_RAND:
                res["RAND"] = avp.data
            elif avp.code == AVP_XRES:
                res["XRES"] = avp.data
            elif avp.code == AVP_AUTN:
                res["AUTN"] = avp.data
            elif avp.code == AVP_KASME:
                res["KASME"] = avp.data
        return res
        
    @staticmethod
    def build_s6a_auth_vector(rand: bytes, xres: bytes, autn: bytes, kasme: bytes) -> List[DiameterAVP]:
        return [
            DiameterAVP(AVP_RAND, 0x40, None, rand),
            DiameterAVP(AVP_XRES, 0x40, None, xres),
            DiameterAVP(AVP_AUTN, 0x40, None, autn),
            DiameterAVP(AVP_KASME, 0x40, None, kasme),
        ]

@dataclass
class DiameterMessage:
    version: int = 1
    command_code: int = 0
    application_id: int = 0
    hop_by_hop_id: int = 0
    end_to_end_id: int = 0
    is_request: bool = True
    is_proxiable: bool = False
    is_error: bool = False
    is_retransmit: bool = False
    avps: List[DiameterAVP] = field(default_factory=list)

    def encode(self) -> bytes:
        flags = 0
        if self.is_request: flags |= 0x80
        if self.is_proxiable: flags |= 0x40
        if self.is_error: flags |= 0x20
        if self.is_retransmit: flags |= 0x10

        avps_data = b"".join(avp.encode() for avp in self.avps)
        total_length = 20 + len(avps_data)
        
        res = bytes([self.version]) + total_length.to_bytes(3, 'big')
        res += bytes([flags]) + self.command_code.to_bytes(3, 'big')
        res += struct.pack("!III", self.application_id, self.hop_by_hop_id, self.end_to_end_id)
        res += avps_data
        return res

    @classmethod
    def decode(cls, data: bytes) -> "DiameterMessage":
        if len(data) < 20:
            raise ValueError("Not enough data for Diameter header")
        
        version = data[0]
        length = int.from_bytes(data[1:4], 'big')
        if version != 1:
            raise ValueError(f"Unsupported Diameter version: {version}")
        if length < 20:
            raise ValueError("Invalid Diameter message length")
        if len(data) != length:
            raise ValueError(
                "Diameter buffer length does not match declared message length"
            )

        flags = data[4]
        command_code = int.from_bytes(data[5:8], 'big')
        app_id, hbh_id, e2e_id = struct.unpack("!III", data[8:20])
        
        msg = cls(
            version=version,
            command_code=command_code,
            application_id=app_id,
            hop_by_hop_id=hbh_id,
            end_to_end_id=e2e_id,
            is_request=(flags & 0x80) != 0,
            is_proxiable=(flags & 0x40) != 0,
            is_error=(flags & 0x20) != 0,
            is_retransmit=(flags & 0x10) != 0
        )
        
        msg.avps = DiameterAVP.decode_all(data[20:length])
        return msg

    def find_avp(self, code: int, vendor_id: Optional[int] = None) -> Optional[DiameterAVP]:
        for avp in self.avps:
            if avp.code == code and (vendor_id is None or avp.vendor_id == vendor_id):
                return avp
        return None

    def find_all_avps(self, code: int, vendor_id: Optional[int] = None) -> List[DiameterAVP]:
        return [avp for avp in self.avps if avp.code == code and (vendor_id is None or avp.vendor_id == vendor_id)]
