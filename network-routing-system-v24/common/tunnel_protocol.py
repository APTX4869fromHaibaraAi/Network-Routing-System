import struct
import hmac
import hashlib
import time
from enum import IntEnum
from typing import Optional
from dataclasses import dataclass


class MessageType(IntEnum):
    DATA = 0x01
    KEEPALIVE = 0x02
    CONTROL = 0x03
    IP_ALLOC_REQUEST = 0x04
    IP_ALLOC_RESPONSE = 0x05
    ROUTE_ADVERTISEMENT = 0x06
    ROUTER_UPDATE = 0x07
    ENDPOINT_ACTIVATION = 0x08
    ACTIVATION_ACK = 0x09
    DEACTIVATION_ACK = 0x0A



class PacketFlags(IntEnum):
    IPV4_PAYLOAD = 0x00
    IPV6_PAYLOAD = 0x01


@dataclass
class TunnelPacket:
    version: int
    msg_type: MessageType
    flags: int
    tunnel_id: int
    sequence: int
    timestamp: int
    payload: bytes
    hmac_tag: bytes = b''


class TunnelProtocol:
    VERSION = 0x01
    HEADER_SIZE = 16
    HMAC_SIZE = 16
    TOTAL_HEADER_SIZE = 32

    def __init__(self, psk: str, tunnel_id: int):
        # DEBUG: 现在不再真正用 psk，只是保留接口
        self.psk = psk.encode('utf-8')
        self.tunnel_id = tunnel_id
        self.tx_sequence = 0
        self.rx_sequence = 0

    # ====== 保留接口，但不再真正校验 ======
    def _compute_hmac(self, header_data: bytes, payload: bytes) -> bytes:
        """
        DEBUG 版：不再计算真实 HMAC，只返回 16 字节 0 占位。
        """
        return b"\x00" * self.HMAC_SIZE

    def _get_timestamp_ms(self) -> int:
        return int(time.time() * 1000) & 0xFFFFFFFF

    def encapsulate(
        self,
        payload: bytes,
        msg_type: MessageType = MessageType.DATA,
        is_ipv6: bool = False
    ) -> bytes:
        flags = PacketFlags.IPV6_PAYLOAD if is_ipv6 else PacketFlags.IPV4_PAYLOAD
        timestamp = self._get_timestamp_ms()

        header = struct.pack(
            '!BBBBIII',
            self.VERSION,
            msg_type,
            flags,
            0,
            self.tunnel_id,
            self.tx_sequence,
            timestamp
        )

        # DEBUG：不做真实 HMAC 校验，只填充 16 字节 0
        hmac_tag = b"\x00" * self.HMAC_SIZE

        packet = header + hmac_tag + payload

        self.tx_sequence = (self.tx_sequence + 1) & 0xFFFFFFFF

        return packet

    def decapsulate(self, packet: bytes) -> Optional[TunnelPacket]:
        # 长度检查还保留，防止乱包
        if len(packet) < self.TOTAL_HEADER_SIZE:
            return None

        header = packet[:self.HEADER_SIZE]
        # DEBUG：忽略收到的 hmac，直接跳过 16 字节
        received_hmac = packet[self.HEADER_SIZE:self.TOTAL_HEADER_SIZE]
        payload = packet[self.TOTAL_HEADER_SIZE:]

        # DEBUG：完全跳过 HMAC 校验
        # expected_hmac = self._compute_hmac(header, payload)
        # if not hmac.compare_digest(received_hmac, expected_hmac):
        #     return None

        version, msg_type, flags, reserved, tunnel_id, sequence, timestamp = struct.unpack(
            '!BBBBIII', header
        )

        # DEBUG：版本也不强制要求一致（你之前已经注释了）
        # if version != self.VERSION:
        #     return None

        # DEBUG：去掉时间戳窗口检查，防止时钟不一致导致丢包
        # current_time = self._get_timestamp_ms()
        # time_diff = abs(current_time - timestamp)
        # if time_diff > 60000:
        #     return None
        
        return TunnelPacket(
            version=version,
            msg_type=MessageType(msg_type),
            flags=flags,
            tunnel_id=tunnel_id,
            sequence=sequence,
            timestamp=timestamp,
            payload=payload,
            hmac_tag=received_hmac
        )
    
    def create_keepalive(self) -> bytes:
        return self.encapsulate(b'', MessageType.KEEPALIVE)
    
    def is_ipv6_payload(self, packet: TunnelPacket) -> bool:
        return packet.flags & PacketFlags.IPV6_PAYLOAD != 0
