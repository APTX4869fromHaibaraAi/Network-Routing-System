"""
Control Protocol for IP Allocation and Route Advertisement
Handles communication between endpoints, routers, and network controller
"""

import json
import struct
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import IntEnum


class ControlMessageType(IntEnum):
    """Control message types for system coordination"""
    IP_ALLOC_REQUEST = 1
    IP_ALLOC_RESPONSE = 2
    ROUTE_ADVERTISEMENT = 3
    ROUTER_UPDATE = 4
    TUNNEL_BIND = 5
    ENDPOINT_ACTIVATION = 6


@dataclass
class IPAllocationRequest:
    """Request for IP address allocation from network controller"""
    endpoint_id: str
    reconnect: bool = False  # True if reconnecting with previous allocation
    previous_subnet: Optional[str] = None


@dataclass
class IPAllocationResponse:
    """Response with allocated IP subnet"""
    endpoint_id: str
    success: bool
    subnet_ipv4: Optional[str] = None  # e.g., "10.100.1.0/24"
    subnet_ipv6: Optional[str] = None  # e.g., "fd00:100:1::/64"
    gateway_ipv4: Optional[str] = None
    gateway_ipv6: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class RouteAdvertisement:
    """Route advertisement from endpoint to router"""
    endpoint_id: str
    routes_ipv4: List[str]  # List of IPv4 subnets
    routes_ipv6: List[str]  # List of IPv6 subnets


@dataclass
class RouterUpdate:
    """Routing update between routers (distributed protocol)"""
    router_id: str
    routes: Dict[str, Dict]  # {subnet: {next_hop, metric, endpoint_id}}
    sequence: int


@dataclass
class TunnelBinding:
    """Binding between tunnel and endpoint addresses"""
    endpoint_id: str
    tunnel_id: int
    overlay_ipv4: str
    overlay_ipv6: str

@dataclass
class EndpointActivation:
    endpoint_id: str  # 接入端 ID
    routes_ipv4: List[str]  # 例如 ["10.100.0.0/24"]
    routes_ipv6: List[str]  # 例如 ["fd00:100::/64"]
    previous_router_id: Optional[str] = None  # 旧路由器标识（可选）
    previous_router_ip: Optional[str] = None  # 旧路由器对外 IPv6（UDP 单播目标）
    active: bool = True  # True=激活新路由器；False=旧路由器清理
    timestamp: float = 0.0  # 可选，调试 / 防重放用


class ControlProtocol:
    """Protocol handler for control messages"""
    
    @staticmethod
    def encode_ip_alloc_request(req: IPAllocationRequest) -> bytes:
        """Encode IP allocation request to JSON bytes"""
        data = asdict(req)
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def decode_ip_alloc_request(data: bytes) -> IPAllocationRequest:
        """Decode IP allocation request from JSON bytes"""
        obj = json.loads(data.decode('utf-8'))
        return IPAllocationRequest(**obj)
    
    @staticmethod
    def encode_ip_alloc_response(resp: IPAllocationResponse) -> bytes:
        """Encode IP allocation response to JSON bytes"""
        data = asdict(resp)
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def decode_ip_alloc_response(data: bytes) -> IPAllocationResponse:
        """Decode IP allocation response from JSON bytes"""
        obj = json.loads(data.decode('utf-8'))
        return IPAllocationResponse(**obj)
    
    @staticmethod
    def encode_route_advertisement(adv: RouteAdvertisement) -> bytes:
        """Encode route advertisement to JSON bytes"""
        data = asdict(adv)
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def decode_route_advertisement(data: bytes) -> RouteAdvertisement:
        """Decode route advertisement from JSON bytes"""
        obj = json.loads(data.decode('utf-8'))
        return RouteAdvertisement(**obj)
    
    @staticmethod
    def encode_router_update(update: RouterUpdate) -> bytes:
        """Encode router update to JSON bytes"""
        data = asdict(update)
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def decode_router_update(data: bytes) -> RouterUpdate:
        """Decode router update from JSON bytes"""
        obj = json.loads(data.decode('utf-8'))
        return RouterUpdate(**obj)
    
    @staticmethod
    def encode_tunnel_binding(binding: TunnelBinding) -> bytes:
        """Encode tunnel binding to JSON bytes"""
        data = asdict(binding)
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def decode_tunnel_binding(data: bytes) -> TunnelBinding:
        """Decode tunnel binding from JSON bytes"""
        obj = json.loads(data.decode('utf-8'))
        return TunnelBinding(**obj)

    @staticmethod
    def encode_endpoint_activation(msg: EndpointActivation) -> bytes:
        data = asdict(msg)
        if not data.get("timestamp"):
            data["timestamp"] = time.time()
        return json.dumps(data).encode("utf-8")

    @staticmethod
    def decode_endpoint_activation(data: bytes) -> EndpointActivation:
        """Decode EndpointActivation from JSON bytes"""
        obj = json.loads(data.decode("utf-8"))
        return EndpointActivation(**obj)
