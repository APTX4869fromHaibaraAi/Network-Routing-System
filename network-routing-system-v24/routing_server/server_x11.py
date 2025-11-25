#!/usr/bin/env python3
"""
Routing Server
Receives tunneled packets, forwards them, and reports metrics to load balancer
"""

import sys
import os
import socket
import struct
import threading
import time
import json
import logging
import yaml
import psutil
import requests
import threading
import ipaddress
from typing import Dict, Optional
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from common.tunnel_protocol import TunnelProtocol, MessageType
from common.control_protocol import (
    IPAllocationRequest, IPAllocationResponse,
    RouteAdvertisement, RouterUpdate, ControlProtocol,
    EndpointActivation,
)


class RoutingServer:
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.setup_logging()
        
        self.tunnel_protocol = TunnelProtocol(
            psk=self.config['tunnel']['psk'],
            tunnel_id=self.config['server']['tunnel_id']
        )
        
        self.udp_socket = None
        self.tun_fd = None
        self.running = False
        
        self.stats = {
            'rx_packets': 0,
            'tx_packets': 0,
            'rx_bytes': 0,
            'tx_bytes': 0,
            'active_tunnels': 0,
            'last_reset': time.time()
        }
        
        self.active_peers = {}
        self.peer_timeout = 30
        self.overlay_ip_to_peer = {}
        self.overlay_prefix_to_peer = {}
        
        self.endpoint_allocations = {}
        self.routing_table = {}
        self.peer_routers = {}

        self.pending_deactivations = {}  # key: (endpoint_id, peer_ip)
        self.deactivation_lock = threading.Lock()
        server_cfg = self.config.get('server', {})
        self.deactivation_max_retries = server_cfg.get('deactivation_max_retries', 100)
        self.deactivation_retry_interval = server_cfg.get('deactivation_retry_interval', 1.0)  # 秒

        self.logger.info(f"Routing server initialized: {self.config['server']['name']}")
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['server']['log_file']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('RoutingServer')
    
    def setup_tunnel_socket(self):
        self.udp_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        bind_addr = self.config['server']['bind_address']
        bind_port = self.config['server']['bind_port']
        
        self.udp_socket.bind((bind_addr, bind_port))
        self.logger.info(f"UDP tunnel listening on [{bind_addr}]:{bind_port}")
    
    def setup_tun_interface(self):
        import fcntl
        TUNSETIFF = 0x400454ca
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000
        
        tun_name = self.config['tunnel']['interface_name']
        
        self.tun_fd = os.open('/dev/net/tun', os.O_RDWR)
        
        ifr = struct.pack('16sH', tun_name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)
        
        self.logger.info(f"TUN interface created: {tun_name}")
        
        os.system(f"ip link set {tun_name} up")
        os.system(f"ip addr add {self.config['tunnel']['tun_ipv4']}/24 dev {tun_name}")
        os.system(f"ip -6 addr add {self.config['tunnel']['tun_ipv6']}/64 dev {tun_name}")
        os.system(f"ip link set {tun_name} mtu 1400")
        
        os.system("sysctl -w net.ipv4.ip_forward=1")
        os.system("sysctl -w net.ipv6.conf.all.forwarding=1")
        os.system("sysctl -w net.ipv4.conf.all.rp_filter=2")
        
        egress_iface = self.config['server']['egress_interface']
        os.system(f"iptables -t nat -A POSTROUTING -o {egress_iface} -j MASQUERADE")
        
        enable_ipv6_nat = self.config['server'].get('enable_ipv6_nat', False)
        if enable_ipv6_nat:
            result = os.system(f"ip6tables -t nat -A POSTROUTING -o {egress_iface} -j MASQUERADE 2>/dev/null")
            if result == 0:
                self.logger.info("IPv6 NAT configured")
            else:
                self.logger.warning("IPv6 NAT not available, skipping")
        
        self.logger.info("IP forwarding and NAT configured")

    def _add_prefix_peer(self, subnet: str, peer_key: str):
        """记录 '某个 overlay 子网' 由哪个 peer 承载。"""
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            self.overlay_prefix_to_peer[net] = peer_key
            self.logger.info(f"[PREFIX] {net} -> {peer_key}")
        except Exception as e:
            self.logger.error(f"[PREFIX] failed to add {subnet} for {peer_key}: {e}")

    def _lookup_peer_for_ip(self, ip_str: str) -> Optional[str]:
        """根据目的 IP，在所有已知子网里找匹配的 peer。"""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except Exception:
            return None

        for net, peer_key in self.overlay_prefix_to_peer.items():
            if ip_obj.version == net.version and ip_obj in net:
                return peer_key
        return None

    def _remove_prefixes_for_subnets(self, subnets: list):
        """根据子网字符串列表，从 prefix 表里删掉对应项。"""
        for s in subnets:
            try:
                net = ipaddress.ip_network(s, strict=False)
                if net in self.overlay_prefix_to_peer:
                    self.overlay_prefix_to_peer.pop(net, None)
                    self.logger.info(f"[PREFIX] removed mapping for {net}")
            except Exception:
                continue

    def _cleanup_ip_peers_for_subnets(self, subnets: list):
        """把 overlay_ip_to_peer 中属于这些子网的 IP 全部清理掉（旧路由器收到 deactivation 时用）。"""
        nets = []
        for s in subnets:
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
            except Exception:
                continue

        to_delete = []
        for ip_str in list(self.overlay_ip_to_peer.keys()):
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except Exception:
                continue

            if any(ip_obj in n for n in nets):
                to_delete.append(ip_str)

        for ip_str in to_delete:
            self.overlay_ip_to_peer.pop(ip_str, None)

        if to_delete:
            self.logger.info(f"[PREFIX] cleaned {len(to_delete)} per-IP peers in old subnets")


    def _extract_source_ip(self, packet: bytes) -> Optional[str]:
        try:
            if len(packet) < 20:
                return None
            version = packet[0] >> 4
            if version == 4:
                return '.'.join(str(b) for b in packet[12:16])
            elif version == 6 and len(packet) >= 40:
                import ipaddress
                return str(ipaddress.IPv6Address(packet[8:24]))
        except:
            pass
        return None

    def _process_ip_alloc_async(self, addr, req):
        """在后台线程里跑 IP 分配 + 回复，不阻塞主收包线程"""
        try:
            self.logger.info(f"[IP-ALLOC] async handling for {req.endpoint_id}")
            alloc = self.handle_ip_allocation_request(
                endpoint_id=req.endpoint_id,
                reconnect=req.reconnect,
                previous_subnet=req.previous_subnet
            )

            if not self.running:
                return

            if alloc:
                resp_payload = ControlProtocol.encode_ip_alloc_response(alloc)
                reply = self.tunnel_protocol.encapsulate(
                    resp_payload,
                    msg_type=MessageType.IP_ALLOC_RESPONSE
                )
                self.udp_socket.sendto(reply, addr)
                self.logger.info(
                    f"[IP-ALLOC] resp sent to {req.endpoint_id}: {alloc.subnet_ipv4}"
                )
            else:
                self.logger.error(f"[IP-ALLOC] failed for {req.endpoint_id}")

        except Exception as e:
            self.logger.error(f"[IP-ALLOC] async handler error: {e}")
    def receive_from_tunnel(self):
        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(65535)
                self.stats['rx_packets'] += 1
                self.stats['rx_bytes'] += len(data)

                packet = self.tunnel_protocol.decapsulate(data)
                if not packet:
                    self.logger.warning(f"Invalid packet from {addr}")
                    continue

                peer_key = f"{addr[0]}:{addr[1]}"
                self.active_peers[peer_key] = {
                    'addr': addr,
                    'last_seen': time.time(),
                    'tunnel_id': packet.tunnel_id
                }

                # ====== 数据包：写进 TUN，走内核转发 ======
                if packet.msg_type == MessageType.DATA:
                    src_ip = self._extract_source_ip(packet.payload)
                    if src_ip:
                        # 记录“这个 overlay IP 来自哪个 peer”，用于回程选择隧道
                        self.overlay_ip_to_peer[src_ip] = peer_key

                    os.write(self.tun_fd, packet.payload)

                # ====== 保活包：直接回一个 KEEPALIVE ======
                elif packet.msg_type == MessageType.KEEPALIVE:
                    keepalive_response = self.tunnel_protocol.create_keepalive()
                    self.udp_socket.sendto(keepalive_response, addr)

                # ====== 路由通告：NAE 通告自己的子网，比如 10.100.0.0/24 ======
                elif packet.msg_type == MessageType.ROUTE_ADVERTISEMENT:
                    try:
                        from common.control_protocol import ControlProtocol
                        adv = ControlProtocol.decode_route_advertisement(packet.payload)
                        self.logger.info(
                            f"ROUTE-ADV from {adv.endpoint_id}: "
                            f"IPv4={adv.routes_ipv4}, IPv6={adv.routes_ipv6}"
                        )
                        self.handle_route_advertisement(
                            adv.endpoint_id,
                            adv.routes_ipv4,
                            adv.routes_ipv6,
                            peer_key=peer_key,
                        )
                    except Exception as e:
                        self.logger.error(f"ROUTE-ADV handler error: {e}")

                # ====== IP 分配请求：NAE 向 router 请求 overlay 子网 ======
                elif packet.msg_type == MessageType.IP_ALLOC_REQUEST:
                    try:
                        from common.control_protocol import ControlProtocol
                        req = ControlProtocol.decode_ip_alloc_request(packet.payload)
                        self.logger.info(f"IP-ALLOC req from {req.endpoint_id} (async)")

                        # 丢给后台线程处理，主线程立刻返回继续收 DATA
                        threading.Thread(
                            target=self._process_ip_alloc_async,
                            args=(addr, req),
                            daemon=True
                        ).start()

                    except Exception as e:
                        self.logger.error(f"IP-ALLOC handler error: {e}")

                elif packet.msg_type == MessageType.ENDPOINT_ACTIVATION:
                    try:
                        from common.control_protocol import ControlProtocol, EndpointActivation
                        act = ControlProtocol.decode_endpoint_activation(packet.payload)
                        self.logger.info(
                            f"ACT from {act.endpoint_id}: active={act.active}, "
                            f"prev={act.previous_router_id}@{act.previous_router_ip}"
                        )
                        if act.active:
                            self.handle_activation_from_endpoint(act, addr, peer_key)
                            try:
                                ack_packet = self.tunnel_protocol.encapsulate(
                                    b"",  # ACK 不需要负载
                                    MessageType.ACTIVATION_ACK,
                                )
                                self.udp_socket.sendto(ack_packet, addr)
                                self.logger.info(
                                    f"[ACT-ACK] sent activation ACK to {act.endpoint_id} at {addr}"
                                )
                            except Exception as e:
                                self.logger.error(f"[ACT-ACK] failed to send ACK: {e}")
                        else:
                            # 旧路由器清理路由
                            self.handle_deactivation_from_router(act)
                            try:
                                # ★ 在 ACK payload 里带上同一个 EndpointActivation，至少包含 endpoint_id
                                ack_payload = ControlProtocol.encode_endpoint_activation(act)
                                ack_pkt = self.tunnel_protocol.encapsulate(
                                    ack_payload,
                                    msg_type=MessageType.DEACTIVATION_ACK,
                                )
                                self.udp_socket.sendto(ack_pkt, addr)
                                self.logger.info(
                                    f"[DEACT-ACK] sent DEACTIVATION_ACK for {act.endpoint_id} back to {addr}"
                                )
                            except Exception as e:
                                self.logger.error(f"[DEACT-ACK] failed to send ACK: {e}")
                    except Exception as e:
                        self.logger.error(f"ACT handler error: {e}")
                elif packet.msg_type == MessageType.ACTIVATION_ACK:
                    # 路由器自己目前对 ACTIVATION_ACK 只是打日志
                    self.logger.info(f"[ACT-ACK] received ACTIVATION_ACK from {addr}")

                elif packet.msg_type == MessageType.DEACTIVATION_ACK:
                    # ★ 收到旧路由器的去激活 ACK：需要标记 pending_deactivations 里的任务为 acked
                    try:
                        from common.control_protocol import ControlProtocol, EndpointActivation
                        ack_act = ControlProtocol.decode_endpoint_activation(packet.payload)
                        endpoint_id = ack_act.endpoint_id  # e.g. "endpoint_1"
                        peer_ip = addr[0]  # 发送 ACK 的那台旧路由器的 IP

                        self.logger.info(
                            f"[DEACT-ACK] received DEACTIVATION_ACK for endpoint {endpoint_id} from {addr}"
                        )

                        # 用 (endpoint_id, 对端 IP) 作为 key，标记这条去激活任务已确认
                        self._mark_deactivation_ack_received(endpoint_id, peer_ip)

                    except Exception as e:
                        self.logger.error(f"[DEACT-ACK] handler error: {e}")
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error receiving from tunnel: {e}")

    def _mark_deactivation_ack_received(self, endpoint_id: str, peer_ip: str):
        """收到旧路由器的 DEACTIVATION_ACK 时，标记对应任务为已确认。"""
        key = (endpoint_id, peer_ip)
        with self.deactivation_lock:
            info = self.pending_deactivations.get(key)
            if info:
                info['acked'] = True
                self.logger.info(
                    f"[DEACT-ACK] deactivation for {endpoint_id} "
                    f"at [{peer_ip}] marked as ACKed"
                )
            else:
                # 没找到说明可能已经超时移除，打个 debug 即可
                self.logger.debug(
                    f"[DEACT-ACK] no pending deactivation found for "
                    f"{endpoint_id}@[{peer_ip}]"
                )

    def handle_activation_from_endpoint(
        self,
        act: EndpointActivation,
        addr,
        peer_key: str,
    ):
        """
        新路由器收到 active=True：
        - 根据 routes_ipv4/6 添加静态路由
        - 在 prefix 表里记录“这些子网 -> 当前 peer”
        - 如 previous_router_ip 不为空，则发 deactivation 给旧路由器
        """
        try:
            self.logger.info(
                f"[ACT] activate {act.endpoint_id} "
                f"routes_v4={act.routes_ipv4}, routes_v6={act.routes_ipv6}, "
                f"from peer={peer_key}"
            )

            # 1) 直接复用 route advertisement 逻辑
            self.handle_route_advertisement(
                act.endpoint_id,
                act.routes_ipv4 or [],
                act.routes_ipv6 or [],
                peer_key=peer_key,
            )

            my_id = self.config['server']['server_id']

            # 2) 如果有旧路由器，单播一个 active=False 通知它清理
            if (
                    act.previous_router_ip
                    and act.previous_router_id
                    and act.previous_router_id != my_id
            ):
                deact = EndpointActivation(
                    endpoint_id=act.endpoint_id,
                    routes_ipv4=act.routes_ipv4 or [],
                    routes_ipv6=act.routes_ipv6 or [],
                    previous_router_id=my_id,
                    previous_router_ip=None,
                    active=False,
                    timestamp=0.0,
                )
                # ★ 启动带重试的去激活流程
                self._start_deactivation_retry(
                    deact,
                    previous_router_ip=act.previous_router_ip,
                    previous_router_id=act.previous_router_id,
                )

            elif act.previous_router_ip and act.previous_router_id == my_id:
                # 同一台路由器上隧道切换：只更新 prefix->peer，不做 deactivation
                self.logger.info(
                    f"[ACT] previous router is myself ({my_id}), "
                    f"treat as WAN/tunnel switch, skip deactivation"
                )

        except Exception as e:
            self.logger.error(f"[ACT] activation handler error: {e}")

    def _start_deactivation_retry(
        self,
        deact: EndpointActivation,
        previous_router_ip: str,
        previous_router_id: str,
    ):
        """
        在“新路由器”侧注册一条去激活任务，并立刻发送第一次 deactivation。
        后续重试由 deactivation_retry_loop 统一处理。
        """
        bind_port = self.config['server']['bind_port']
        addr = (previous_router_ip, bind_port)

        payload = ControlProtocol.encode_endpoint_activation(deact)
        packet = self.tunnel_protocol.encapsulate(
            payload,
            msg_type=MessageType.ENDPOINT_ACTIVATION,
        )

        key = (deact.endpoint_id, previous_router_ip)
        now = time.time()

        # 先试着发一次
        try:
            self.udp_socket.sendto(packet, addr)
            attempts = 1
            self.logger.info(
                f"[ACT] sent deactivation (attempt 1/{self.deactivation_max_retries}) "
                f"of {deact.endpoint_id} to "
                f"{previous_router_id}@[{previous_router_ip}]:{bind_port}"
            )
        except Exception as e:
            attempts = 1
            self.logger.error(
                f"[ACT] failed to send deactivation of {deact.endpoint_id} to "
                f"{previous_router_id}@[{previous_router_ip}]:{bind_port}: {e}"
            )

        # 写入 pending 表，等待 ACK 或后续重试
        with self.deactivation_lock:
            self.pending_deactivations[key] = {
                'packet': packet,
                'addr': addr,
                'attempts': attempts,
                'last_sent': now,
                'acked': False,
            }


    def handle_deactivation_from_router(self, act: EndpointActivation):
        """
        旧路由器收到 active=False：
        - 删除对应的静态路由
        - 清除 routing_table 中这些前缀
        - 清空相应子网的 prefix 映射 & 单 IP 映射
        """
        try:
            tun_name = self.config['tunnel']['interface_name']
            removed = 0

            for route in act.routes_ipv4 or []:
                os.system(f"ip route del {route} dev {tun_name} 2>/dev/null")
                if route in self.routing_table:
                    self.routing_table.pop(route, None)
                    removed += 1

            for route in act.routes_ipv6 or []:
                os.system(f"ip -6 route del {route} dev {tun_name} 2>/dev/null")
                if route in self.routing_table:
                    self.routing_table.pop(route, None)
                    removed += 1

            all_subnets = (act.routes_ipv4 or []) + (act.routes_ipv6 or [])
            self._remove_prefixes_for_subnets(all_subnets)
            self._cleanup_ip_peers_for_subnets(all_subnets)

            self.logger.info(
                f"[ACT] deactivated {act.endpoint_id}, removed {removed} routes"
            )
        except Exception as e:
            self.logger.error(f"[ACT] deactivation handler error: {e}")


    def _extract_dest_ip(self, packet: bytes) -> Optional[str]:
        try:
            if len(packet) < 20:
                return None
            version = packet[0] >> 4
            if version == 4:
                return '.'.join(str(b) for b in packet[16:20])
            elif version == 6 and len(packet) >= 40:
                import ipaddress
                return str(ipaddress.IPv6Address(packet[24:40]))
        except:
            pass
        return None

    def send_to_tunnel(self):
        while self.running:
            try:
                packet = os.read(self.tun_fd, 65535)
                if not packet:
                    continue

                is_ipv6 = (packet[0] >> 4) == 6
                encapsulated = self.tunnel_protocol.encapsulate(packet, is_ipv6=is_ipv6)

                dst_ip = self._extract_dest_ip(packet)

                peer_key = None
                if dst_ip:
                    # ★ 通过 IP 所在的子网找到 peer
                    peer_key = self._lookup_peer_for_ip(dst_ip)
                # ========== 有映射：单播 ==========
                if peer_key and peer_key in self.active_peers:
                    pinfo = self.active_peers[peer_key]
                    if time.time() - pinfo['last_seen'] < self.peer_timeout:
                        addr = pinfo['addr']
                        self.udp_socket.sendto(encapsulated, addr)
                        self.stats['tx_packets'] += 1
                        self.stats['tx_bytes'] += len(encapsulated)
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error sending to tunnel: {e}")

    def handle_ip_allocation_request(self, endpoint_id: str, reconnect: bool = False,
                                     previous_subnet: Optional[str] = None) -> Optional[IPAllocationResponse]:
        """Proxy IP allocation request to network controller"""
        try:
            controller_url = self.config.get('network_controller', {}).get('url')
            if not controller_url:
                self.logger.error("Network controller URL not configured")
                return None
            
            request = IPAllocationRequest(
                endpoint_id=endpoint_id,
                reconnect=reconnect,
                previous_subnet=previous_subnet
            )
            
            response = requests.post(
                f"{controller_url}/allocate_ip",
                json={'endpoint_id': endpoint_id, 'reconnect': reconnect, 'previous_subnet': previous_subnet},
                timeout=10
            )
            
            if response.status_code == 200:
                response_data = response.json()
                allocation_response = IPAllocationResponse(**response_data)
                
                if allocation_response.success:
                    self.endpoint_allocations[endpoint_id] = allocation_response
                    self.logger.info(
                        f"Allocated subnet for {endpoint_id}: "
                        f"IPv4={allocation_response.subnet_ipv4}, IPv6={allocation_response.subnet_ipv6}"
                    )
                
                return allocation_response
            else:
                self.logger.error(f"Failed to allocate IP for {endpoint_id}: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error proxying IP allocation request: {e}")
            return None

    def handle_route_advertisement(
            self,
            endpoint_id: str,
            routes_ipv4: list,
            routes_ipv6: list,
            peer_key: Optional[str] = None,  # ★ 新增参数
    ):
        """Handle route advertisement from endpoint"""
        try:
            tun_name = self.config['tunnel']['interface_name']

            for route in routes_ipv4:
                self.routing_table[route] = {
                    'endpoint_id': endpoint_id,
                    'next_hop': endpoint_id,
                    'metric': 1,
                    'timestamp': time.time()
                }
                os.system(f"ip route add {route} dev {tun_name} 2>/dev/null")
                if peer_key:
                    self._add_prefix_peer(route, peer_key)

            for route in routes_ipv6:
                self.routing_table[route] = {
                    'endpoint_id': endpoint_id,
                    'next_hop': endpoint_id,
                    'metric': 1,
                    'timestamp': time.time()
                }
                os.system(f"ip -6 route add {route} dev {tun_name} 2>/dev/null")
                if peer_key:
                    self._add_prefix_peer(route, peer_key)

            self.logger.info(
                f"Added routes for {endpoint_id}: "
                f"IPv4={routes_ipv4}, IPv6={routes_ipv6}, peer={peer_key}"
            )

            self.exchange_routes_with_peers()

        except Exception as e:
            self.logger.error(f"Error handling route advertisement: {e}")


        except Exception as e:
            self.logger.error(f"Error handling route advertisement: {e}")
    
    def exchange_routes_with_peers(self):
        """Exchange routing information with peer routers (distributed protocol)"""
        try:
            peer_routers = self.config.get('peer_routers', [])
            if not peer_routers:
                return
            
            update = RouterUpdate(
                router_id=self.config['server']['server_id'],
                routes=self.routing_table,
                sequence=int(time.time())
            )
            
            for peer in peer_routers:
                try:
                    peer_url = peer.get('url')
                    if peer_url:
                        requests.post(
                            f"{peer_url}/router_update",
                            json={'router_id': update.router_id, 'routes': update.routes, 'sequence': update.sequence},
                            timeout=5
                        )
                except Exception as e:
                    self.logger.debug(f"Failed to exchange routes with peer {peer.get('router_id')}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error exchanging routes with peers: {e}")
    
    def cleanup_stale_peers(self):
        while self.running:
            try:
                time.sleep(10)
                current_time = time.time()
                stale_peers = [
                    peer_key for peer_key, info in self.active_peers.items()
                    if current_time - info['last_seen'] > self.peer_timeout
                ]
                for peer_key in stale_peers:
                    del self.active_peers[peer_key]
                    self.logger.info(f"Removed stale peer: {peer_key}")
            except Exception as e:
                self.logger.error(f"Error cleaning up peers: {e}")
    
    def collect_metrics(self) -> Dict:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        net_io = psutil.net_io_counters()
        
        time_elapsed = time.time() - self.stats['last_reset']
        if time_elapsed > 0:
            bandwidth_mbps = (self.stats['tx_bytes'] * 8) / (time_elapsed * 1_000_000)
        else:
            bandwidth_mbps = 0
        
        active_tunnels = len([
            p for p in self.active_peers.values()
            if time.time() - p['last_seen'] < self.peer_timeout
        ])
        
        metrics = {
            'server_id': self.config['server']['server_id'],
            'server_name': self.config['server']['name'],
            'timestamp': time.time(),
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'bandwidth_mbps': bandwidth_mbps,
            'active_tunnels': active_tunnels,
            'total_rx_packets': self.stats['rx_packets'],
            'total_tx_packets': self.stats['tx_packets'],
            'internal_ip': self.config['server']['internal_ip'],
            'external_ip': self.config['server']['external_ip']
        }
        
        return metrics

    def deactivation_retry_loop(self):
        """后台线程：对未确认的 deactivation 进行重发，直到 ACK 或超出重试次数。"""
        while self.running:
            time.sleep(self.deactivation_retry_interval)
            now = time.time()

            with self.deactivation_lock:
                keys_to_delete = []

                for key, info in self.pending_deactivations.items():
                    endpoint_id, peer_ip = key

                    if info.get('acked'):
                        # 已收到 ACK，清理
                        self.logger.info(
                            f"[ACT] deactivation for {endpoint_id}@[{peer_ip}] "
                            f"ACKed, stop retrying"
                        )
                        keys_to_delete.append(key)
                        continue

                    attempts = info.get('attempts', 0)
                    last_sent = info.get('last_sent', 0)

                    if attempts >= self.deactivation_max_retries:
                        self.logger.error(
                            f"[ACT] deactivation for {endpoint_id}@[{peer_ip}] "
                            f"failed: no ACK after {attempts} attempts"
                        )
                        keys_to_delete.append(key)
                        continue

                    # 到了下一次重发的时间
                    if now - last_sent >= self.deactivation_retry_interval:
                        try:
                            self.udp_socket.sendto(info['packet'], info['addr'])
                            info['attempts'] = attempts + 1
                            info['last_sent'] = now
                            self.logger.warning(
                                f"[ACT] resend deactivation for {endpoint_id}@[{peer_ip}], "
                                f"attempt {info['attempts']}/{self.deactivation_max_retries}"
                            )
                        except Exception as e:
                            self.logger.error(
                                f"[ACT] resend deactivation for {endpoint_id}@[{peer_ip}] "
                                f"failed: {e}"
                            )

                # 真正删除已完成/失败的任务
                for key in keys_to_delete:
                    self.pending_deactivations.pop(key, None)

    
    def report_metrics(self):
        while self.running:
            try:
                time.sleep(self.config['metrics']['report_interval'])
                
                metrics = self.collect_metrics()
                
                lb_url = self.config['load_balancer']['url']
                response = requests.post(
                    f"{lb_url}/metrics",
                    json=metrics,
                    timeout=5
                )
                
                if response.status_code == 200:
                    self.logger.debug(f"Metrics reported successfully")
                else:
                    self.logger.warning(f"Failed to report metrics: {response.status_code}")
                
                self.stats['last_reset'] = time.time()
                self.stats['rx_bytes'] = 0
                self.stats['tx_bytes'] = 0
                
            except Exception as e:
                self.logger.error(f"Error reporting metrics: {e}")
    
    def start(self):
        self.running = True
        
        self.setup_tunnel_socket()
        self.setup_tun_interface()
        
        threads = [
            threading.Thread(target=self.receive_from_tunnel, daemon=True),
            threading.Thread(target=self.send_to_tunnel, daemon=True),
            threading.Thread(target=self.cleanup_stale_peers, daemon=True),
            threading.Thread(target=self.report_metrics, daemon=True),
            threading.Thread(target=self.deactivation_retry_loop, daemon=True),
        ]
        
        for thread in threads:
            thread.start()
        
        self.logger.info("Routing server started")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.stop()
    
    def stop(self):
        self.running = False
        if self.udp_socket:
            self.udp_socket.close()
        if self.tun_fd:
            os.close(self.tun_fd)


def main():
    if os.geteuid() != 0:
        print("ERROR: This program must be run as root (for TUN device and network configuration)")
        print("Please run with: sudo python3 " + sys.argv[0])
        sys.exit(1)
    
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <config_file>")
        sys.exit(1)
    
    config_path = sys.argv[1]
    server = RoutingServer(config_path)
    server.start()


if __name__ == '__main__':
    main()
