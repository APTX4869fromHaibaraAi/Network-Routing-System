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
from typing import Dict, Optional
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from common.tunnel_protocol import TunnelProtocol, MessageType
from common.control_protocol import (
    IPAllocationRequest, IPAllocationResponse,
    RouteAdvertisement, RouterUpdate, ControlProtocol
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
        
        self.endpoint_allocations = {}
        self.routing_table = {}
        self.peer_routers = {}
        
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
                            adv.routes_ipv6
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

                    except Exception as e:
                        self.logger.error(f"IP-ALLOC handler error: {e}")

                # （如果以后还有其它控制类型，可以继续往下 elif）

            except Exception as e:
                if self.running:
                    self.logger.error(f"Error receiving from tunnel: {e}")
    
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

                # ========== 有映射：单播 ==========
                if dst_ip and dst_ip in self.overlay_ip_to_peer:
                    peer_key = self.overlay_ip_to_peer[dst_ip]
                    if peer_key in self.active_peers:
                        peer_info = self.active_peers[peer_key]
                        if time.time() - peer_info['last_seen'] < self.peer_timeout:
                            addr = peer_info['addr']
                            tunnel_id = peer_info.get('tunnel_id')

                            # 先打日志再发也行，发完再打也行，这里先打

                            self.udp_socket.sendto(encapsulated, addr)
                            self.stats['tx_packets'] += 1
                            self.stats['tx_bytes'] += len(encapsulated)

                # ========== 没映射：广播 ==========
                else:
                    now = time.time()
                    for pk, pinfo in self.active_peers.items():
                        if now - pinfo['last_seen'] < self.peer_timeout:
                            addr = pinfo['addr']
                            tunnel_id = pinfo.get('tunnel_id')

                            # 可选：广播时也打一下具体发给谁


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
    
    def handle_route_advertisement(self, endpoint_id: str, routes_ipv4: list, routes_ipv6: list):
        """Handle route advertisement from endpoint"""
        try:
            for route in routes_ipv4:
                self.routing_table[route] = {
                    'endpoint_id': endpoint_id,
                    'next_hop': endpoint_id,
                    'metric': 1,
                    'timestamp': time.time()
                }
                os.system(f"ip route add {route} dev {self.config['tunnel']['interface_name']} 2>/dev/null")
            
            for route in routes_ipv6:
                self.routing_table[route] = {
                    'endpoint_id': endpoint_id,
                    'next_hop': endpoint_id,
                    'metric': 1,
                    'timestamp': time.time()
                }
                os.system(f"ip -6 route add {route} dev {self.config['tunnel']['interface_name']} 2>/dev/null")
            
            self.logger.info(f"Added routes for {endpoint_id}: IPv4={routes_ipv4}, IPv6={routes_ipv6}")
            
            self.exchange_routes_with_peers()
            
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
            threading.Thread(target=self.report_metrics, daemon=True)
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
