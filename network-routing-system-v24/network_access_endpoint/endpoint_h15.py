#!/usr/bin/env python3
"""
Network Access Endpoint (Version 2)
Implements new initialization flow with dynamic IP allocation and primary/backup routing
"""

import sys
import os
import socket
import struct
import threading
import time
import logging
import yaml
import requests
import fcntl
import json
import subprocess
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from common.tunnel_protocol import TunnelProtocol, MessageType
from common.control_protocol import (
    IPAllocationRequest, IPAllocationResponse,
    RouteAdvertisement, ControlProtocol,
    EndpointActivation,
)

@dataclass
class RouterInfo:
    router_id: str
    internal_ip: str
    external_ip: str
    is_primary: bool


class TunnelConnection:
    def __init__(
            self,
            router_info: RouterInfo,
            port: int, protocol: TunnelProtocol,
            bind_address: str = None,
            wan_name: str = None,
    ):
        self.router_info = router_info
        self.port = port
        self.protocol = protocol
        self.bind_address = bind_address
        self.wan_name = wan_name
        
        self.socket = None
        self.connected = False
        self.last_keepalive_sent = 0
        self.last_packet_received = 0
        self.rtt_ms = 0

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.wan_name:
                try:
                    # 25 = SO_BINDTODEVICE（Linux）
                    self.socket.setsockopt(
                        socket.SOL_SOCKET,
                        25,
                        self.wan_name.encode("utf-8") + b"\x00"
                    )
                except Exception as e:
                    logging.warning(
                        f"SO_BINDTODEVICE {self.wan_name} failed for "
                        f"{self.router_info.router_id}: {e}"
                    )

            if self.bind_address:
                self.socket.bind((self.bind_address, 0))

            self.socket.connect((self.router_info.external_ip, self.port))
            self.connected = True
            self.last_keepalive_sent = time.time()
            self.last_packet_received = time.time()
            return True
        except Exception as e:
            logging.error(f"Failed to connect tunnel to {self.router_info.router_id}: {e}")
            return False

    def send_keepalive(self):
        if not self.connected:
            return False
        
        try:
            keepalive = self.protocol.create_keepalive()
            self.socket.send(keepalive)
            self.last_keepalive_sent = time.time()
            return True
        except Exception as e:
            logging.error(f"Failed to send keepalive to {self.router_info.router_id}: {e}")
            logging.error(
                f"[DEBUG] mark tunnel DEAD due to keepalive error: "
                f"router={self.router_info.router_id}, bind={self.bind_address}"
            )
            self.connected = False
            return False
    
    def send_data(self, data: bytes, is_ipv6: bool = False):
        if not self.connected:
            return False
        
        try:
            encapsulated = self.protocol.encapsulate(data, is_ipv6=is_ipv6)
            self.socket.send(encapsulated)
            return True
        except Exception as e:
            logging.error(f"Failed to send data to {self.router_info.router_id}: {e}")
            logging.error(
                f"[DEBUG] mark tunnel DEAD due to send_data error: "
                f"router={self.router_info.router_id}, bind={self.bind_address}"
            )
            self.connected = False
            return False
    
    def send_control_message(self, msg_type: MessageType, payload: bytes):
        if not self.connected:
            return False
        
        try:
            encapsulated = self.protocol.encapsulate(payload, msg_type=msg_type)
            self.socket.send(encapsulated)
            return True
        except Exception as e:
            logging.error(f"Failed to send control message to {self.router_info.router_id}: {e}")
            self.connected = False
            return False

    def receive(self, timeout: float = 0.1) -> Optional[bytes]:
        if not self.connected:
            return None

        try:
            self.socket.settimeout(timeout)
            data = self.socket.recv(65535)
            if not data:
                return None

            packet = self.protocol.decapsulate(data)
            if not packet:
                return None

            # ☆ 只要解包成功，不管类型是 DATA / KEEPALIVE / 控制，都认为隧道是活的
            self.last_packet_received = time.time()

            # 只有 DATA 报文才写入 TUN
            if packet.msg_type == MessageType.DATA:
                return packet.payload

            # 其他类型（KEEPALIVE、IP_ALLOC_RESPONSE 等）这里直接忽略
            return None

        except socket.timeout:
            return None
        except Exception as e:
            logging.error(f"Error receiving data from {self.router_info.router_id}: {e}")
            self.connected = False
            return None

    def is_alive(self, timeout: float = 15) -> bool:
        if not self.connected:
            return False
        
        if time.time() - self.last_packet_received > timeout:
            return False
        
        return True
    
    def close(self):
        if self.socket:
            self.socket.close()
        self.connected = False


class NetworkAccessEndpoint:
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.setup_logging()

        endpoint_cfg = self.config.get("endpoint", {})
        self.endpoint_id = endpoint_cfg.get("endpoint_id", "endpoint_1")
        self.wan_interfaces = endpoint_cfg.get("wan_interfaces", [])
        self._init_wan_addresses()
        self.router_tunnels: Dict[str, Dict[str, TunnelConnection]] = {}
        # 记录各 WAN 接口上一次的链路状态（UP / DOWN），用于检测“状态变化”
        self.wan_status = {}
        self.wan_down_since = {}
        self.wan_last_retry = {}
        self.wan_monitor_proc = None

        for wan in self.wan_interfaces:
            name = wan.get("name")
            if not name:
                continue
            up = self.is_interface_up(name)
            self.wan_status[name] = up
            self.wan_down_since[name] = None
            self.wan_last_retry[name] = 0.0
            self.logger.info(
                f"WAN interface {name} initial state: {'UP' if up else 'DOWN'}"
            )
        # Router selection (as decided by the load balancer)
        self.primary_router_id: Optional[str] = None
        self.backup_router_id: Optional[str] = None
        self.active_router_id: Optional[str] = None
        
        # Convenience pointers to currently preferred tunnels
        self.primary_tunnel: Optional[TunnelConnection] = None
        self.backup_tunnel: Optional[TunnelConnection] = None
        self.active_tunnel: Optional[TunnelConnection] = None
        self.tunnel_lock = threading.Lock()

        self.allocated_subnet_ipv4 = None
        self.allocated_subnet_ipv6 = None
        self.gateway_ipv4 = None
        self.gateway_ipv6 = None
        
        self.tun_fd = None
        self.running = False
        
        self.logger.info(f"Network access endpoint initialized: {self.endpoint_id}")
    
    def setup_logging(self):
        log_dir = "/var/log"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        log_file = self.config['endpoint'].get('log_file', f"/var/log/network_access_endpoint_{int(time.time())}.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - NetworkAccessEndpoint - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger("NetworkAccessEndpoint")
    def get_interface_ipv6(self, ifname: str) -> Optional[str]:
        """检测指定网口的第一个全局 IPv6 地址（例如 2001:...）。"""
        try:
            result = subprocess.run(
                ["ip", "-6", "addr", "show", "dev", ifname],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet6 ") and "scope global" in line:
                    # 形如 "inet6 2001:da8:.../64 scope global ..."
                    addr = line.split()[1]  # 取 "2001:.../64"
                    return addr.split("/")[0]
            self.logger.warning(f"No global IPv6 address found for interface {ifname}")
        except Exception as e:
            self.logger.error(f"Failed to get IPv6 address for {ifname}: {e}")
        return None

    def is_interface_up(self, ifname: str) -> bool:
        """检测指定网口在 OS 层面是否是 UP 状态。"""
        # 优先读 /sys/class/net/<ifname>/operstate
        path = f"/sys/class/net/{ifname}/operstate"
        try:
            with open(path, "r") as f:
                state = f.read().strip().lower()
            return state == "up"
        except Exception:
            # 退而求其次，使用 `ip link show`
            try:
                result = subprocess.run(
                    ["ip", "link", "show", "dev", ifname],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if "state UP" in result.stdout:
                    return True
                first_line = result.stdout.splitlines()[0] if result.stdout else ""
                return "<UP," in first_line or "UP>" in first_line
            except Exception as e:
                self.logger.error(f"Failed to check interface state for {ifname}: {e}")
                # 检测不了时，保守认为是 up，避免误杀
                return True

    def _init_wan_addresses(self):
        """把每个 WAN 接口的 ipv6 字段填满：优先配置，其次自动探测。"""
        if not self.wan_interfaces:
            return

        new_list = []
        for wan in self.wan_interfaces:
            name = wan.get("name")
            if not name:
                continue
            cfg_ipv6 = wan.get("ipv6")
            ipv6 = cfg_ipv6 or self.get_interface_ipv6(name)
            entry = dict(wan)
            if ipv6:
                entry["ipv6"] = ipv6
                if not cfg_ipv6:
                    self.logger.info(f"Detected IPv6 {ipv6} for WAN interface {name}")
                else:
                    self.logger.info(f"Using configured IPv6 {ipv6} for WAN interface {name}")
            else:
                self.logger.warning(
                    f"No IPv6 address available for WAN interface {name}; "
                    f"no tunnel will be built on it"
                )
            new_list.append(entry)
        self.wan_interfaces = new_list
    def discover_load_balancer(self) -> Optional[str]:
        """Step 1: Discover load balancer address"""
        try:
            lb_config = self.config.get('load_balancer', {})
            
            if 'url' in lb_config and lb_config['url']:
                return lb_config['url']
            
            if 'dns_name' in lb_config and lb_config['dns_name']:
                domain = lb_config['dns_name']
            else:
                domain = "lb.network.local"
            
            # Try reading from environment variable first
            lb_url = os.environ.get("LOAD_BALANCER_URL")
            if lb_url:
                self.logger.info(f"Using load balancer URL from environment: {lb_url}")
                return lb_url
            
            self.logger.info(f"Discovering load balancer via DNS: {domain}")
            return f"http://{domain}:8080"
            
        except Exception as e:
            self.logger.error(f"Failed to discover load balancer: {e}")
            return None
    
    def query_router_info(self, lb_url: str) -> Tuple[Optional[RouterInfo], Optional[RouterInfo], Optional[RouterInfo]]:
        """Step 2: Query primary and backup router info from load balancer"""
        try:
            response = requests.get(
                f"{lb_url}/decision/{self.endpoint_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                decision = response.json()
                
                primary = RouterInfo(
                    router_id=decision['primary_router_id'],
                    internal_ip=decision['primary_router_internal_ip'],
                    external_ip=decision['primary_router_external_ip'],
                    is_primary=True
                )
                
                backup = RouterInfo(
                    router_id=decision['backup_router_id'],
                    internal_ip=decision['backup_router_internal_ip'],
                    external_ip=decision['backup_router_external_ip'],
                    is_primary=False
                )

                prev_router = None
                prev_id = decision.get('previous_primary_router_id')
                prev_internal = decision.get('previous_primary_router_internal_ip')
                prev_external = decision.get('previous_primary_router_external_ip')
                if prev_id and prev_external:
                    prev_router = RouterInfo(
                        router_id=prev_id,
                        internal_ip=prev_internal or "",
                        external_ip=prev_external,
                        is_primary=True  # 这里的 is_primary 只是个标记，实际不用
                    )
                
                self.logger.info(
                    f"Received router decision: primary={primary.router_id}, backup={backup.router_id}"
                )
                
                return primary, backup, prev_router
            
            self.logger.error(f"Load balancer returned status {response.status_code}")
            return None, None, None
                
        except Exception as e:
            self.logger.error(f"Error querying router info: {e}")
            return None, None, None

    def establish_tunnels(self, primary_router: RouterInfo, backup_router: RouterInfo) -> bool:
        """
        建立隧道：对每个路由器、对每个 WAN 接口，各建一条隧道。

        - 配置文件 endpoint.wan_interfaces 里有几个 WAN，就建几条隧道：
            wan0 -> RS.wan0
            wan1 -> RS.wan0
            ...
        - 隧道之间没有“主 / 备”之分，只是运行时会挑一条“当前使用”的。
        """
        try:
            psk = self.config["tunnel"]["psk"]
            tunnel_port = self.config["tunnel"]["port"]

            wan_interfaces = self.wan_interfaces or []
            if not wan_interfaces:
                self.logger.error("No WAN interfaces configured in endpoint.wan_interfaces")
                return False

            # 1) 清理旧隧道
            with self.tunnel_lock:
                for tunnels in self.router_tunnels.values():
                    for t in tunnels.values():
                        if t:
                            t.close()
                self.router_tunnels.clear()
                self.primary_tunnel = None
                self.backup_tunnel = None
                self.active_tunnel = None

            # 2) 记录当前逻辑上的主/备路由器（来自负载均衡器）
            self.primary_router_id = primary_router.router_id if primary_router else None
            self.backup_router_id = backup_router.router_id if backup_router else None

            # 为不同隧道生成唯一的 tunnel_id
            try:
                base_id = int(self.endpoint_id.split("_")[1]) * 100
            except Exception:
                base_id = 1000  # 防御式 fallback

            def _create_tunnel(
                    router: RouterInfo,
                    wan_name: str,
                    bind_addr: Optional[str],
                    tunnel_id_offset: int,
            ) -> Optional[TunnelConnection]:
                """真正创建单条隧道的帮助函数（隧道之间平权）"""
                if router is None or bind_addr is None:
                    return None

                protocol = TunnelProtocol(psk=psk, tunnel_id=base_id + tunnel_id_offset)
                conn = TunnelConnection(
                    router_info=router,
                    port=tunnel_port,
                    protocol=protocol,
                    bind_address=bind_addr,
                    wan_name=wan_name,
                )
                if conn.connect():
                    self.logger.info(
                        f"Established tunnel to {router.router_id} via {wan_name} ({bind_addr})"
                    )
                    return conn
                else:
                    self.logger.error(
                        f"Failed to establish tunnel to {router.router_id} via {wan_name} ({bind_addr})"
                    )
                    return None

            # 3) 准备要建立的所有隧道：
            #    对 primary_router 和 backup_router，各自枚举所有 WAN
            router_defs = []  # (router, wan_name, bind_addr, offset)
            offset = 0

            for router in (primary_router, backup_router):
                if not router:
                    continue
                for wan in wan_interfaces:
                    wan_name = wan.get("name")
                    bind_addr = wan.get("ipv6")
                    if not wan_name or not bind_addr:
                        continue
                    router_defs.append((router, wan_name, bind_addr, offset))
                    offset += 1

            any_success = False

            with self.tunnel_lock:
                # 4) 按定义逐个建立隧道
                for router, wan_name, bind_addr, tid_offset in router_defs:
                    conn = _create_tunnel(router, wan_name, bind_addr, tid_offset)
                    if not conn:
                        continue
                    any_success = True
                    rid = router.router_id
                    if rid not in self.router_tunnels:
                        self.router_tunnels[rid] = {}
                    # key 就用 wan 名：wan0 / wan1 / ...
                    self.router_tunnels[rid][wan_name] = conn

                # 5) 为每个路由器选出“当前使用”的隧道：
                #    规则：按配置文件中 wan_interfaces 的顺序，找第一条 is_alive 的。
                def _pick_router_active(rid: Optional[str]) -> Optional[TunnelConnection]:
                    if not rid:
                        return None
                    tunnels = self.router_tunnels.get(rid, {})
                    if not tunnels:
                        return None

                    # 先按配置顺序选
                    for wan in wan_interfaces:
                        name = wan.get("name")
                        if not name:
                            continue
                        t = tunnels.get(name)
                        if t and t.is_alive():
                            return t

                    # 万一配置对不上，就退而求其次：随便找一条活的
                    for t in tunnels.values():
                        if t and t.is_alive():
                            return t
                    return None

                if self.primary_router_id:
                    self.primary_tunnel = _pick_router_active(self.primary_router_id)
                if self.backup_router_id:
                    self.backup_tunnel = _pick_router_active(self.backup_router_id)

                # 6) 全局 active_tunnel：优先用“主路由器”的一条隧道，其次“备路由器”的一条
                self.active_tunnel = self.primary_tunnel or self.backup_tunnel

                if self.active_tunnel:
                    self.active_router_id = self.active_tunnel.router_info.router_id
                    self.logger.info(
                        f"Active tunnel set to router {self.active_router_id} "
                        f"via {self.active_tunnel.bind_address}"
                    )
                else:
                    self.active_router_id = None
                    self.logger.error("No active tunnel could be established")

            return any_success and self.active_tunnel is not None

        except Exception as e:
            self.logger.error(f"Error establishing tunnels: {e}")
            return False

    def _reselect_tunnels_locked(self, reason: str = ""):
        """在已经持有 self.tunnel_lock 的前提下，根据当前状态重新选择
        - self.primary_tunnel / self.backup_tunnel / self.active_tunnel

        注意：
        - 不包含 while/sleep，只在事件或 LB 更新时被调用；
        - 对 WAN 做“软切换”：如果当前 active_tunnel 还健康，则不会仅仅因为
          WAN0 恢复或 LB 更新而从 WAN1 换回 WAN0，除非当前 WAN 本身失效。
        """
        wan_interfaces = self.wan_interfaces or []

        def _pick_router_active(rid: Optional[str]) -> Optional[TunnelConnection]:
            if not rid:
                return None
            tunnels = self.router_tunnels.get(rid, {})
            if not tunnels:
                return None

            # 先按配置顺序，挑“接口是 UP 且隧道活着”的
            for wan in wan_interfaces:
                wname = wan.get("name")
                if not wname:
                    continue
                t = tunnels.get(wname)
                if not t:
                    continue
                if not t.connected:
                    continue
                if not self.wan_status.get(wname, True):
                    continue
                if t.is_alive():
                    return t

            # 退而求其次：随便找一条 connected+alive+所属 WAN 也是 up 的
            for wname, t in tunnels.items():
                if (
                    t
                    and t.connected
                    and self.wan_status.get(wname, True)
                    and t.is_alive()
                ):
                    return t

            return None

        def _wan_name_of_tunnel(t: TunnelConnection) -> str:
            for rid, tunnels in self.router_tunnels.items():
                for wname, tt in tunnels.items():
                    if tt is t:
                        return wname
            return "unknown"

        old_active = self.active_tunnel

        # 1) 先根据当前 primary/backup router 选择对应的“候选隧道”
        new_primary = _pick_router_active(self.primary_router_id)
        new_backup = _pick_router_active(self.backup_router_id)

        if new_primary is not self.primary_tunnel:
            if new_primary:
                self.logger.info(
                    f"[SELECT] primary_tunnel -> "
                    f"{new_primary.router_info.router_id} via {_wan_name_of_tunnel(new_primary)} "
                    f"(reason={reason})"
                )
            else:
                self.logger.warning(
                    f"[SELECT] no available primary_tunnel (reason={reason})"
                )
            self.primary_tunnel = new_primary

        if new_backup is not self.backup_tunnel:
            if new_backup:
                self.logger.info(
                    f"[SELECT] backup_tunnel -> "
                    f"{new_backup.router_info.router_id} via {_wan_name_of_tunnel(new_backup)} "
                    f"(reason={reason})"
                )
            else:
                self.logger.warning(
                    f"[SELECT] no available backup_tunnel (reason={reason})"
                )
            self.backup_tunnel = new_backup

        # 2) 选 active_tunnel：策略很简单——优先 primary，其次 backup
        candidate = None
        if self.primary_tunnel:
            wname = _wan_name_of_tunnel(self.primary_tunnel)
            if (
                self.primary_tunnel.connected
                and self.wan_status.get(wname, True)
                and self.primary_tunnel.is_alive()
            ):
                candidate = self.primary_tunnel

        if candidate is None and self.backup_tunnel:
            wname = _wan_name_of_tunnel(self.backup_tunnel)
            if (
                self.backup_tunnel.connected
                and self.wan_status.get(wname, True)
                and self.backup_tunnel.is_alive()
            ):
                candidate = self.backup_tunnel

        new_active = candidate

        # 3) 对 WAN 做“软切换保护”：
        #    - 如果当前 active_tunnel 还健康（隧道 alive 且 WAN up），
        #    - 并且新候选与当前 active 属于同一个 router，只是 WAN 不同，
        #    → 那么保持现状，不因为 reason=wan*_UP 或 lb_update 强行切回。
        if old_active and new_active and (new_active is not old_active):
            try:
                old_wan = _wan_name_of_tunnel(old_active)
                new_wan = _wan_name_of_tunnel(new_active)
                old_rid = old_active.router_info.router_id
                new_rid = new_active.router_info.router_id

                old_wan_up = self.wan_status.get(old_wan, True)
                if old_active.is_alive() and old_wan_up and old_rid == new_rid:
                    # 当前 active 还健康，且只是“同一个 router 的不同 WAN”切换请求
                    # -> 为了软切换，保持在旧 WAN 上
                    self.logger.info(
                        f"[SELECT] keep active_tunnel on {old_rid}@{old_wan} "
                        f"(reason={reason}, prefer existing healthy WAN over {new_wan})"
                    )
                    return
            except Exception as e:
                self.logger.error(f"[SELECT] soft-switch check failed: {e}")

        # === 后面是原来的切换逻辑 ===
        if new_active is old_active:
            # 没变就啥也不干
            return

        if new_active is None:
            if old_active is not None:
                self.logger.error(
                    f"[SELECT] active_tunnel -> None (from "
                    f"{old_active.router_info.router_id}) (reason={reason})"
                )
            else:
                self.logger.error(
                    f"[SELECT] still no active tunnel (reason={reason})"
                )
            self.active_tunnel = None
            self.active_router_id = None
            return

        # 真正切换 active_tunnel
        self.active_tunnel = new_active
        self.active_router_id = new_active.router_info.router_id
        wname = _wan_name_of_tunnel(new_active)

        self.logger.info(
            f"[SELECT] active_tunnel -> {self.active_router_id} via {wname} "
            f"(reason={reason})"
        )

        # 触发 activation（告诉 RS “谁是当前 active”）
        prev_router = old_active.router_info if old_active else None
        try:
            self.send_activation(previous_router=prev_router)
        except Exception as e:
            self.logger.error(f"Failed to send activation after tunnel switch: {e}")


    def _on_wan_state_event(self, ifname: str, is_up: bool):
        """
        被 WAN 事件线程调用：
        - 更新 self.wan_status[ifname]
        - 对该 WAN 上所有隧道进行 close / reconnect
        - 对 DOWN 事件调用 _reselect_tunnels_locked() 进行切换，
          对 UP 事件只做“重连”，不强行切回当前 active_tunnel。
        """
        # 先在锁内更新状态 / 收集需要处理的隧道，避免长时间持锁
        reconnect_tunnels = []
        bind_ipv6 = None

        with self.tunnel_lock:
            prev_up = self.wan_status.get(ifname)
            if prev_up is None:
                # 不是配置里的 WAN，忽略
                return

            if prev_up == is_up:
                # 状态没变化就不用重复处理
                return

            self.wan_status[ifname] = is_up

            if not is_up:
                # 接口 DOWN：把该接口上的隧道全部关掉，并重新选 active_tunnel
                self.logger.warning(
                    f"[WAN-EVENT] interface {ifname} DOWN, closing its tunnels"
                )
                for rid, tunnels in self.router_tunnels.items():
                    t = tunnels.get(ifname)
                    if t and t.connected:
                        self.logger.warning(
                            f"[WAN-EVENT] closing tunnel to "
                            f"{t.router_info.router_id} on {ifname}"
                        )
                        t.close()

                # 重新选一次 active_tunnel（这里允许从 WAN0 -> WAN1 的硬切换）
                self._reselect_tunnels_locked(
                    reason=f"wan={ifname}_DOWN"
                )
                return

            # 走到这说明是 UP 事件
            self.logger.info(
                f"[WAN-EVENT] interface {ifname} UP, trying to reconnect its tunnels"
            )

            # 优先从配置里拿 IPv6，没有的话尝试自动探测一次
            for wan in self.wan_interfaces or []:
                if wan.get("name") == ifname:
                    bind_ipv6 = wan.get("ipv6")
                    if not bind_ipv6:
                        bind_ipv6 = self.get_interface_ipv6(ifname)
                        wan["ipv6"] = bind_ipv6
                    break

            # 收集该 WAN 上所有需要重连的隧道
            for rid, tunnels in self.router_tunnels.items():
                t = tunnels.get(ifname)
                if not t:
                    continue
                if t.connected:
                    continue
                reconnect_tunnels.append(t)

        # === 锁外执行重连尝试，避免阻塞其他线程 ===
        if not reconnect_tunnels:
            self.logger.info(
                f"[WAN-EVENT] interface {ifname} UP but no tunnels to reconnect"
            )
            return

        if not bind_ipv6:
            self.logger.error(
                f"[WAN-EVENT] interface {ifname} UP but no IPv6 address available, "
                f"skip reconnect"
            )
            return

        max_attempts = 10
        retry_interval = 5.0

        for attempt in range(1, max_attempts + 1):
            all_ok = True
            for t in reconnect_tunnels:
                if t.connected:
                    continue
                all_ok = False
                t.bind_address = bind_ipv6
                try:
                    if t.connect():
                        self.logger.info(
                            f"[WAN-EVENT] reconnected tunnel to "
                            f"{t.router_info.router_id} via {ifname} ({t.bind_address}), "
                            f"attempt {attempt}/{max_attempts}"
                        )
                    else:
                        self.logger.error(
                            f"[WAN-EVENT] connect() returned False for "
                            f"{t.router_info.router_id} via {ifname}, "
                            f"attempt {attempt}/{max_attempts}"
                        )
                except Exception as e:
                    self.logger.error(
                        f"[WAN-EVENT] exception while reconnect tunnel "
                        f"to {t.router_info.router_id} via {ifname} "
                        f"on attempt {attempt}/{max_attempts}: {e}"
                    )

            if all_ok:
                break

            # 还有未连上的隧道，隔一会儿再试
            time.sleep(retry_interval)

        # 注意：UP 事件本身不强制调用 _reselect_tunnels_locked()
        # 软切换策略：只在 WAN DOWN / LB 更新 / 当前 active 挂掉时才重新选 active_tunnel

    def wan_event_monitor_loop(self):
        """
        使用内核 Netlink 监听 WAN 接口的 UP/DOWN 事件，
        不再依赖 `ip monitor link` 子进程。

        - 订阅 RTMGRP_LINK 组
        - 收到 RTM_NEWLINK/RTM_DELLINK 时解析 ifname
        - 只对配置中的 WAN 接口调用 _on_wan_state_event()
        """
        import socket
        import struct
        import os

        # 我们关心的业务 WAN 名称集合（如：{"wan0", "wan1"}）
        wan_names = {
            wan.get("name")
            for wan in (self.wan_interfaces or [])
            if wan.get("name")
        }
        if not wan_names:
            self.logger.info("[WAN-EVENT] no WAN interfaces configured, netlink monitor thread exit")
            return

        # 一些 Netlink / rtnetlink 常量
        # 这些值和内核头文件一致：
        #   include/uapi/linux/rtnetlink.h / if_link.h
        RTM_NEWLINK = 16
        RTM_DELLINK = 17
        IFLA_IFNAME = 3
        RTMGRP_LINK = 1

        NLMSG_HDRLEN = 16
        NLA_HDRLEN = 4

        def _align4(x: int) -> int:
            return (x + 3) & ~3

        # 创建 netlink 套接字
        try:
            nl_sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
        except Exception as e:
            self.logger.error(f"[WAN-EVENT] failed to create netlink socket: {e}")
            return

        try:
            # 订阅 RTMGRP_LINK 组，只收链路事件
            nl_sock.bind((os.getpid(), RTMGRP_LINK))
            # 设置超时，方便 self.running=False 时能及时退出
            nl_sock.settimeout(1.0)
        except Exception as e:
            self.logger.error(f"[WAN-EVENT] failed to bind netlink socket: {e}")
            try:
                nl_sock.close()
            except Exception:
                pass
            return

        self.logger.info(
            f"[WAN-EVENT] started netlink link monitor for: {', '.join(sorted(wan_names))}"
        )

        while self.running:
            try:
                try:
                    data = nl_sock.recv(65535)
                except socket.timeout:
                    # 定期检查 self.running，没事件就继续循环
                    continue

                offset = 0
                data_len = len(data)

                # 一次 recv 里可能有多个 netlink 消息，这里逐个解析
                while offset + NLMSG_HDRLEN <= data_len:
                    # netlink 头：nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid
                    nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack_from(
                        "IHHII", data, offset
                    )
                    if nlmsg_len < NLMSG_HDRLEN:
                        break  # 数据异常，直接跳出

                    msg_end = offset + nlmsg_len
                    if msg_end > data_len:
                        break  # 截断，丢弃本条

                    # 只关心 LINK 类型的消息
                    if nlmsg_type in (RTM_NEWLINK, RTM_DELLINK):
                        payload = data[offset + NLMSG_HDRLEN: msg_end]
                        if len(payload) >= 16:
                            # struct ifinfomsg:
                            #   unsigned char  ifi_family;
                            #   unsigned char  __ifi_pad;
                            #   unsigned short ifi_type;
                            #   int            ifi_index;
                            #   unsigned int   ifi_flags;
                            #   unsigned int   ifi_change;
                            ifi_family, _pad, ifi_type, ifi_index, ifi_flags, ifi_change = struct.unpack_from(
                                "BBHiII", payload, 0
                            )

                            attrs = payload[16:]
                            attr_off = 0
                            ifname = None

                            # 解析 netlink attributes（TLV）
                            while attr_off + NLA_HDRLEN <= len(attrs):
                                nla_len, nla_type = struct.unpack_from("HH", attrs, attr_off)
                                if nla_len < NLA_HDRLEN:
                                    break

                                attr_end = attr_off + nla_len
                                if attr_end > len(attrs):
                                    break

                                value = attrs[attr_off + NLA_HDRLEN: attr_end]

                                if nla_type == IFLA_IFNAME:
                                    # IFLA_IFNAME 是接口名字，C 字符串，结尾有 '\0'
                                    name_bytes = value.split(b"\x00", 1)[0]
                                    try:
                                        ifname = name_bytes.decode("utf-8", errors="ignore")
                                    except Exception:
                                        ifname = None

                                attr_off += _align4(nla_len)

                            if ifname and ifname in wan_names:
                                # 用你已经写好的 is_interface_up() 再确认一次状态
                                is_up = self.is_interface_up(ifname)
                                self._on_wan_state_event(ifname, is_up)

                    offset += _align4(nlmsg_len)

            except Exception as e:
                if self.running:
                    self.logger.error(f"[WAN-EVENT] netlink monitor error: {e}")
                # 出现严重错误就结束线程
                break

        self.logger.info("[WAN-EVENT] wan_event_monitor_loop (netlink) exiting")
        try:
            nl_sock.close()
        except Exception:
            pass

    def request_ip_allocation(self) -> bool:
        """Step 4: Request IP allocation via primary router（沿用 v2 的实现方式）"""
        try:
            if not self.primary_tunnel or not self.primary_tunnel.connected:
                self.logger.error("No primary tunnel available for IP allocation request")
                return False

            request = IPAllocationRequest(
                endpoint_id=self.endpoint_id,
                reconnect=False,
                previous_subnet=None
            )

            request_data = ControlProtocol.encode_ip_alloc_request(request)

            if not self.primary_tunnel.send_control_message(
                    MessageType.IP_ALLOC_REQUEST, request_data
            ):
                self.logger.error("Failed to send IP allocation request")
                return False

            self.logger.info("Sent IP allocation request, waiting for response...")

            timeout = time.time() + 3
            while time.time() < timeout:
                try:
                    # 直接从 UDP socket 读取 tunnel 包
                    self.primary_tunnel.socket.settimeout(1.0)
                    data = self.primary_tunnel.socket.recv(65535)
                    if not data:
                        continue

                    packet = self.primary_tunnel.protocol.decapsulate(data)
                    if not packet:
                        continue

                    # 只关心 IP_ALLOC_RESPONSE 类型
                    if packet.msg_type != MessageType.IP_ALLOC_RESPONSE:
                        continue

                    # 负载再交给 ControlProtocol 解成 IPAllocationResponse
                    response = ControlProtocol.decode_ip_alloc_response(packet.payload)

                    if response.success:
                        self.allocated_subnet_ipv4 = response.subnet_ipv4
                        self.allocated_subnet_ipv6 = response.subnet_ipv6
                        self.gateway_ipv4 = response.gateway_ipv4
                        self.gateway_ipv6 = response.gateway_ipv6

                        self.logger.info(
                            f"Received IP allocation: IPv4={self.allocated_subnet_ipv4}, "
                            f"IPv6={self.allocated_subnet_ipv6}"
                        )
                        return True
                    else:
                        self.logger.error(f"IP allocation failed: {response.error_message}")
                        return False

                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"Error receiving IP allocation response: {e}")
                    continue

            self.logger.error("Timeout waiting for IP allocation response")
            return False

        except Exception as e:
            self.logger.error(f"Error requesting IP allocation: {e}")
            return False

    def setup_tun_interface(self):
        """Step 5: Configure TUN interface with allocated IPs"""
        try:
            TUNSETIFF = 0x400454ca
            IFF_TUN = 0x0001
            IFF_NO_PI = 0x1000
            
            self.tun_fd = os.open('/dev/net/tun', os.O_RDWR)
            
            ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
            ifs = fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)
            tun_name = ifs[:16].strip(b'\x00').decode('utf-8')
            
            self.logger.info(f"Created TUN interface: {tun_name}")
            
            # Configure IPv4
            if self.allocated_subnet_ipv4 and self.gateway_ipv4:
                os.system(f"ip addr add {self.gateway_ipv4} dev {tun_name}")
                os.system(f"ip link set dev {tun_name} up")
                self.logger.info(f"Configured IPv4 on {tun_name}: {self.gateway_ipv4}")
            
            # Configure IPv6
            if self.allocated_subnet_ipv6 and self.gateway_ipv6:
                os.system(f"ip -6 addr add {self.gateway_ipv6} dev {tun_name}")
                os.system(f"ip link set dev {tun_name} up")
                self.logger.info(f"Configured IPv6 on {tun_name}: {self.gateway_ipv6}")
            
        except Exception as e:
            self.logger.error(f"Error setting up TUN interface: {e}")
            raise

    def send_activation(self, previous_router: Optional[RouterInfo] = None) -> bool:
        """
        给当前 active_tunnel 对应的路由器发送 EndpointActivation 激活包。
        previous_router:
            - None：首次上线，没有旧路由器
            - RouterInfo：从这台旧路由器切过来
        """
        tunnel = self.active_tunnel
        if not tunnel or not tunnel.connected:
            self.logger.error("No active tunnel available for activation message")
            return False

        routes_ipv4 = [self.allocated_subnet_ipv4] if self.allocated_subnet_ipv4 else []
        routes_ipv6 = [self.allocated_subnet_ipv6] if self.allocated_subnet_ipv6 else []

        prev_id = previous_router.router_id if previous_router else None
        prev_ip = previous_router.external_ip if previous_router else None

        act = EndpointActivation(
            endpoint_id=self.endpoint_id,
            routes_ipv4=routes_ipv4,
            routes_ipv6=routes_ipv6,
            previous_router_id=prev_id,
            previous_router_ip=prev_ip,
            active=True,
        )

        payload = ControlProtocol.encode_endpoint_activation(act)
        ok = tunnel.send_control_message(MessageType.ENDPOINT_ACTIVATION, payload)

        if ok:
            self.logger.info(
                f"Sent activation to router {tunnel.router_info.router_id}, "
                f"previous_router={prev_id}"
            )
        else:
            self.logger.error("Failed to send activation message")

        return ok


    def advertise_routes(self):
        """Step 6: Advertise routes to primary router"""
        try:
            routes_ipv4 = [self.allocated_subnet_ipv4] if self.allocated_subnet_ipv4 else []
            routes_ipv6 = [self.allocated_subnet_ipv6] if self.allocated_subnet_ipv6 else []
            
            advertisement = RouteAdvertisement(
                endpoint_id=self.endpoint_id,
                routes_ipv4=routes_ipv4,
                routes_ipv6=routes_ipv6
            )
            
            adv_data = ControlProtocol.encode_route_advertisement(advertisement)
            
            if self.primary_tunnel and self.primary_tunnel.send_control_message(MessageType.ROUTE_ADVERTISEMENT, adv_data):
                self.logger.info(f"Advertised routes: IPv4={routes_ipv4}, IPv6={routes_ipv6}")
            else:
                self.logger.error("Failed to advertise routes")
            
        except Exception as e:
            self.logger.error(f"Error advertising routes: {e}")
    
    def decision_loop(self):
        lb_url = None
        while self.running and not lb_url:
            lb_url = self.discover_load_balancer()
            if lb_url:
                self.logger.info(f"[LB] decision_loop using load balancer URL: {lb_url}")
                break

            self.logger.error(
                f"[LB] Cannot query load balancer without URL, retrying in 1s..."
            )
            time.sleep(1)
        
        while self.running:
            try:
                time.sleep(self.config['load_balancer'].get('poll_interval', 2))
                
                primary_router, backup_router, _prev_router = self.query_router_info(lb_url)
                if not primary_router and not backup_router:
                    self.logger.warning(
                        "[LB] Load balancer returned no router info, keep current decision"
                    )
                    continue

                with self.tunnel_lock:
                    if primary_router:
                        if primary_router.router_id != self.primary_router_id:
                            self.logger.info(
                                f"Primary router preference changed: {self.primary_router_id} -> {primary_router.router_id}"
                            )
                            self.primary_router_id = primary_router.router_id
                    if backup_router:
                        if backup_router.router_id != self.backup_router_id:
                            self.logger.info(
                                f"Backup router preference changed: {self.backup_router_id} -> {backup_router.router_id}"
                            )
                            self.backup_router_id = backup_router.router_id
                    self._reselect_tunnels_locked(reason="lb_update")
            except Exception as e:
                self.logger.error(f"Error in decision loop: {e}")

    def keepalive_loop(self):
        """Send keepalive packets to maintain all tunnels and periodically log active tunnel status."""
        keepalive_interval = self.config['tunnel'].get('keepalive_interval', 10)

        while self.running:
            try:
                time.sleep(keepalive_interval)

                with self.tunnel_lock:
                    # 1) 给所有还连着的隧道发 keepalive
                    for tunnels in self.router_tunnels.values():
                        for tunnel in tunnels.values():
                            if tunnel and tunnel.connected:
                                tunnel.send_keepalive()
            except Exception as e:
                self.logger.error(f"Error in keepalive loop: {e}")

    def health_check_loop(self):
        """监控隧道健康 + WAN 口 up/down，快速切换 active_tunnel，重连逻辑放在次要位置。"""
        check_interval = 0.1  # 检测周期，越小切换越快（注意 CPU 占用）
        grace_down = 30.0  # 接口 DOWN 后宽限 30 秒再真正关闭隧道
        retry_interval = 2.0  # 接口 UP 时，最多每 2s 尝试一次重连

        loop_id = 0

        while self.running:
            try:
                time.sleep(check_interval)
                loop_id += 1
                loop_start = time.time()

                reconnect_tasks = []  # 元素形如 (tunnel, wan_name)

                with self.tunnel_lock:
                    wan_interfaces = self.wan_interfaces or []

                    # 1) 按接口更新 up/down 状态 + 重连
                    for wan in wan_interfaces:
                        name = wan.get("name")
                        if not name:
                            continue

                        now_up = self.is_interface_up(name)
                        prev_up = self.wan_status.get(name, now_up)
                        down_since = self.wan_down_since.get(name)

                        # A. UP -> DOWN
                        if prev_up and not now_up:
                            self.logger.warning(
                                f"WAN interface {name} transitioned DOWN, suspending its tunnels"
                            )
                            for rid, tunnels in self.router_tunnels.items():
                                t = tunnels.get(name)
                                if t and t.connected:
                                    self.logger.warning(
                                        f"WAN {name} is DOWN, marking tunnel to {t.router_info.router_id} as dead"
                                    )
                                    t.connected = False
                            self.wan_status[name] = False
                            self.wan_down_since[name] = time.time()
                            self.wan_last_retry[name] = 0.0

                        # B. DOWN -> UP
                        elif (not prev_up) and now_up:
                            self.logger.info(
                                f"WAN interface {name} transitioned UP (link), will try to reuse its tunnels"
                            )
                            self.wan_status[name] = True
                            self.wan_down_since[name] = None
                            self.wan_last_retry[name] = 0.0

                        else:
                            self.wan_status[name] = now_up

                        # C. 当前是 DOWN，处理宽限时间与隧道真正关闭
                        if not now_up:
                            if down_since is not None and time.time() - down_since > grace_down:
                                self.logger.warning(
                                    f"WAN interface {name} has been DOWN for more than "
                                    f"{grace_down}s, closing its tunnels"
                                )
                                for rid, tunnels in self.router_tunnels.items():
                                    t = tunnels.get(name)
                                    if t:
                                        t.close()
                                self.wan_down_since[name] = None
                            continue

                        # now_up == True，可以视情况做“重连尝试”
                        last_retry = self.wan_last_retry.get(name, 0.0)
                        if time.time() - last_retry >= retry_interval:
                            self.wan_last_retry[name] = time.time()

                            detected_ipv6 = self.get_interface_ipv6(name)
                            if not detected_ipv6:
                                # 这一条保留，方便看 IPv6 准备好没
                                self.logger.info(
                                    f"WAN interface {name} is UP but has no global IPv6 yet, "
                                    f"skip reconnect this round"
                                )
                            else:
                                old_ipv6 = None
                                for w in self.wan_interfaces:
                                    if w.get("name") == name:
                                        old_ipv6 = w.get("ipv6")
                                        if old_ipv6 != detected_ipv6:
                                            w["ipv6"] = detected_ipv6
                                        break

                                if old_ipv6 and old_ipv6 != detected_ipv6:
                                    self.logger.info(
                                        f"WAN interface {name} IPv6 changed {old_ipv6} -> {detected_ipv6}"
                                    )

                                # 为该 WAN 上“未连接”的隧道准备重连任务
                                scheduled = 0
                                for rid, tunnels in self.router_tunnels.items():
                                    t = tunnels.get(name)
                                    if not t or t.connected:
                                        continue
                                    if t.bind_address != detected_ipv6:
                                        t.bind_address = detected_ipv6
                                    reconnect_tasks.append((t, name))
                                    scheduled += 1

                                if scheduled > 0:
                                    self.logger.info(
                                        f"[HEALTH] wan={name} scheduled {scheduled} reconnect(s)"
                                    )

                    # 2) 选 router 的活隧道
                    def _pick_router_active(rid: Optional[str]) -> Optional[TunnelConnection]:
                        if not rid:
                            return None
                        tunnels = self.router_tunnels.get(rid, {})
                        if not tunnels:
                            return None

                        for wan in wan_interfaces:
                            wname = wan.get("name")
                            if not wname:
                                continue
                            t = tunnels.get(wname)
                            if t and t.is_alive():
                                return t

                        for t in tunnels.values():
                            if t and t.is_alive():
                                return t
                        return None

                    def _get_wan_name_for_tunnel(t: TunnelConnection) -> str:
                        for rid, tunnels in self.router_tunnels.items():
                            for wname, tt in tunnels.items():
                                if tt is t:
                                    return wname
                        return "unknown_wan"

                    new_primary_tunnel = _pick_router_active(self.primary_router_id)
                    new_backup_tunnel = _pick_router_active(self.backup_router_id)

                    if new_primary_tunnel is not self.primary_tunnel:
                        if new_primary_tunnel:
                            wan_name = _get_wan_name_for_tunnel(new_primary_tunnel)
                            self.logger.info(
                                f"Primary router tunnel now {new_primary_tunnel.router_info.router_id} "
                                f"via {wan_name}"
                            )
                        else:
                            rid = self.primary_router_id
                            tunnels = self.router_tunnels.get(rid, {})
                            states = []
                            for wname, t in tunnels.items():
                                if not t:
                                    states.append(f"{wname}: <none>")
                                else:
                                    states.append(
                                        f"{wname}: connected={t.connected}, "
                                        f"is_alive={t.is_alive()}, "
                                        f"wan_up={self.wan_status.get(wname, None)}"
                                    )
                            self.logger.warning(
                                f"No live tunnel available for primary router {rid}; states: " +
                                " | ".join(states)
                            )
                        self.primary_tunnel = new_primary_tunnel

                    if new_backup_tunnel is not self.backup_tunnel:
                        if new_backup_tunnel:
                            wan_name = _get_wan_name_for_tunnel(new_backup_tunnel)
                            self.logger.info(
                                f"Backup router tunnel now {new_backup_tunnel.router_info.router_id} "
                                f"via {wan_name}"
                            )
                        else:
                            self.logger.warning("No live tunnel available for backup router")
                        self.backup_tunnel = new_backup_tunnel

                    # 3) 软切换 active_tunnel
                    current_active = self.active_tunnel
                    old_tunnel = current_active
                    if current_active:
                        wan_name = _get_wan_name_for_tunnel(current_active)
                        wan_up = self.wan_status.get(wan_name, True)
                        if (not current_active.is_alive()) or (not wan_up):
                            self.logger.info(
                                f"[HEALTH] current active tunnel to "
                                f"{current_active.router_info.router_id} via {wan_name} "
                                f"is no longer healthy"
                            )
                            current_active = None

                    if current_active is not None:
                        cur_rid = current_active.router_info.router_id
                        if (
                                self.primary_tunnel
                                and self.primary_router_id
                                and self.primary_router_id != cur_rid
                        ):
                            pt_wan = _get_wan_name_for_tunnel(self.primary_tunnel)
                            pt_wan_up = self.wan_status.get(pt_wan, True)
                            if self.primary_tunnel.is_alive() and pt_wan_up:
                                self.logger.info(
                                    f"[LB] Preferred primary router is {self.primary_router_id}, "
                                    f"forcing active tunnel switch from {cur_rid} to {self.primary_router_id}"
                                )
                                current_active = None

                    if current_active is None:
                        candidate = None
                        if self.primary_tunnel:
                            pt_wan = _get_wan_name_for_tunnel(self.primary_tunnel)
                            if self.primary_tunnel.is_alive() and self.wan_status.get(pt_wan, True):
                                candidate = self.primary_tunnel

                        if candidate is None and self.backup_tunnel:
                            bt_wan = _get_wan_name_for_tunnel(self.backup_tunnel)
                            if self.backup_tunnel.is_alive() and self.wan_status.get(bt_wan, True):
                                candidate = self.backup_tunnel

                        new_active = candidate
                    else:
                        new_active = current_active

                    if new_active is not self.active_tunnel:
                        if new_active:
                            wan_name = _get_wan_name_for_tunnel(new_active)
                            self.logger.info(
                                f"Active tunnel switched to router {new_active.router_info.router_id} "
                                f"via {wan_name}"
                            )
                            self.active_router_id = new_active.router_info.router_id
                        else:
                            self.logger.error("No active tunnel available")
                            self.active_router_id = None

                        self.active_tunnel = new_active

                        if new_active:
                            prev_router = old_tunnel.router_info if old_tunnel else None
                            try:
                                self.send_activation(previous_router=prev_router)
                            except Exception as e:
                                self.logger.error(f"Failed to send activation after switch: {e}")

                # ===== 锁外执行 connect()，并只对“慢的”打日志 =====
                for t, wan_name in reconnect_tasks:
                    start = time.time()
                    try:
                        ok = t.connect()
                        cost = time.time() - start
                        # 只有 connect 比较慢才打日志，比如 > 0.1s
                        if cost > 0.1:
                            self.logger.warning(
                                f"[HEALTH] RECONNECT wan={wan_name} router={t.router_info.router_id} "
                                f"ok={ok} cost={cost:.3f}s"
                            )
                    except Exception as e:
                        cost = time.time() - start
                        self.logger.error(
                            f"[HEALTH] RECONNECT_ERR wan={wan_name} "
                            f"router={t.router_info.router_id} cost={cost:.3f}s err={e}"
                        )

                loop_cost = time.time() - loop_start
                # 一整轮健康检查如果特别慢，也打一个 warn
                if loop_cost > 0.2:
                    self.logger.warning(
                        f"[HEALTH] loop={loop_id} total loop cost={loop_cost:.3f}s, "
                        f"reconnect_tasks={len(reconnect_tasks)}"
                    )

            except Exception as e:
                self.logger.error(f"Error in health check loop: {e}")

    def send_to_tunnel(self):
        """Forward packets from TUN to active tunnel"""
        while self.running:
            try:
                packet = os.read(self.tun_fd, 65535)
                if not packet:
                    continue

                is_ipv6 = (packet[0] >> 4) == 6

                # 不要在这里拿大锁，只是“读一次快照”
                tunnel = self.active_tunnel
                if tunnel and tunnel.connected:
                    try:
                        tunnel.send_data(packet, is_ipv6=is_ipv6)
                    except Exception as e:
                        if self.running:
                            self.logger.error(f"Error sending to tunnel: {e}")
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error reading from TUN: {e}")

    def receive_from_tunnels(self):
        import select

        socket_map = {}  # 上一轮缓存的 {socket: tunnel}
        while self.running:
            try:
                # 1) 尝试更新 socket_map，但不要阻塞在大锁上
                updated = False
                if self.tunnel_lock.acquire(blocking=False):
                    try:
                        socket_map = {
                            tunnel.socket: tunnel
                            for tunnels_per_router in self.router_tunnels.values()
                            for tunnel in tunnels_per_router.values()
                            if tunnel and tunnel.connected and tunnel.socket
                        }
                        updated = True
                    finally:
                        self.tunnel_lock.release()

                sockets = list(socket_map.keys())
                if not sockets:
                    time.sleep(0.01)
                    continue

                # 2) 等待这些 socket 可读
                readable, _, _ = select.select(sockets, [], [], 0.1)

                # 3) 把数据写回 TUN
                for sock in readable:
                    tunnel = socket_map.get(sock)
                    if not tunnel:
                        continue
                    data = tunnel.receive(timeout=0)
                    if data:
                        os.write(self.tun_fd, data)

            except Exception as e:
                if self.running:
                    self.logger.error(f"Error receiving from tunnels: {e}")

    def start(self):
        """Start endpoint with robust initialization (no auto-exit)."""
        self.running = True

        self.logger.info("Starting network access endpoint with new initialization flow...")

        # === 1) Discover load balancer URL (loop until success) ===
        retry_interval = 1
        lb_url = None
        while self.running and not lb_url:
            lb_url = self.discover_load_balancer()
            if lb_url:
                self.logger.info(f"Discovered load balancer URL: {lb_url}")
                break
            self.logger.error(
                f"Failed to discover load balancer, retrying in {retry_interval}s..."
            )
            time.sleep(retry_interval)
        if not self.running:
            return
        # === 2) 必须同时拿到 primary & backup，才往下走 ===
        primary_router = None
        backup_router = None
        initial_prev_router = None
        while self.running and (primary_router is None or backup_router is None):
            primary_router, backup_router, prev_router = self.query_router_info(lb_url)
            if primary_router and backup_router:
                self.logger.info(
                    f"Got router decision from LB: primary={primary_router.router_id}, "
                    f"backup={backup_router.router_id}, "
                    f"prev_primary={prev_router.router_id if prev_router else 'None'}"
                )
                initial_prev_router = prev_router
                break
            # 只拿到一个也算失败，清掉结果继续重试
            primary_router = None
            backup_router = None
            self.logger.error(
                "Failed to get BOTH primary and backup routers from load balancer, "
                f"retrying in {retry_interval}s..."
            )
            time.sleep(retry_interval)
        if not self.running:
            return
        # === 3) 建立隧道：失败则重试 ===
        while self.running:
            if self.establish_tunnels(primary_router, backup_router):
                break
            self.logger.error(
                "Failed to establish tunnels, retrying in %ds..." % retry_interval
            )
            time.sleep(retry_interval)
        if not self.running:
            return
        # === 4) 向控制器申请 IP：失败则重试 ===
        while self.running:
            if self.request_ip_allocation():
                break
            self.logger.error(
                "Failed to allocate IP addresses, retrying in %ds..." % retry_interval
            )
            time.sleep(retry_interval)
        if not self.running:
            return
        # === 5) 配置 TUN：出错也只打日志 + 重试，不退出程序 ===
        while self.running:
            try:
                self.setup_tun_interface()
                break
            except Exception as e:
                self.logger.error(
                    f"Error setting up TUN interface, will retry in {retry_interval}s: {e}"
                )
                time.sleep(retry_interval)
        if not self.running:
            return
        # === 6) 首次激活当前 active_tunnel ===
        self.send_activation(previous_router=initial_prev_router)

        # === 7) 启动后台线程 ===
        threads = [
            threading.Thread(target=self.send_to_tunnel, daemon=True),
            threading.Thread(target=self.receive_from_tunnels, daemon=True),
            threading.Thread(target=self.keepalive_loop, daemon=True),
            threading.Thread(target=self.wan_event_monitor_loop, daemon=True),
            threading.Thread(target=self.decision_loop, daemon=True),
        ]

        for t in threads:
            t.start()

        self.logger.info("Network access endpoint started successfully")

        # 主线程只负责阻塞住和响应 Ctrl+C
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.stop()

    def stop(self):
        self.running = False
        with self.tunnel_lock:
            # Close all tunnels
            for tunnels in self.router_tunnels.values():
                for tunnel in tunnels.values():
                    if tunnel:
                        tunnel.close()
            self.primary_tunnel = None
            self.backup_tunnel = None
            self.active_tunnel = None
        
        if self.tun_fd:
            os.close(self.tun_fd)

        if getattr(self, "wan_monitor_proc", None) is not None:
            try:
                if self.wan_monitor_proc.poll() is None:
                    self.wan_monitor_proc.terminate()
            except Exception:
                pass


def main():
    if os.geteuid() != 0:
        print("ERROR: This program must be run as root (for TUN device and network configuration)")
        print("Please run with: sudo python3 " + sys.argv[0])
        sys.exit(1)
    
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <config_file>")
        sys.exit(1)
    
    config_path = sys.argv[1]
    endpoint = NetworkAccessEndpoint(config_path)
    endpoint.start()


if __name__ == '__main__':
    main()

