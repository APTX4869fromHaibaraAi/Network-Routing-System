#!/usr/bin/env python3
"""
Load Balancer Server
Receives metrics from routing servers and provides optimal routing decisions
"""

import sys
import os
import time
import logging
import yaml
from typing import Dict, Optional, List, Union
from dataclasses import dataclass, asdict
from datetime import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn


@dataclass
class ServerMetrics:
    server_id: str
    server_name: str
    timestamp: float
    cpu_percent: float
    memory_percent: float
    bandwidth_mbps: float
    active_tunnels: int
    total_rx_packets: int
    total_tx_packets: int
    internal_ip: str
    external_ip: str
    score: float = 0.0
    last_updated: float = 0.0


class MetricsRequest(BaseModel):
    server_id: str
    server_name: str
    timestamp: float
    cpu_percent: float
    memory_percent: float
    bandwidth_mbps: float
    active_tunnels: int
    total_rx_packets: int
    total_tx_packets: int
    internal_ip: str
    external_ip: str


class DecisionResponse(BaseModel):
    primary_router_id: str
    primary_router_internal_ip: str
    primary_router_external_ip: str
    backup_router_id: str
    backup_router_internal_ip: str
    backup_router_external_ip: str
    business_server_ip: str
    primary_score: float
    backup_score: float
    timestamp: float
    routers: List[Dict[str, Union[str, float]]]
    previous_primary_router_id: Optional[str] = None
    previous_primary_router_internal_ip: Optional[str] = None
    previous_primary_router_external_ip: Optional[str] = None

class LoadBalancer:
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.setup_logging()
        
        self.server_metrics: Dict[str, ServerMetrics] = {}
        
        self.weights = {
            'cpu': self.config['algorithm']['weights']['cpu'],
            'memory': self.config['algorithm']['weights']['memory'],
            'bandwidth': self.config['algorithm']['weights']['bandwidth'],
            'connections': self.config['algorithm']['weights']['connections']
        }
        
        self.anti_flap_threshold = self.config['algorithm']['anti_flap_threshold']
        self.anti_flap_hold_time = self.config['algorithm']['anti_flap_hold_time']
        
        self.current_decisions: Dict[str, Dict] = {}
        
        self.logger.info("Load balancer initialized")
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['server']['log_file']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('LoadBalancer')
    
    def calculate_score(self, metrics: ServerMetrics) -> float:
        cpu_score = (100 - metrics.cpu_percent) / 100
        memory_score = (100 - metrics.memory_percent) / 100
        
        max_bandwidth = self.config['algorithm'].get('max_bandwidth_mbps', 1000)
        bandwidth_score = max(0, (max_bandwidth - metrics.bandwidth_mbps) / max_bandwidth)
        
        max_connections = self.config['algorithm'].get('max_connections', 100)
        connection_score = max(0, (max_connections - metrics.active_tunnels) / max_connections)
        
        total_score = (
            cpu_score * self.weights['cpu'] +
            memory_score * self.weights['memory'] +
            bandwidth_score * self.weights['bandwidth'] +
            connection_score * self.weights['connections']
        )
        
        return total_score
    
    def update_metrics(self, metrics_data: MetricsRequest) -> Dict:
        metrics = ServerMetrics(
            server_id=metrics_data.server_id,
            server_name=metrics_data.server_name,
            timestamp=metrics_data.timestamp,
            cpu_percent=metrics_data.cpu_percent,
            memory_percent=metrics_data.memory_percent,
            bandwidth_mbps=metrics_data.bandwidth_mbps,
            active_tunnels=metrics_data.active_tunnels,
            total_rx_packets=metrics_data.total_rx_packets,
            total_tx_packets=metrics_data.total_tx_packets,
            internal_ip=metrics_data.internal_ip,
            external_ip=metrics_data.external_ip,
            last_updated=time.time()
        )
        
        metrics.score = self.calculate_score(metrics)
        
        self.server_metrics[metrics.server_id] = metrics
        
        self.logger.info(
            f"Updated metrics for {metrics.server_name}: "
            f"CPU={metrics.cpu_percent:.1f}%, MEM={metrics.memory_percent:.1f}%, "
            f"BW={metrics.bandwidth_mbps:.2f}Mbps, Tunnels={metrics.active_tunnels}, "
            f"Score={metrics.score:.3f}"
        )
        
        return {"status": "ok", "score": metrics.score}
    
    def get_optimal_server(self, endpoint_id: str) -> Optional[ServerMetrics]:
        current_time = time.time()
        
        valid_servers = [
            metrics for metrics in self.server_metrics.values()
            if current_time - metrics.last_updated < 30
        ]
        
        if not valid_servers:
            self.logger.warning("No valid routing servers available")
            return None
        
        best_server = max(valid_servers, key=lambda m: m.score)
        
        if endpoint_id in self.current_decisions:
            current_decision = self.current_decisions[endpoint_id]
            current_server_id = current_decision['server_id']
            decision_time = current_decision['timestamp']
            
            if current_server_id in self.server_metrics:
                current_server = self.server_metrics[current_server_id]
                
                if current_time - decision_time < self.anti_flap_hold_time:
                    score_diff = best_server.score - current_server.score
                    if score_diff < self.anti_flap_threshold:
                        self.logger.debug(
                            f"Anti-flap: keeping {current_server.server_name} "
                            f"(score diff {score_diff:.3f} < threshold {self.anti_flap_threshold})"
                        )
                        return current_server
        
        self.current_decisions[endpoint_id] = {
            'server_id': best_server.server_id,
            'timestamp': current_time
        }
        
        self.logger.info(
            f"Selected optimal server for {endpoint_id}: {best_server.server_name} "
            f"(score={best_server.score:.3f})"
        )
        
        return best_server

    def get_decision(self, endpoint_id: str) -> DecisionResponse:
        """
        带防抖逻辑的决策函数：
        - 至少需要 2 个有效路由器；
        - 默认选择当前得分最高的两个作为候选 primary / backup；
        - 如果在 anti_flap_hold_time 时间窗口内，新 primary 相比旧 primary 的得分提升
          小于 anti_flap_threshold，则继续沿用旧 primary，不切换。
        """
        current_time = time.time()

        # 1) 过滤出“最近有上报”的路由器
        valid_servers = [
            metrics for metrics in self.server_metrics.values()
            if current_time - metrics.last_updated < 30  # 30 秒内有上报视为有效
        ]

        if len(valid_servers) < 2:
            raise HTTPException(status_code=503, detail="Need at least 2 routing servers available")

        # 2) 按得分排序，先算出“瞬时最优”的两个候选路由器
        sorted_servers = sorted(valid_servers, key=lambda m: m.score, reverse=True)
        candidate_primary = sorted_servers[0]
        candidate_backup = sorted_servers[1]

        # 默认就用当前瞬时最优
        selected_primary = candidate_primary
        selected_backup = candidate_backup

        prev_decision = self.current_decisions.get(endpoint_id)
        prev_primary = None
        if prev_decision is not None:
            try:
                prev_time = prev_decision['timestamp']
                prev_ids = prev_decision.get('router_ids')
                if isinstance(prev_ids, list) and prev_ids:
                    prev_primary_id = prev_ids[0]
                    prev_primary = next(
                        (m for m in valid_servers if m.server_id == prev_primary_id),
                        None
                    )
            except Exception:
                prev_primary = None

        # 3) 应用 anti-flap：在一定时间窗口内，避免 primary 来回抖动
        if prev_decision is not None and prev_primary is not None:
            prev_time = prev_decision['timestamp']

            # 只在“时间窗口内”才考虑防抖
            if current_time - prev_time < self.anti_flap_hold_time:
                # 如果候选 primary 和之前的 primary 不是同一台，才有“要不要切”的问题
                if candidate_primary.server_id != prev_primary.server_id:
                    score_diff = candidate_primary.score - prev_primary.score

                    # 如果分数提升不显著（小于阈值），则继续沿用旧 primary
                    if score_diff < self.anti_flap_threshold:
                        self.logger.info(
                            "Anti-flap: keep previous primary %s (score=%.3f) for %s; "
                            "candidate=%s (score=%.3f, diff=%.3f < %.3f)",
                            prev_primary.server_id, prev_primary.score,
                            endpoint_id,
                            candidate_primary.server_id, candidate_primary.score,
                            score_diff, self.anti_flap_threshold,
                        )
                        selected_primary = prev_primary

                        # 重新选择 backup：在当前排序中找一个“不是 primary”的最佳服务器
                        for s in sorted_servers:
                            if s.server_id != selected_primary.server_id:
                                selected_backup = s
                                break
                    else:
                        # 分数提升显著，允许切换到新的 primary
                        self.logger.info(
                            "Switch primary for %s: %s(%.3f) -> %s(%.3f), diff=%.3f >= %.3f",
                            endpoint_id,
                            prev_primary.server_id, prev_primary.score,
                            candidate_primary.server_id, candidate_primary.score,
                            score_diff, self.anti_flap_threshold,
                        )
                # else: 候选第一名本身就是之前的 primary，自然无需处理
            # else: 时间窗口已过，不用防抖

            # 4) 记录本次决策（用于下一次防抖）
        self.current_decisions[endpoint_id] = {
            'router_ids': [selected_primary.server_id, selected_backup.server_id],
            'timestamp': current_time,
        }

        # 5) 计算这一轮“需要下发给接入端的 previous_primary”
        previous_primary_for_client = None
        if prev_primary is not None and prev_primary.server_id != selected_primary.server_id:
            # 只有真的发生了 primary 变化才下发 previous_primary
            previous_primary_for_client = prev_primary

        # 6) 构造返回用的路由器信息（这里只返回 primary+backup 两个）
        routers_info = [{
            "router_id": router.server_id,
            "internal_ip": router.internal_ip,
            "external_ip": router.external_ip,
            "score": router.score,
        } for router in (selected_primary, selected_backup)]

        self.logger.info(
            "Decision for %s: primary=%s(%.3f), backup=%s(%.3f)",
            endpoint_id,
            selected_primary.server_id, selected_primary.score,
            selected_backup.server_id, selected_backup.score,
        )

        return DecisionResponse(
            primary_router_id=selected_primary.server_id,
            primary_router_internal_ip=selected_primary.internal_ip,
            primary_router_external_ip=selected_primary.external_ip,
            backup_router_id=selected_backup.server_id,
            backup_router_internal_ip=selected_backup.internal_ip,
            backup_router_external_ip=selected_backup.external_ip,
            business_server_ip=self.config['business_server']['ip'],
            primary_score=selected_primary.score,
            backup_score=selected_backup.score,
            timestamp=current_time,
            routers=routers_info,
            previous_primary_router_id=(
                previous_primary_for_client.server_id
                if previous_primary_for_client else None
            ),
            previous_primary_router_internal_ip=(
                previous_primary_for_client.internal_ip
                if previous_primary_for_client else None
            ),
            previous_primary_router_external_ip=(
                previous_primary_for_client.external_ip
                if previous_primary_for_client else None
            ),
        )

    def get_status(self) -> Dict:
        current_time = time.time()
        
        servers_status = []
        for metrics in self.server_metrics.values():
            age = current_time - metrics.last_updated
            status = "active" if age < 30 else "stale"
            
            servers_status.append({
                "server_id": metrics.server_id,
                "server_name": metrics.server_name,
                "internal_ip": metrics.internal_ip,
                "external_ip": metrics.external_ip,
                "status": status,
                "age_seconds": age,
                "cpu_percent": metrics.cpu_percent,
                "memory_percent": metrics.memory_percent,
                "bandwidth_mbps": metrics.bandwidth_mbps,
                "active_tunnels": metrics.active_tunnels,
                "score": metrics.score
            })
        
        return {
            "timestamp": current_time,
            "total_servers": len(self.server_metrics),
            "active_servers": len([s for s in servers_status if s["status"] == "active"]),
            "servers": servers_status,
            "active_decisions": len(self.current_decisions)
        }


app = FastAPI(title="Load Balancer API")
lb: Optional[LoadBalancer] = None


@app.post("/metrics")
async def receive_metrics(metrics: MetricsRequest):
    return lb.update_metrics(metrics)


@app.get("/decision/{endpoint_id}")
async def get_decision(endpoint_id: str):
    return lb.get_decision(endpoint_id)


@app.get("/status")
async def get_status():
    return lb.get_status()


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": time.time()}


def main():
    global lb
    
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <config_file>")
        sys.exit(1)
    
    config_path = sys.argv[1]
    lb = LoadBalancer(config_path)
    
    host = lb.config['server']['bind_address']
    port = lb.config['server']['bind_port']
    
    lb.logger.info(f"Starting load balancer on {host}:{port}")
    
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == '__main__':
    main()
