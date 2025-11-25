#!/usr/bin/env python3
"""
Network Controller
Manages network devices, address allocation, configuration, and monitoring
Supports dynamic subnet allocation for 10,000+ endpoints
"""

import sys
import os
import time
import logging
import yaml
import json
import ipaddress
import itertools
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from common.control_protocol import (
    IPAllocationRequest, IPAllocationResponse, 
    ControlProtocol
)


class DeviceRegistration(BaseModel):
    device_id: str
    device_type: str
    hostname: str
    management_ip: str
    interfaces: List[Dict]


class DeviceConfig(BaseModel):
    device_id: str
    config_type: str
    config_data: Dict


class DeviceStatus(BaseModel):
    device_id: str
    status: str
    timestamp: float
    metrics: Optional[Dict] = None


@dataclass
class ManagedDevice:
    device_id: str
    device_type: str
    hostname: str
    management_ip: str
    interfaces: List[Dict]
    registered_at: float
    last_seen: float
    status: str
    config: Dict
    metrics: Dict


@dataclass
class SubnetAllocation:
    """Subnet allocation for an endpoint"""
    endpoint_id: str
    subnet_ipv4: str
    subnet_ipv6: str
    gateway_ipv4: str
    gateway_ipv6: str
    allocated_at: float
    last_seen: float


class NetworkController:
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.setup_logging()
        
        self.devices: Dict[str, ManagedDevice] = {}
        
        self.subnet_allocations: Dict[str, SubnetAllocation] = {}
        self.allocated_subnets_ipv4 = set()
        self.allocated_subnets_ipv6 = set()
        
        self.base_network_ipv4 = ipaddress.IPv4Network(
            self.config['ip_allocation'].get('base_network_ipv4', '10.100.0.0/16')
        )
        self.base_network_ipv6 = ipaddress.IPv6Network(
            self.config['ip_allocation'].get('base_network_ipv6', 'fd00:100::/32')
        )
        self.start_subnet_index_ipv4 = int(
            self.config['ip_allocation'].get('start_subnet_index_ipv4', 0)
        )

        self.subnet_prefix_ipv4 = self.config['ip_allocation'].get('subnet_prefix_ipv4', 24)
        self.subnet_prefix_ipv6 = self.config['ip_allocation'].get('subnet_prefix_ipv6', 64)

        if self.start_subnet_index_ipv4 > 0:
            for subnet in itertools.islice(
                    self.base_network_ipv4.subnets(new_prefix=self.subnet_prefix_ipv4),
                    self.start_subnet_index_ipv4
            ):
                self.allocated_subnets_ipv4.add(str(subnet))
        self.allocation_timeout = self.config['ip_allocation'].get('allocation_timeout', 3600)
        
        self.ip_pools = {
            'tun_ipv4': self.config['ip_allocation']['tun_ipv4_pool'],
            'tun_ipv6': self.config['ip_allocation']['tun_ipv6_pool']
        }
        
        self.allocated_ips = {
            'tun_ipv4': set(),
            'tun_ipv6': set()
        }
        
        self.logger.info("Network controller initialized")
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['controller']['log_file']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('NetworkController')
    
    def allocate_subnet(self, endpoint_id: str, reconnect: bool = False, 
                       previous_subnet: Optional[str] = None) -> Optional[SubnetAllocation]:
        """Allocate a subnet for an endpoint with persistence support"""
        
        if reconnect and previous_subnet and endpoint_id in self.subnet_allocations:
            allocation = self.subnet_allocations[endpoint_id]
            allocation.last_seen = time.time()
            self.logger.info(f"Restored previous allocation for {endpoint_id}: {allocation.subnet_ipv4}")
            return allocation
        
        if endpoint_id in self.subnet_allocations:
            allocation = self.subnet_allocations[endpoint_id]
            allocation.last_seen = time.time()
            return allocation
        
        try:
            subnet_ipv4 = None
            for subnet in self.base_network_ipv4.subnets(new_prefix=self.subnet_prefix_ipv4):
                subnet_str = str(subnet)
                if subnet_str not in self.allocated_subnets_ipv4:
                    subnet_ipv4 = subnet
                    self.allocated_subnets_ipv4.add(subnet_str)
                    break
            
            if not subnet_ipv4:
                self.logger.error("No available IPv4 subnets")
                return None
            
            subnet_ipv6 = None
            for subnet in self.base_network_ipv6.subnets(new_prefix=self.subnet_prefix_ipv6):
                subnet_str = str(subnet)
                if subnet_str not in self.allocated_subnets_ipv6:
                    subnet_ipv6 = subnet
                    self.allocated_subnets_ipv6.add(subnet_str)
                    break
            
            if not subnet_ipv6:
                self.logger.error("No available IPv6 subnets")
                self.allocated_subnets_ipv4.remove(str(subnet_ipv4))
                return None
            
            gateway_ipv4 = str(list(subnet_ipv4.hosts())[0])
            gateway_ipv6 = str(subnet_ipv6.network_address + 1)
            
            allocation = SubnetAllocation(
                endpoint_id=endpoint_id,
                subnet_ipv4=str(subnet_ipv4),
                subnet_ipv6=str(subnet_ipv6),
                gateway_ipv4=gateway_ipv4,
                gateway_ipv6=gateway_ipv6,
                allocated_at=time.time(),
                last_seen=time.time()
            )
            
            self.subnet_allocations[endpoint_id] = allocation
            
            self.logger.info(
                f"Allocated subnet for {endpoint_id}: IPv4={subnet_ipv4}, IPv6={subnet_ipv6}"
            )
            
            return allocation
            
        except Exception as e:
            self.logger.error(f"Error allocating subnet: {e}")
            return None
    
    def release_subnet(self, endpoint_id: str):
        """Release subnet allocation for an endpoint"""
        if endpoint_id in self.subnet_allocations:
            allocation = self.subnet_allocations[endpoint_id]
            self.allocated_subnets_ipv4.discard(allocation.subnet_ipv4)
            self.allocated_subnets_ipv6.discard(allocation.subnet_ipv6)
            del self.subnet_allocations[endpoint_id]
            self.logger.info(f"Released subnet for {endpoint_id}")
    
    def cleanup_stale_allocations(self):
        """Clean up allocations that haven't been seen for a long time"""
        current_time = time.time()
        stale_endpoints = []
        
        for endpoint_id, allocation in self.subnet_allocations.items():
            if current_time - allocation.last_seen > self.allocation_timeout:
                stale_endpoints.append(endpoint_id)
        
        for endpoint_id in stale_endpoints:
            self.release_subnet(endpoint_id)
            self.logger.info(f"Cleaned up stale allocation for {endpoint_id}")
    
    def handle_ip_allocation_request(self, request: IPAllocationRequest) -> IPAllocationResponse:
        """Handle IP allocation request from endpoint via router"""
        try:
            allocation = self.allocate_subnet(
                endpoint_id=request.endpoint_id,
                reconnect=request.reconnect,
                previous_subnet=request.previous_subnet
            )
            
            if allocation:
                return IPAllocationResponse(
                    endpoint_id=request.endpoint_id,
                    success=True,
                    subnet_ipv4=allocation.subnet_ipv4,
                    subnet_ipv6=allocation.subnet_ipv6,
                    gateway_ipv4=allocation.gateway_ipv4,
                    gateway_ipv6=allocation.gateway_ipv6
                )
            else:
                return IPAllocationResponse(
                    endpoint_id=request.endpoint_id,
                    success=False,
                    error_message="No available subnets"
                )
                
        except Exception as e:
            self.logger.error(f"Error handling IP allocation request: {e}")
            return IPAllocationResponse(
                endpoint_id=request.endpoint_id,
                success=False,
                error_message=str(e)
            )
    
    def allocate_ip(self, pool_name: str) -> Optional[str]:
        pool = self.ip_pools.get(pool_name)
        if not pool:
            return None
        
        base_ip = pool['base']
        start = pool['start']
        end = pool['end']
        
        if pool_name == 'tun_ipv4':
            base_parts = base_ip.rsplit('.', 1)[0]
            for i in range(start, end + 1):
                ip = f"{base_parts}.{i}"
                if ip not in self.allocated_ips[pool_name]:
                    self.allocated_ips[pool_name].add(ip)
                    return ip
        
        elif pool_name == 'tun_ipv6':
            base_prefix = base_ip.rsplit(':', 1)[0]
            for i in range(start, end + 1):
                ip = f"{base_prefix}:{i:x}"
                if ip not in self.allocated_ips[pool_name]:
                    self.allocated_ips[pool_name].add(ip)
                    return ip
        
        return None
    
    def register_device(self, registration: DeviceRegistration) -> Dict:
        if registration.device_id in self.devices:
            self.logger.warning(f"Device {registration.device_id} already registered, updating")
        
        tun_ipv4 = self.allocate_ip('tun_ipv4')
        tun_ipv6 = self.allocate_ip('tun_ipv6')
        
        if not tun_ipv4 or not tun_ipv6:
            raise HTTPException(status_code=500, detail="IP allocation failed")
        
        device = ManagedDevice(
            device_id=registration.device_id,
            device_type=registration.device_type,
            hostname=registration.hostname,
            management_ip=registration.management_ip,
            interfaces=registration.interfaces,
            registered_at=time.time(),
            last_seen=time.time(),
            status="registered",
            config={
                "tun_ipv4": tun_ipv4,
                "tun_ipv6": tun_ipv6,
                "tunnel_psk": self.config['security']['default_psk'],
                "tunnel_port": self.config['tunnel']['default_port']
            },
            metrics={}
        )
        
        self.devices[registration.device_id] = device
        
        self.logger.info(
            f"Registered device {registration.device_id} ({registration.device_type}): "
            f"IPv4={tun_ipv4}, IPv6={tun_ipv6}"
        )
        
        return {
            "status": "registered",
            "device_id": registration.device_id,
            "config": device.config
        }
    
    def update_device_config(self, config_update: DeviceConfig) -> Dict:
        if config_update.device_id not in self.devices:
            raise HTTPException(status_code=404, detail="Device not found")
        
        device = self.devices[config_update.device_id]
        
        if config_update.config_type == "tunnel":
            device.config.update(config_update.config_data)
        elif config_update.config_type == "routing":
            device.config['routing'] = config_update.config_data
        elif config_update.config_type == "full":
            device.config = config_update.config_data
        
        self.logger.info(
            f"Updated config for {config_update.device_id}: type={config_update.config_type}"
        )
        
        return {"status": "updated", "device_id": config_update.device_id}
    
    def update_device_status(self, status_update: DeviceStatus) -> Dict:
        if status_update.device_id not in self.devices:
            raise HTTPException(status_code=404, detail="Device not found")
        
        device = self.devices[status_update.device_id]
        device.status = status_update.status
        device.last_seen = time.time()
        
        if status_update.metrics:
            device.metrics = status_update.metrics
        
        return {"status": "ok"}
    
    def get_device_info(self, device_id: str) -> Dict:
        if device_id not in self.devices:
            raise HTTPException(status_code=404, detail="Device not found")
        
        device = self.devices[device_id]
        
        return {
            "device_id": device.device_id,
            "device_type": device.device_type,
            "hostname": device.hostname,
            "management_ip": device.management_ip,
            "interfaces": device.interfaces,
            "status": device.status,
            "last_seen": device.last_seen,
            "config": device.config,
            "metrics": device.metrics
        }
    
    def get_all_devices(self) -> Dict:
        devices_list = []
        current_time = time.time()
        
        for device in self.devices.values():
            age = current_time - device.last_seen
            online = age < 60
            
            devices_list.append({
                "device_id": device.device_id,
                "device_type": device.device_type,
                "hostname": device.hostname,
                "management_ip": device.management_ip,
                "status": device.status,
                "online": online,
                "last_seen_ago": age
            })
        
        return {
            "total_devices": len(self.devices),
            "devices": devices_list
        }
    
    def get_network_topology(self) -> Dict:
        topology = {
            "endpoints": [],
            "routers": [],
            "load_balancer": None,
            "business_server": None
        }
        
        for device in self.devices.values():
            device_info = {
                "device_id": device.device_id,
                "hostname": device.hostname,
                "management_ip": device.management_ip,
                "tun_ipv4": device.config.get("tun_ipv4"),
                "tun_ipv6": device.config.get("tun_ipv6"),
                "status": device.status
            }
            
            if device.device_type == "endpoint":
                topology["endpoints"].append(device_info)
            elif device.device_type == "router":
                topology["routers"].append(device_info)
            elif device.device_type == "load_balancer":
                topology["load_balancer"] = device_info
            elif device.device_type == "business_server":
                topology["business_server"] = device_info
        
        return topology
    
    def push_config_to_device(self, device_id: str) -> Dict:
        if device_id not in self.devices:
            raise HTTPException(status_code=404, detail="Device not found")
        
        device = self.devices[device_id]
        
        try:
            management_url = f"http://{device.management_ip}:8080/config"
            response = requests.post(
                management_url,
                json=device.config,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info(f"Config pushed to {device_id}")
                return {"status": "success", "device_id": device_id}
            else:
                self.logger.error(f"Failed to push config to {device_id}: {response.status_code}")
                return {"status": "failed", "device_id": device_id, "error": response.text}
                
        except Exception as e:
            self.logger.error(f"Error pushing config to {device_id}: {e}")
            return {"status": "error", "device_id": device_id, "error": str(e)}


app = FastAPI(title="Network Controller API")
controller: Optional[NetworkController] = None


@app.post("/register")
async def register_device(registration: DeviceRegistration):
    return controller.register_device(registration)


@app.post("/config")
async def update_config(config_update: DeviceConfig):
    return controller.update_device_config(config_update)


@app.post("/status")
async def update_status(status_update: DeviceStatus):
    return controller.update_device_status(status_update)


@app.get("/device/{device_id}")
async def get_device(device_id: str):
    return controller.get_device_info(device_id)


@app.get("/devices")
async def get_devices():
    return controller.get_all_devices()


@app.get("/topology")
async def get_topology():
    return controller.get_network_topology()


@app.post("/push_config/{device_id}")
async def push_config(device_id: str):
    return controller.push_config_to_device(device_id)


@app.post("/allocate_ip")
async def allocate_ip_endpoint(request_data: dict):
    """Handle IP allocation request from routing server"""
    try:
        request = IPAllocationRequest(**request_data)
        response = controller.handle_ip_allocation_request(request)
        return asdict(response)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/allocations")
async def get_allocations():
    """Get all subnet allocations"""
    allocations = []
    for endpoint_id, allocation in controller.subnet_allocations.items():
        allocations.append(asdict(allocation))
    return {"total": len(allocations), "allocations": allocations}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": time.time()}


def main():
    global controller
    
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <config_file>")
        sys.exit(1)
    
    config_path = sys.argv[1]
    controller = NetworkController(config_path)
    
    host = controller.config['controller']['bind_address']
    port = controller.config['controller']['bind_port']
    
    controller.logger.info(f"Starting network controller on {host}:{port}")
    
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == '__main__':
    main()
