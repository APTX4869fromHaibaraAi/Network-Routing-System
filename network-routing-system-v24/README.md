# Network Routing System with Intelligent Load Balancing

A distributed network routing system with automatic failover and intelligent load balancing for UDP tunnels. This system enables network access endpoints to dynamically select optimal routing servers based on real-time performance metrics.

## System Architecture

### Components

1. **Network Access Endpoints** - Client devices that establish dual UDP tunnels to routing servers
2. **Routing Servers** - Forward tunneled traffic and report performance metrics
3. **Load Balancer** - Collects metrics and provides routing decisions
4. **Network Controller** - Manages device registration, configuration, and monitoring

### Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                    Internet / Campus Network                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        │                     │                     │
   ┌────▼────┐          ┌────▼────┐          ┌────▼────┐
   │ Router  │          │ Router  │          │ Router  │
   │ Server 1│          │ Server 2│          │ Server 3│
   └────┬────┘          └────┬────┘          └────┬────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Load Balancer     │
                    │  (8.146.198.12)    │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │ Network Controller │
                    │ (211.71.65.211)    │
                    └────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   ┌────▼────┐          ┌────▼────┐
   │Endpoint │          │Endpoint │
   │    1    │          │    2    │
   └─────────┘          └─────────┘
```

## Features

### Core Functionality

- **Dual UDP Tunnel Management**: Each endpoint maintains two simultaneous tunnels for redundancy
- **IPv4 and IPv6 Support**: Tunnels support both IPv4 and IPv6 payload encapsulation
- **Intelligent Load Balancing**: Weighted scoring algorithm based on CPU, memory, bandwidth, and connection count
- **Automatic Failover**: Millisecond-level tunnel switching with local health checks
- **Anti-Flap Protection**: Prevents frequent switching between routers
- **HMAC Authentication**: Tunnel packets authenticated with HMAC-SHA256
- **Real-time Metrics**: Routing servers report metrics every 10 seconds
- **Centralized Management**: Network controller for device registration and configuration

### Performance Characteristics

- **Tunnel Switching**: Sub-100ms failover time
- **Metrics Reporting**: 10-second intervals
- **Keepalive**: 10-second intervals with 30-second timeout
- **MTU**: 1400 bytes for TUN interfaces

## Installation

### Prerequisites

- Ubuntu 22.04 LTS
- Python 3.8 or higher
- Root access
- Network connectivity between all nodes

### Installing Routing Server

```bash
cd scripts
chmod +x install_routing_server.sh
sudo ./install_routing_server.sh
```

### Installing Load Balancer

```bash
cd scripts
chmod +x install_load_balancer.sh
sudo ./install_load_balancer.sh
```

### Installing Network Access Endpoint

```bash
cd scripts
chmod +x install_network_access_endpoint.sh
sudo ./install_network_access_endpoint.sh
```

### Installing Network Controller

```bash
cd scripts
chmod +x install_network_controller.sh
sudo ./install_network_controller.sh
```

## Configuration

### Pre-Shared Key (PSK)

**IMPORTANT**: Before deploying, generate a strong pre-shared key and update it in all configuration files:

```bash
# Generate a random PSK
openssl rand -base64 32

# Update in all config files:
# - /etc/network-routing-system/routing_server.yaml
# - /etc/network-routing-system/network_access_endpoint.yaml
# - /etc/network-routing-system/network_controller.yaml
```

### Routing Server Configuration

Edit `/etc/network-routing-system/routing_server.yaml`:

```yaml
server:
  server_id: "router_1"
  name: "Routing Server 1"
  tunnel_id: 1001
  bind_address: "::"              # IPv6 any address
  bind_port: 51820
  internal_ip: "192.168.1.251"    # Internal network IP
  external_ip: "2408:8207:1a29:8960::c0a8:1fb"  # External IPv6
  egress_interface: "eth0"        # Network interface for NAT
  log_file: "/var/log/routing_server_1.log"

tunnel:
  psk: "your-pre-shared-key-here"
  interface_name: "tun0"
  tun_ipv4: "10.10.1.1"
  tun_ipv6: "fd00:100::1"

load_balancer:
  url: "http://8.146.198.12:8080"

metrics:
  report_interval: 10
```

### Load Balancer Configuration

Edit `/etc/network-routing-system/load_balancer.yaml`:

```yaml
server:
  bind_address: "0.0.0.0"
  bind_port: 8080
  log_file: "/var/log/load_balancer.log"

algorithm:
  weights:
    cpu: 0.30          # CPU weight (30%)
    memory: 0.20       # Memory weight (20%)
    bandwidth: 0.30    # Bandwidth weight (30%)
    connections: 0.20  # Connection count weight (20%)
  max_bandwidth_mbps: 1000
  max_connections: 100
  anti_flap_threshold: 0.05    # Minimum score difference to switch
  anti_flap_hold_time: 30      # Seconds to hold before allowing switch

business_server:
  ip: "211.71.74.218"
```

### Network Access Endpoint Configuration

Edit `/etc/network-routing-system/network_access_endpoint.yaml`:

```yaml
endpoint:
  endpoint_id: "endpoint_1"
  name: "Network Access Endpoint 1"
  log_file: "/var/log/network_access_endpoint_1.log"

tunnel:
  psk: "your-pre-shared-key-here"
  interface_name: "tun0"
  tun_ipv4: "10.10.100.11"
  tun_ipv6: "fd00:100::11"
  port: 51820
  keepalive_interval: 10
  routes:
    - "211.71.74.0/24"    # Business server subnet
    - "211.71.65.0/24"    # Controller subnet

routers:
  - router_id: "router_2"
    internal_ip: "192.168.2.252"
    external_ip: "2001:da8:205:20c0::c0a8:2fc"
    bind_address: "2001:da8:205:20c0:c0a8:20b"  # Local interface IPv6
  - router_id: "router_3"
    internal_ip: "192.168.3.253"
    external_ip: "2001:da8:205:2060::c0a8:3fd"
    bind_address: "2001:da8:205:2060:c0a8:20b"

load_balancer:
  url: "http://8.146.198.12:8080"
  poll_interval: 10
```

### Network Controller Configuration

Edit `/etc/network-routing-system/network_controller.yaml`:

```yaml
controller:
  bind_address: "0.0.0.0"
  bind_port: 8090
  log_file: "/var/log/network_controller.log"

ip_allocation:
  tun_ipv4_pool:
    base: "10.10.100.0"
    start: 1
    end: 254
  tun_ipv6_pool:
    base: "fd00:100::"
    start: 1
    end: 65535

security:
  default_psk: "your-pre-shared-key-here"

tunnel:
  default_port: 51820
```

## Deployment

### 1. Deploy Load Balancer (Cloud Server)

```bash
# On 8.146.198.12
sudo systemctl start load_balancer
sudo systemctl enable load_balancer
sudo systemctl status load_balancer

# Test
curl http://localhost:8080/health
```

### 2. Deploy Network Controller (Campus Network)

```bash
# On 211.71.65.211
sudo systemctl start network_controller
sudo systemctl enable network_controller
sudo systemctl status network_controller

# Test
curl http://localhost:8090/health
```

### 3. Deploy Routing Servers

```bash
# On each routing server (1, 2, 3)
sudo systemctl start routing_server
sudo systemctl enable routing_server
sudo systemctl status routing_server

# Check logs
sudo journalctl -u routing_server -f
```

### 4. Deploy Network Access Endpoints

```bash
# On each endpoint device
sudo systemctl start network_access_endpoint
sudo systemctl enable network_access_endpoint
sudo systemctl status network_access_endpoint

# Check logs
sudo journalctl -u network_access_endpoint -f
```

## Operation

### Starting Services

```bash
# Start individual service
sudo systemctl start <service_name>

# Start all services (on each node)
sudo systemctl start routing_server        # On routing servers
sudo systemctl start load_balancer         # On load balancer
sudo systemctl start network_access_endpoint  # On endpoints
sudo systemctl start network_controller    # On controller
```

### Stopping Services

```bash
sudo systemctl stop <service_name>
```

### Viewing Logs

```bash
# Real-time logs
sudo journalctl -u <service_name> -f

# Recent logs
sudo journalctl -u <service_name> -n 100

# Logs since boot
sudo journalctl -u <service_name> -b
```

### Monitoring

#### Load Balancer Status

```bash
curl http://8.146.198.12:8080/status
```

Response:
```json
{
  "timestamp": 1699660800.0,
  "total_servers": 3,
  "active_servers": 3,
  "servers": [
    {
      "server_id": "router_1",
      "server_name": "Routing Server 1",
      "status": "active",
      "cpu_percent": 25.5,
      "memory_percent": 45.2,
      "bandwidth_mbps": 150.3,
      "active_tunnels": 5,
      "score": 0.785
    }
  ],
  "active_decisions": 2
}
```

#### Network Controller Status

```bash
curl http://211.71.65.211:8090/devices
curl http://211.71.65.211:8090/topology
```

#### Check Tunnel Status

```bash
# On endpoint
ip link show tun0
ip addr show tun0
ip route show

# Test connectivity through tunnel
ping -I tun0 10.10.1.1
ping6 -I tun0 fd00:100::1
```

## Troubleshooting

### Tunnel Not Establishing

1. Check firewall rules:
```bash
sudo ufw status
sudo ufw allow 51820/udp
```

2. Verify network connectivity:
```bash
ping6 2001:da8:205:20c0::c0a8:2fc
```

3. Check service logs:
```bash
sudo journalctl -u network_access_endpoint -n 50
```

### Routing Server Not Reporting Metrics

1. Check load balancer connectivity:
```bash
curl http://8.146.198.12:8080/health
```

2. Verify configuration:
```bash
cat /etc/network-routing-system/routing_server.yaml
```

3. Check service status:
```bash
sudo systemctl status routing_server
```

### High Tunnel Switching Frequency

1. Check anti-flap settings in load balancer config
2. Increase `anti_flap_hold_time` value
3. Increase `anti_flap_threshold` value
4. Monitor server metrics for instability

### Packet Loss

1. Check MTU settings:
```bash
ip link show tun0
# Should show mtu 1400
```

2. Verify HMAC authentication:
```bash
# Check logs for authentication failures
sudo journalctl -u routing_server | grep -i hmac
```

3. Check network congestion:
```bash
# On routing server
iftop -i eth0
```

## Security Considerations

### Pre-Shared Key Management

- Use strong, randomly generated PSKs (minimum 32 bytes)
- Rotate PSKs periodically
- Store PSKs securely (file permissions 600)
- Use different PSKs for production and testing

### Firewall Configuration

```bash
# On routing servers - allow tunnel port
sudo ufw allow 51820/udp

# On load balancer - allow API port
sudo ufw allow 8080/tcp

# On network controller - allow API port
sudo ufw allow 8090/tcp
```

### Network Isolation

- Deploy load balancer on separate network segment
- Use VPN or private network for management traffic
- Restrict API access to known IP ranges
- Enable TLS for API endpoints in production

## Performance Tuning

### System Parameters

```bash
# Increase UDP buffer sizes
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
sudo sysctl -w net.core.rmem_default=26214400
sudo sysctl -w net.core.wmem_default=26214400

# Optimize conntrack
sudo sysctl -w net.netfilter.nf_conntrack_max=1000000
sudo sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=7200
```

### Load Balancer Algorithm Tuning

Adjust weights based on your priorities:

- **Low latency priority**: Increase bandwidth weight
- **High availability priority**: Increase connection count weight
- **Resource efficiency**: Increase CPU and memory weights

### Tunnel Keepalive Tuning

For unstable networks:
- Decrease `keepalive_interval` (e.g., 5 seconds)
- Increase health check frequency

For stable networks:
- Increase `keepalive_interval` (e.g., 20 seconds)
- Reduce overhead

## API Reference

### Load Balancer API

#### POST /metrics
Submit routing server metrics

Request:
```json
{
  "server_id": "router_1",
  "server_name": "Routing Server 1",
  "timestamp": 1699660800.0,
  "cpu_percent": 25.5,
  "memory_percent": 45.2,
  "bandwidth_mbps": 150.3,
  "active_tunnels": 5,
  "total_rx_packets": 1000000,
  "total_tx_packets": 950000,
  "internal_ip": "192.168.1.251",
  "external_ip": "2408:8207:1a29:8960::c0a8:1fb"
}
```

#### GET /decision/{endpoint_id}
Get optimal routing decision

Response:
```json
{
  "optimal_router_id": "router_2",
  "optimal_router_internal_ip": "192.168.2.252",
  "optimal_router_external_ip": "2001:da8:205:20c0::c0a8:2fc",
  "business_server_ip": "211.71.74.218",
  "score": 0.825,
  "timestamp": 1699660800.0
}
```

#### GET /status
Get load balancer status

#### GET /health
Health check endpoint

### Network Controller API

#### POST /register
Register a new device

#### POST /config
Update device configuration

#### POST /status
Update device status

#### GET /device/{device_id}
Get device information

#### GET /devices
List all devices

#### GET /topology
Get network topology

#### POST /push_config/{device_id}
Push configuration to device

#### GET /health
Health check endpoint

## Protocol Specification

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for detailed UDP tunnel protocol specification.

## License

This project is provided as-is for educational and research purposes.

## Support

For issues, questions, or contributions, please contact the system administrator.

## Version History

- **v1.0.0** (2025-11-11): Initial release
  - Dual UDP tunnel support
  - Intelligent load balancing
  - Automatic failover
  - Network controller integration
  - HMAC authentication
