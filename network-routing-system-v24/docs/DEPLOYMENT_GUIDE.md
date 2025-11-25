# Deployment Guide for Specific Network Topology

This guide provides step-by-step instructions for deploying the network routing system according to the specific topology described in the requirements.

## Network Topology Overview

### Node List

| Node | IP Addresses | Location | Role |
|------|-------------|----------|------|
| **Network Access Endpoint 1** | Port1: IPv4: 192.168.3.11, IPv6: 2001:da8:205:2060:c0a8:20b<br>Port2: IPv4: 192.168.2.11, IPv6: 2001:da8:205:20c0:c0a8:20b | Development Board | Client |
| **Network Access Endpoint 2** | Port1: IPv4: 192.168.3.22, IPv6: 2001:da8:205:2060::c0a8:316<br>Port2: IPv4: 192.168.2.22, IPv6: 2001:da8:205:20c0::c0a8:316 | Development Board | Client |
| **Load Balancer** | Public IPv4: 8.146.198.12<br>Domain: aaa.bjtu.com | Cloud Server | Control Plane |
| **Routing Server 1** | Internal: 192.168.1.251<br>External: 2408:8207:1a29:8960::c0a8:1fb | Home Broadband | Router |
| **Routing Server 2** | Internal: 192.168.2.252<br>External: 2001:da8:205:20c0::c0a8:2fc | Campus Network | Router |
| **Routing Server 3** | Internal: 192.168.3.253<br>External: 2001:da8:205:2060::c0a8:3fd | Campus Network | Router |
| **Business Server** | 211.71.74.218/25 | Campus Internal | Backend |
| **Network Controller** | 211.71.65.211/24 | Campus Internal | Management |

## Pre-Deployment Checklist

### 1. Generate Pre-Shared Key

```bash
# Generate a strong PSK
PSK=$(openssl rand -base64 32)
echo "Generated PSK: $PSK"
# Save this PSK securely - you'll need it for all nodes
```

### 2. Verify Network Connectivity

```bash
# From endpoints, test IPv6 connectivity to routing servers
ping6 -c 3 2001:da8:205:20c0::c0a8:2fc  # Router 2
ping6 -c 3 2001:da8:205:2060::c0a8:3fd  # Router 3

# From routing servers, test connectivity to load balancer
curl http://8.146.198.12:8080/health
```

### 3. Open Firewall Ports

```bash
# On all routing servers
sudo ufw allow 51820/udp

# On load balancer
sudo ufw allow 8080/tcp

# On network controller
sudo ufw allow 8090/tcp
```

## Deployment Steps

### Step 1: Deploy Load Balancer (8.146.198.12)

```bash
# 1. Copy project files to server
scp -r network-routing-system root@8.146.198.12:/tmp/

# 2. SSH to server
ssh root@8.146.198.12

# 3. Install
cd /tmp/network-routing-system/scripts
chmod +x install_load_balancer.sh
./install_load_balancer.sh

# 4. Configure
nano /etc/network-routing-system/load_balancer.yaml
# No changes needed for default configuration

# 5. Start service
systemctl start load_balancer
systemctl enable load_balancer

# 6. Verify
systemctl status load_balancer
curl http://localhost:8080/health
curl http://localhost:8080/status
```

### Step 2: Deploy Network Controller (211.71.65.211)

```bash
# 1. Copy project files
scp -r network-routing-system root@211.71.65.211:/tmp/

# 2. SSH to server
ssh root@211.71.65.211

# 3. Install
cd /tmp/network-routing-system/scripts
chmod +x install_network_controller.sh
./install_network_controller.sh

# 4. Configure
nano /etc/network-routing-system/network_controller.yaml
# Update the PSK with your generated key

# 5. Start service
systemctl start network_controller
systemctl enable network_controller

# 6. Verify
systemctl status network_controller
curl http://localhost:8090/health
```

### Step 3: Deploy Routing Server 1 (192.168.1.251)

```bash
# 1. Copy project files
scp -r network-routing-system root@192.168.1.251:/tmp/

# 2. SSH to server
ssh root@192.168.1.251

# 3. Install
cd /tmp/network-routing-system/scripts
chmod +x install_routing_server.sh
./install_routing_server.sh

# 4. Configure
cp /tmp/network-routing-system/configs/routing_server_1.yaml /etc/network-routing-system/routing_server.yaml
nano /etc/network-routing-system/routing_server.yaml

# Update these fields:
# - tunnel.psk: <your-generated-psk>
# - server.egress_interface: <your-actual-interface-name>

# 5. Start service
systemctl start routing_server
systemctl enable routing_server

# 6. Verify
systemctl status routing_server
journalctl -u routing_server -n 50
ip addr show tun0
```

### Step 4: Deploy Routing Server 2 (192.168.2.252)

```bash
# 1. Copy project files
scp -r network-routing-system root@192.168.2.252:/tmp/

# 2. SSH to server
ssh root@192.168.2.252

# 3. Install
cd /tmp/network-routing-system/scripts
chmod +x install_routing_server.sh
./install_routing_server.sh

# 4. Configure
cp /tmp/network-routing-system/configs/routing_server_2.yaml /etc/network-routing-system/routing_server.yaml
nano /etc/network-routing-system/routing_server.yaml

# Update these fields:
# - tunnel.psk: <your-generated-psk>
# - server.egress_interface: <your-actual-interface-name>

# 5. Start service
systemctl start routing_server
systemctl enable routing_server

# 6. Verify
systemctl status routing_server
journalctl -u routing_server -n 50
```

### Step 5: Deploy Routing Server 3 (192.168.3.253)

```bash
# 1. Copy project files
scp -r network-routing-system root@192.168.3.253:/tmp/

# 2. SSH to server
ssh root@192.168.3.253

# 3. Install
cd /tmp/network-routing-system/scripts
chmod +x install_routing_server.sh
./install_routing_server.sh

# 4. Configure
cp /tmp/network-routing-system/configs/routing_server_3.yaml /etc/network-routing-system/routing_server.yaml
nano /etc/network-routing-system/routing_server.yaml

# Update these fields:
# - tunnel.psk: <your-generated-psk>
# - server.egress_interface: <your-actual-interface-name>

# 5. Start service
systemctl start routing_server
systemctl enable routing_server

# 6. Verify
systemctl status routing_server
journalctl -u routing_server -n 50
```

### Step 6: Deploy Network Access Endpoint 1 (Development Board)

```bash
# 1. Copy project files to endpoint
scp -r network-routing-system root@192.168.3.11:/tmp/

# 2. SSH to endpoint
ssh root@192.168.3.11

# 3. Install
cd /tmp/network-routing-system/scripts
chmod +x install_network_access_endpoint.sh
./install_network_access_endpoint.sh

# 4. Configure
cp /tmp/network-routing-system/configs/network_access_endpoint_1.yaml /etc/network-routing-system/network_access_endpoint.yaml
nano /etc/network-routing-system/network_access_endpoint.yaml

# Update these fields:
# - tunnel.psk: <your-generated-psk>
# - routers[0].bind_address: Verify this matches your Port2 IPv6
# - routers[1].bind_address: Verify this matches your Port1 IPv6

# 5. Start service
systemctl start network_access_endpoint
systemctl enable network_access_endpoint

# 6. Verify
systemctl status network_access_endpoint
journalctl -u network_access_endpoint -n 50
ip addr show tun0
ip route show
```

### Step 7: Deploy Network Access Endpoint 2 (Development Board)

```bash
# 1. Copy project files to endpoint
scp -r network-routing-system root@192.168.3.22:/tmp/

# 2. SSH to endpoint
ssh root@192.168.3.22

# 3. Install
cd /tmp/network-routing-system/scripts
chmod +x install_network_access_endpoint.sh
./install_network_access_endpoint.sh

# 4. Configure
cp /tmp/network-routing-system/configs/network_access_endpoint_2.yaml /etc/network-routing-system/network_access_endpoint.yaml
nano /etc/network-routing-system/network_access_endpoint.yaml

# Update these fields:
# - tunnel.psk: <your-generated-psk>
# - routers[0].bind_address: Verify this matches your Port2 IPv6
# - routers[1].bind_address: Verify this matches your Port1 IPv6

# 5. Start service
systemctl start network_access_endpoint
systemctl enable network_access_endpoint

# 6. Verify
systemctl status network_access_endpoint
journalctl -u network_access_endpoint -n 50
ip addr show tun0
```

## Post-Deployment Verification

### 1. Check Load Balancer Status

```bash
curl http://8.146.198.12:8080/status
```

Expected output should show all 3 routing servers as "active".

### 2. Test Tunnel Connectivity

```bash
# On Endpoint 1
ping -c 5 10.10.2.1  # Ping Router 2 TUN IP
ping -c 5 10.10.3.1  # Ping Router 3 TUN IP

# Test IPv6
ping6 -c 5 fd00:100::2
ping6 -c 5 fd00:100::3
```

### 3. Test Business Server Connectivity

```bash
# On Endpoint 1
ping -c 5 211.71.74.218
```

### 4. Monitor Tunnel Switching

```bash
# On Endpoint 1, watch logs
journalctl -u network_access_endpoint -f

# You should see:
# - Tunnel established messages
# - Load balancer query messages every 10 seconds
# - Tunnel switching messages when optimal router changes
```

### 5. Verify Metrics Reporting

```bash
# On any routing server
journalctl -u routing_server -f | grep "Metrics reported"

# Should see successful metric reports every 10 seconds
```

## Testing Failover

### Test 1: Stop Active Routing Server

```bash
# 1. Check which router is active on endpoint
curl http://8.146.198.12:8080/decision/endpoint_1

# 2. Stop that routing server
ssh root@<active-router-ip>
systemctl stop routing_server

# 3. Watch endpoint logs - should see automatic failover
ssh root@192.168.3.11
journalctl -u network_access_endpoint -f

# Expected: Tunnel switches to backup within seconds
```

### Test 2: Simulate High Load

```bash
# On one routing server, simulate high CPU
stress-ng --cpu 4 --timeout 60s

# Watch load balancer decision change
watch -n 1 'curl -s http://8.146.198.12:8080/status | jq'

# Endpoints should switch away from the loaded server
```

## Troubleshooting Common Issues

### Issue 1: Routing Server Not Reporting Metrics

**Symptoms**: Load balancer shows 0 active servers

**Solution**:
```bash
# Check routing server logs
journalctl -u routing_server -n 100

# Verify load balancer URL in config
cat /etc/network-routing-system/routing_server.yaml | grep url

# Test connectivity
curl http://8.146.198.12:8080/health
```

### Issue 2: Tunnel Not Establishing

**Symptoms**: Endpoint logs show connection failures

**Solution**:
```bash
# Check firewall on routing server
sudo ufw status
sudo ufw allow 51820/udp

# Verify IPv6 connectivity
ping6 2001:da8:205:20c0::c0a8:2fc

# Check bind address matches interface
ip -6 addr show
```

### Issue 3: PSK Mismatch

**Symptoms**: "Invalid packet" or "HMAC verification failed" in logs

**Solution**:
```bash
# Verify PSK is identical on all nodes
grep psk /etc/network-routing-system/*.yaml

# Update all configs with same PSK
# Restart all services
```

### Issue 4: No Route to Business Server

**Symptoms**: Cannot ping 211.71.74.218 from endpoint

**Solution**:
```bash
# Check routes on endpoint
ip route show

# Verify TUN interface has route
ip route show dev tun0

# Check NAT on routing server
iptables -t nat -L -n -v
```

## Performance Monitoring

### Monitor Bandwidth Usage

```bash
# On routing server
iftop -i tun0

# Or use vnstat
vnstat -i tun0 -l
```

### Monitor Tunnel Statistics

```bash
# On endpoint
watch -n 1 'ip -s link show tun0'
```

### Monitor Load Balancer Decisions

```bash
# Real-time decision monitoring
watch -n 1 'curl -s http://8.146.198.12:8080/status | jq ".servers[] | {name: .server_name, score: .score, status: .status}"'
```

## Maintenance

### Updating Configuration

```bash
# 1. Edit configuration
nano /etc/network-routing-system/<service>.yaml

# 2. Restart service
systemctl restart <service>

# 3. Verify
systemctl status <service>
```

### Rotating PSK

```bash
# 1. Generate new PSK
NEW_PSK=$(openssl rand -base64 32)

# 2. Update all configuration files
# 3. Restart services in order:
#    - Routing servers first
#    - Endpoints last
```

### Log Rotation

Logs are automatically rotated by systemd. To view:

```bash
# Current logs
journalctl -u <service> -n 100

# Logs from specific date
journalctl -u <service> --since "2025-11-10"

# Follow logs
journalctl -u <service> -f
```

## Backup and Recovery

### Backup Configuration

```bash
# Backup all configs
tar -czf network-routing-config-$(date +%Y%m%d).tar.gz /etc/network-routing-system/

# Backup to remote server
scp network-routing-config-*.tar.gz backup-server:/backups/
```

### Restore Configuration

```bash
# Extract backup
tar -xzf network-routing-config-YYYYMMDD.tar.gz -C /

# Restart services
systemctl restart routing_server
systemctl restart network_access_endpoint
```

## Scaling

### Adding More Endpoints

1. Copy endpoint configuration template
2. Update endpoint_id to unique value
3. Update IP addresses
4. Deploy using installation script

### Adding More Routing Servers

1. Copy routing server configuration template
2. Update server_id and tunnel_id to unique values
3. Update IP addresses
4. Deploy using installation script
5. Endpoints will automatically discover via load balancer

## Security Hardening

### Enable HMAC Authentication

Already implemented by default. Ensure PSK is strong:

```bash
# Generate strong PSK (32+ bytes)
openssl rand -base64 48
```

### Restrict API Access

```bash
# On load balancer, restrict to known IPs
ufw allow from 192.168.0.0/16 to any port 8080
ufw allow from 211.71.0.0/16 to any port 8080
```

### Enable TLS for APIs

For production, configure reverse proxy (nginx) with TLS:

```nginx
server {
    listen 443 ssl;
    server_name aaa.bjtu.com;
    
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    
    location / {
        proxy_pass http://localhost:8080;
    }
}
```

## Support

For issues or questions, refer to:
- Main README.md
- Protocol specification: docs/PROTOCOL.md
- System logs: `journalctl -u <service>`
