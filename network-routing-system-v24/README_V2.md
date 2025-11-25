# 网络路由系统 V2 - 部署指南

## 系统概述

本系统实现了基于智能负载均衡的分布式网络路由系统，支持动态IP地址分配、主备路由切换和分布式路由协议。

### 主要特性

- ✅ **动态子网分配**：支持10,000+网络接入端的自动IP地址分配
- ✅ **主备路由架构**：负载均衡器自动选择主备路由服务器
- ✅ **分布式路由协议**：路由服务器间自动交换路由信息
- ✅ **智能负载均衡**：基于CPU、内存、带宽、连接数的综合评分
- ✅ **自动故障切换**：毫秒级主备隧道切换
- ✅ **地址持久化**：断线重连后恢复之前的私网网段

## 系统架构

```
网络接入端 (2个开发板)
    ↓ UDP隧道 (主备)
路由服务器2、3 (校园网)
    ↓ 指标上报
负载均衡器 (云服务器)
    ↓ 主备决策
网络控制器 (校园网)
    ↓ IP分配
```

## 核心组件

### 1. 网络控制器 (Network Controller)
- **功能**：动态子网分配、地址持久化、资源管理
- **端口**：8090
- **位置**：211.71.65.211

### 2. 负载均衡器 (Load Balancer)
- **功能**：主备路由服务器选择、性能监控
- **端口**：8080
- **位置**：8.146.198.12 (域名: sinet.top)

### 3. 路由服务器 (Routing Servers)
- **功能**：隧道转发、IP分配代理、分布式路由
- **数量**：2个 (服务器2、3)
- **位置**：
  - 服务器2: 192.168.2.252 (外网: 2001:da8:205:20c0::c0a8:2fc)
  - 服务器3: 192.168.3.253 (外网: 2001:da8:205:2060::c0a8:3fd)

### 4. 网络接入端 (Network Access Endpoints)
- **功能**：双隧道管理、动态IP获取、自动切换
- **数量**：2个开发板
- **接口**：每个2个网络端口（IPv4 + IPv6）

## 初始化流程

系统按照以下9步骤初始化：

1. **DNS发现**：网络接入端通过域名sinet.top查找负载均衡器
2. **获取路由信息**：向负载均衡器请求主备路由服务器信息
3. **建立隧道**：同时建立到主备路由服务器的UDP隧道
4. **请求IP分配**：通过主路由服务器代理，向网络控制器请求子网分配
5. **配置接口**：使用分配的子网配置TUN接口
6. **路由通告**：向路由服务器通告自己的路由信息
7. **路由交换**：路由服务器间交换路由信息（分布式协议）
8. **业务数据传输**：开始通过主隧道传输业务数据
9. **持续监控**：定期查询负载均衡器，根据需要切换主备隧道

## 部署步骤

### 前置要求

- Ubuntu 22.04 系统
- Root权限
- Python 3.8+
- 网络连通性

### 1. 安装依赖

```bash
pip3 install -r requirements.txt
```

### 2. 生成预共享密钥

```bash
openssl rand -base64 32
```

将生成的密钥更新到所有配置文件的`psk`字段。

### 3. 部署顺序

#### 3.1 网络控制器 (211.71.65.211)

```bash
cd /home/ubuntu/network-routing-system
sudo python3 network_controller/controller.py configs/network_controller.yaml
```

#### 3.2 负载均衡器 (8.146.198.12)

```bash
sudo python3 load_balancer/server.py configs/load_balancer.yaml
```

#### 3.3 路由服务器2 (192.168.2.252)

```bash
sudo python3 routing_server/server.py configs/routing_server_2.yaml
```

#### 3.4 路由服务器3 (192.168.3.253)

```bash
sudo python3 routing_server/server.py configs/routing_server_3.yaml
```

#### 3.5 网络接入端1

```bash
sudo python3 network_access_endpoint/endpoint_v2.py configs/network_access_endpoint_1.yaml
```

#### 3.6 网络接入端2

```bash
sudo python3 network_access_endpoint/endpoint_v2.py configs/network_access_endpoint_2.yaml
```

### 4. 使用systemd服务（推荐）

```bash
# 安装服务
cd scripts
sudo ./install_network_controller.sh
sudo ./install_load_balancer.sh
sudo ./install_routing_server.sh
sudo ./install_network_access_endpoint.sh

# 启动服务
sudo systemctl start network_controller
sudo systemctl start load_balancer
sudo systemctl start routing_server
sudo systemctl start network_access_endpoint

# 查看状态
sudo systemctl status network_controller
sudo systemctl status load_balancer
sudo systemctl status routing_server
sudo systemctl status network_access_endpoint
```

## 验证部署

### 1. 检查网络控制器

```bash
curl http://211.71.65.211:8090/health
curl http://211.71.65.211:8090/allocations
```

### 2. 检查负载均衡器

```bash
curl http://8.146.198.12:8080/status
```

### 3. 检查隧道

```bash
# 在网络接入端
ip addr show tun0
ip route show
ping -c 5 10.100.1.1  # 测试到网关的连通性
```

### 4. 查看日志

```bash
# 网络控制器
tail -f /var/log/network_controller.log

# 负载均衡器
tail -f /var/log/load_balancer.log

# 路由服务器
tail -f /var/log/routing_server.log

# 网络接入端
tail -f /var/log/network_access_endpoint.log
```

## 配置说明

### 网络控制器配置

```yaml
ip_allocation:
  base_network_ipv4: "10.100.0.0/16"  # IPv4基础网络（支持65536个/24子网）
  base_network_ipv6: "fd00:100::/32"  # IPv6基础网络
  subnet_prefix_ipv4: 24              # 每个接入端分配/24子网
  subnet_prefix_ipv6: 64              # 每个接入端分配/64子网
  allocation_timeout: 3600            # 1小时后释放未活跃的分配
```

### 负载均衡器配置

```yaml
algorithm:
  weights:
    cpu: 0.30          # CPU权重30%
    memory: 0.20       # 内存权重20%
    bandwidth: 0.30    # 带宽权重30%
    connections: 0.20  # 连接数权重20%
  anti_flap_threshold: 0.1   # 防抖阈值
  anti_flap_hold_time: 30    # 防抖保持时间（秒）
```

### 路由服务器配置

```yaml
network_controller:
  url: "http://211.71.65.211:8090"  # 网络控制器地址

peer_routers:  # 对等路由服务器（用于分布式路由）
  - router_id: "router_3"
    url: "http://192.168.3.253:8080"
```

## 故障排除

### 问题1：网络接入端无法获取IP地址

**原因**：网络控制器未启动或无法访问

**解决**：
```bash
# 检查网络控制器状态
curl http://211.71.65.211:8090/health

# 检查路由服务器日志
tail -f /var/log/routing_server.log | grep "allocation"
```

### 问题2：隧道无法建立

**原因**：防火墙阻止UDP端口或IPv6不可达

**解决**：
```bash
# 检查UDP端口
sudo netstat -ulnp | grep 51820

# 测试IPv6连通性
ping6 2001:da8:205:20c0::c0a8:2fc
```

### 问题3：主备切换不工作

**原因**：负载均衡器未收到路由服务器指标

**解决**：
```bash
# 检查负载均衡器状态
curl http://8.146.198.12:8080/status

# 检查路由服务器指标上报
tail -f /var/log/routing_server.log | grep "Metrics reported"
```

### 问题4：断线重连后IP地址改变

**原因**：网络控制器未保存之前的分配

**解决**：
```bash
# 检查分配记录
curl http://211.71.65.211:8090/allocations

# 确认reconnect参数正确传递
tail -f /var/log/network_access_endpoint.log | grep "reconnect"
```

## 性能指标

- **子网分配容量**：65,536个/24子网（支持65,536个接入端）
- **隧道切换延迟**：< 10ms（本地健康检查）
- **指标上报频率**：每10秒
- **决策响应时间**：< 1秒
- **地址分配时间**：< 5秒

## 扩展性

系统设计支持：
- **网络接入端**：10,000+（通过/24子网分配）
- **路由服务器**：100+（通过分布式路由协议）
- **业务载荷**：每个接入端254个设备

## 安全建议

1. **更改预共享密钥**：使用强随机密钥
2. **启用防火墙**：只开放必要端口
3. **使用TLS**：为控制平面API启用HTTPS
4. **定期更新**：保持系统和依赖包最新

## 技术支持

如有问题，请查看日志文件或联系系统管理员。

## 版本信息

- **版本**：2.0
- **发布日期**：2025-11-12
- **兼容系统**：Ubuntu 22.04
