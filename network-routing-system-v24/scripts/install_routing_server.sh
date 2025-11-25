#!/bin/bash
set -e

echo "Installing Routing Server..."

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

apt-get update
apt-get install -y python3 python3-pip iproute2 iptables

pip3 install pyyaml psutil requests

mkdir -p /opt/network-routing-system
mkdir -p /etc/network-routing-system
mkdir -p /var/log

cp -r ../common /opt/network-routing-system/
cp -r ../routing_server /opt/network-routing-system/

if [ ! -f /etc/network-routing-system/routing_server.yaml ]; then
    cp ../configs/routing_server_1.yaml /etc/network-routing-system/routing_server.yaml
    echo "Configuration file created at /etc/network-routing-system/routing_server.yaml"
    echo "Please edit this file with your specific settings"
fi

cp routing_server.service /etc/systemd/system/
systemctl daemon-reload

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Edit /etc/network-routing-system/routing_server.yaml with your configuration"
echo "2. Update the PSK (pre-shared key) in the configuration"
echo "3. Start the service: systemctl start routing_server"
echo "4. Enable auto-start: systemctl enable routing_server"
echo "5. Check status: systemctl status routing_server"
echo "6. View logs: journalctl -u routing_server -f"
