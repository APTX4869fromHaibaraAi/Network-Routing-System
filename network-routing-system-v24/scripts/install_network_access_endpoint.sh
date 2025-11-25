#!/bin/bash
set -e

echo "Installing Network Access Endpoint..."

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

apt-get update
apt-get install -y python3 python3-pip iproute2

pip3 install pyyaml requests

mkdir -p /opt/network-routing-system
mkdir -p /etc/network-routing-system
mkdir -p /var/log

cp -r ../common /opt/network-routing-system/
cp -r ../network_access_endpoint /opt/network-routing-system/

if [ ! -f /etc/network-routing-system/network_access_endpoint.yaml ]; then
    cp ../configs/network_access_endpoint_1.yaml /etc/network-routing-system/network_access_endpoint.yaml
    echo "Configuration file created at /etc/network-routing-system/network_access_endpoint.yaml"
    echo "Please edit this file with your specific settings"
fi

cp network_access_endpoint.service /etc/systemd/system/
systemctl daemon-reload

echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Edit /etc/network-routing-system/network_access_endpoint.yaml with your configuration"
echo "2. Update the PSK (pre-shared key) in the configuration"
echo "3. Update router addresses and bind addresses for your network interfaces"
echo "4. Start the service: systemctl start network_access_endpoint"
echo "5. Enable auto-start: systemctl enable network_access_endpoint"
echo "6. Check status: systemctl status network_access_endpoint"
echo "7. View logs: journalctl -u network_access_endpoint -f"
