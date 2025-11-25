#!/bin/bash
set -e

echo "Installing Load Balancer..."

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

apt-get update
apt-get install -y python3 python3-pip

pip3 install pyyaml fastapi uvicorn pydantic

mkdir -p /opt/network-routing-system
mkdir -p /etc/network-routing-system
mkdir -p /var/log

cp -r ../load_balancer /opt/network-routing-system/

if [ ! -f /etc/network-routing-system/load_balancer.yaml ]; then
    cp ../configs/load_balancer.yaml /etc/network-routing-system/load_balancer.yaml
    echo "Configuration file created at /etc/network-routing-system/load_balancer.yaml"
    echo "Please edit this file with your specific settings"
fi

cp load_balancer.service /etc/systemd/system/
systemctl daemon-reload

echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Edit /etc/network-routing-system/load_balancer.yaml with your configuration"
echo "2. Start the service: systemctl start load_balancer"
echo "3. Enable auto-start: systemctl enable load_balancer"
echo "4. Check status: systemctl status load_balancer"
echo "5. View logs: journalctl -u load_balancer -f"
echo "6. Test API: curl http://localhost:8080/health"
