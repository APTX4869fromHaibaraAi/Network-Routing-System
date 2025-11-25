#!/bin/bash
set -e

echo "Installing Network Controller..."

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

apt-get update
apt-get install -y python3 python3-pip

pip3 install pyyaml fastapi uvicorn pydantic requests

mkdir -p /opt/network-routing-system
mkdir -p /etc/network-routing-system
mkdir -p /var/log

cp -r ../network_controller /opt/network-routing-system/

if [ ! -f /etc/network-routing-system/network_controller.yaml ]; then
    cp ../configs/network_controller.yaml /etc/network-routing-system/network_controller.yaml
    echo "Configuration file created at /etc/network-routing-system/network_controller.yaml"
    echo "Please edit this file with your specific settings"
fi

cp network_controller.service /etc/systemd/system/
systemctl daemon-reload

echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Edit /etc/network-routing-system/network_controller.yaml with your configuration"
echo "2. Update the PSK (pre-shared key) in the configuration"
echo "3. Start the service: systemctl start network_controller"
echo "4. Enable auto-start: systemctl enable network_controller"
echo "5. Check status: systemctl status network_controller"
echo "6. View logs: journalctl -u network_controller -f"
echo "7. Test API: curl http://localhost:8090/health"
