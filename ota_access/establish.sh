#!/bin/sh
sudo openvpn --cert /home/pi/ota_access/vpn_client.crt --key /home/pi/ota_access/vpn_client.key --config /home/pi/ota_access/3rdparty-client-config.ovpn
