#!/bin/bash

echo "========================================"
echo "   V-SHIELD Firewall Setup Starting"
echo "========================================"

sudo apt update

sudo apt install -y python3 python3-pip python3-scapy python3-colorama iptables

echo "========================================"
echo "   Setup Completed Successfully"
echo "========================================"

echo "Run firewall using: sudo ./run.sh"