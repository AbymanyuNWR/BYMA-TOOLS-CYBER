#!/bin/bash

echo ""
echo "===================================================="
echo "  BYMA TOOLS - Installation Script"
echo "  Multi-Purpose Cybersecurity Toolkit"
echo "===================================================="
echo ""

echo "[1/3] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3 not found!"
    echo "Please install Python 3.8+ from your package manager"
    exit 1
fi
echo "[OK] Python3 found"
echo ""

echo "[2/3] Installing dependencies..."
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install dependencies"
    exit 1
fi
echo ""

echo "[3/3] Setting up directories..."
mkdir -p database output/output/reports wordlists
echo ""

echo "===================================================="
echo "  Installation Complete!"
echo "===================================================="
echo ""
echo "Usage:"
echo "  python3 main.py --help"
echo "  python3 main.py auto http://target.com"
echo ""
echo "For more information, see README.md"
