#!/usr/bin/env bash
# KJAGU Linux Launcher

set -e

echo ""
echo "  ========================================================================"
echo "     KJAGU // Anti-Spyware & Endpoint Threat Hunter v3.1"
echo "     Absolute Immortal Inc. -- Defensive Security Research"
echo "     100% Free & Local -- Zero API Keys Required"
echo "  ========================================================================"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "  [!] ERROR: python3 is not installed."
    echo "      Install Python 3 via: sudo apt install python3 python3-pip"
    exit 1
fi

if ! python3 -c "import psutil" &> /dev/null; then
    echo "  [*] First run detected. Installing dependencies..."
    pip3 install -r requirements.txt || pip install -r requirements.txt
fi

python3 kjagu_core.py "$@"
