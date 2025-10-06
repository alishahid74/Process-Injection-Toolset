#!/usr/bin/env bash
set -euo pipefail

echo "[*] Activate venv before running this script: source .venv/bin/activate"
echo "[*] Running injection detection..."
mkdir -p results/injection
python3 src/angr_detect_injection.py --binary samples/injection_demo --out results/injection/found_input.txt

echo "[*] Optional: run sample in sandbox (manual)"
echo "To run: ./samples/injection_demo \"\$(cat results/injection/found_input.txt)\""
echo "[*] If you want to patch, run patch script:"
echo "python3 src/patch_injection_lief.py --binary samples/injection_demo --addr 0x4011ec --size 8 --out samples/injection_demo_patched"
