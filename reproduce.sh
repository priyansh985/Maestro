#!/usr/bin/env bash
# reproduce.sh - clean-environment reproduction of arXiv:2508.10043
# Implements the "reproduce.sh" requirement per the Stage 3 spec.
#
# Usage (bash):
#   bash reproduce.sh            # full repro with no LLM keys
#   SKIP_INSTALL=1 bash reproduce.sh
#
# Outputs:
#   results/run.log
#   results/table4_threat_matrix.csv|.md
#   results/table5_security_risk.csv|.md
#   results/tc1.json
#   results/tc2.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

PY="${PYTHON:-python}"
if [[ -x .venv/bin/python ]]; then PY=".venv/bin/python"; fi
if [[ -x .venv/Scripts/python.exe ]]; then PY=".venv/Scripts/python.exe"; fi

if [[ "${SKIP_INSTALL:-0}" != "1" ]]; then
  echo "[reproduce] creating venv in .venv ..."
  "${PYTHON:-python}" -m venv .venv || true
  if [[ -x .venv/Scripts/python.exe ]]; then PY=".venv/Scripts/python.exe"; else PY=".venv/bin/python"; fi
  "$PY" -m pip install --upgrade pip
  "$PY" -m pip install -e ".[dev]"
fi

mkdir -p data/pcap data/memory results

echo "[reproduce] Validating configs/threats.yaml against Eq.(1) ..."
"$PY" -m maestro.scripts.validate_threats

echo "[reproduce] Running unit tests ..."
"$PY" -m pytest -q

echo "[reproduce] Running TC1 + TC2 + Table 4 + Table 5 ..."
"$PY" -m maestro.experiments.runner

echo "[reproduce] Done. See results/ for tables and logs."
