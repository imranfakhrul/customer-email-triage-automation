#!/usr/bin/env bash
# Customer Email Triage Automation — Phase 2 Background Worker Launcher
# Milestone [P2-09]: Persistent Phase 2 Queue Worker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

PYTHON_BIN="./venv/bin/python"
if [ ! -x "${PYTHON_BIN}" ]; then
    PYTHON_BIN="python3"
fi

exec "${PYTHON_BIN}" scripts/phase2_worker.py "$@"
