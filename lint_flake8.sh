#!/usr/bin/env bash

set -euo pipefail

# Usage:
#   bash lint_flake8.sh                # check current project
#   bash lint_flake8.sh path/to/check  # check a specific path

TARGET_PATH="${1:-.}"

if command -v flake8 >/dev/null 2>&1; then
  FLAKE8=(flake8)
elif command -v python3 >/dev/null 2>&1 && python3 -m flake8 --version >/dev/null 2>&1; then
  FLAKE8=(python3 -m flake8)
elif command -v python >/dev/null 2>&1 && python -m flake8 --version >/dev/null 2>&1; then
  FLAKE8=(python -m flake8)
elif command -v python.exe >/dev/null 2>&1 && python.exe -m flake8 --version >/dev/null 2>&1; then
  FLAKE8=(python.exe -m flake8)
elif command -v py.exe >/dev/null 2>&1 && py.exe -3 -m flake8 --version >/dev/null 2>&1; then
  FLAKE8=(py.exe -3 -m flake8)
else
  echo "flake8 is not installed. Install it first:"
  echo "  python -m pip install flake8"
  exit 1
fi

echo "Running flake8 on: ${TARGET_PATH}"

"${FLAKE8[@]}" "${TARGET_PATH}" \
  --max-line-length=120 \
  --extend-exclude=".git,__pycache__,.pytest_cache,.mypy_cache,.ruff_cache,venv,.venv,build,dist,node_modules"
