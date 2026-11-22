#!/bin/bash
# Double-click to start the ARGUS triage workbench. It opens in your browser.
# Leave this window open while you use ARGUS; close it to stop ARGUS.
cd "$(dirname "$0")/source code" || exit 1
exec ../.venv/bin/python -m argus.cli ui --port 8766
