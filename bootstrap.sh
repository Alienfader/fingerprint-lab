#!/usr/bin/env bash
# Build a local venv for the JA3 diff lab and install the two optional clients.
# Safe to re-run. Nothing here touches your CTF repo or global Python.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
echo "==> creating venv (.venv) with $($PY --version)"
"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> upgrading pip"
python -m pip install --quiet --upgrade pip

echo "==> installing pinned dependencies (requirements.txt)"
# requests / curl_cffi / tls_client: the automated-client population.
# h2: HTTP/2 state machine for the capture server's Akamai fingerprinting.
# playwright: real-browser driver (chromium build installed separately below).
# pytest: test runner.
python -m pip install --quiet -r requirements.txt

echo "==> installing the Chromium build for the browser-layer experiments (Phases 3 & 5)"
# Heavier: pulls a ~150MB Chromium. Skip with:  SKIP_BROWSER=1 ./bootstrap.sh
if [ "${SKIP_BROWSER:-0}" != "1" ]; then
  python -m playwright install chromium
else
  echo "    skipped (SKIP_BROWSER=1); the browser-layer tests/CLIs will not run until you install it"
fi

echo
echo "Done. Verify the core (75 tests, ~2s, no browser/loopback/network):"
echo "  .venv/bin/python -m pytest -m \"not integration\""
echo
echo "Then explore:"
echo "  .venv/bin/python -m pytest                              # full suite (launches Chromium)"
echo "  .venv/bin/python -m crosslayer --out runs/2026-10-26-crosslayer   # a phase experiment"
echo "  .venv/bin/python ja3_diff.py                            # origin script: TLS/HTTP2 fingerprints"
