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

echo "==> installing requests + curl_cffi + tls-client"
# curl_cffi: patched libcurl, forges browser TLS/HTTP2 via impersonate=.
# tls-client: a second, independent forgery engine (Go/uTLS behind a Python binding).
python -m pip install --quiet "requests>=2.32" "curl_cffi>=0.7" "tls-client>=1.0"

echo "==> installing capture-server + test deps (h2, pytest)"
# h2: HTTP/2 state machine for the capture server's Akamai fingerprinting.
# pytest: dev/test dependency for tests/.
python -m pip install --quiet "h2>=4.1" "pytest>=8"

echo "==> installing playwright (+ chromium) for the browser-fingerprint demo"
# Heavier: pulls a ~100MB Chromium. Skip with:  SKIP_BROWSER=1 ./bootstrap.sh
if [ "${SKIP_BROWSER:-0}" != "1" ]; then
  python -m pip install --quiet "playwright>=1.44"
  python -m playwright install chromium
else
  echo "    skipped (SKIP_BROWSER=1); browser_fp.py will not run until you install it"
fi

echo
echo "Done. Now run:"
echo "  source .venv/bin/activate"
echo "  python ja3_diff.py        # network layer: TLS/HTTP2 fingerprints"
echo "  python browser_fp.py      # browser layer: headless tells"
