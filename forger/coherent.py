"""Self-only coherent forger: drives curl_cffi against the researcher's own
loopback capture server and fabricates the JS /collect payload."""
import json
import time
import uuid

from curl_cffi import requests as creq

from ja3_diff import CHROME_UA

_FIREFOX_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) "
    "Gecko/20100101 Firefox/125.0"
)
_REAL_RENDERER = "ANGLE (Apple, Apple M1 Pro, OpenGL 4.1 Metal - 88)"
_REAL_VENDOR = "Google Inc. (Apple)"


def build_payload(*, include_js: bool = True, webdriver: bool = False,
                  gpu: str = "real", window_chrome: bool = True,
                  ua_match: bool = True) -> dict:
    """Fabricate the 12-field probe payload. Defaults are fully coherent.

    include_js is accepted for documentation; the no-JS forger is driven by
    passing payload=None to forge().
    """
    if gpu == "swiftshader":
        vendor, renderer = "Google Inc. (Google)", "Google SwiftShader"
    else:
        vendor, renderer = _REAL_VENDOR, _REAL_RENDERER
    return {
        "webdriver": webdriver,
        "userAgent": CHROME_UA if ua_match else _FIREFOX_UA,
        "pluginsLen": 5,
        "pluginNames": ["PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer",
                        "Microsoft Edge PDF Viewer", "WebKit built-in PDF"],
        "languages": ["en-US", "en"],
        "hasWindowChrome": window_chrome,
        "hardwareConc": 10,
        "platform": "MacIntel",
        "webglVendor": vendor,
        "webglRenderer": renderer,
        "permMismatch": False,
        "canvas": "forged-canvas-" + uuid.uuid4().hex[:8],
    }


def forge(server, *, payload: dict | None, profile: str = "chrome124",
          ua: str = CHROME_UA):
    """GET /probe/<nonce>, optionally POST payload to /collect/<nonce>, and
    return the joined Record. Loopback only: the host is hardcoded."""
    nonce = "frg" + uuid.uuid4().hex[:12]
    base = f"https://127.0.0.1:{server.port}"
    creq.get(f"{base}/probe/{nonce}", headers={"User-Agent": ua},
             impersonate=profile, verify=False, timeout=10)
    if payload is not None:
        creq.post(f"{base}/collect/{nonce}",
                  headers={"User-Agent": ua, "Content-Type": "application/json"},
                  data=json.dumps(payload), impersonate=profile,
                  verify=False, timeout=10)
    path = f"/probe/{nonce}"
    deadline = time.time() + 8
    while time.time() < deadline:
        for r in list(server.records.values()):
            if (r.http or {}).get("path") == path and (
                    payload is None or r.js is not None):
                return r
        time.sleep(0.05)
    raise RuntimeError(f"no joined record for {path} within timeout")
