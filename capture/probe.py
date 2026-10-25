"""Probe page: serves probe.js with a nonce so the browser's in-page fingerprint
can be POSTed back and joined to the connection that fetched the page."""
from __future__ import annotations

import re
from pathlib import Path

NONCE_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_JS_PATH = Path(__file__).parent / "static" / "probe.js"


def valid_nonce(nonce: str) -> bool:
    return NONCE_RE.fullmatch(nonce) is not None


def probe_js() -> str:
    return _JS_PATH.read_text(encoding="utf-8")


def probe_html(nonce: str) -> str:
    if not valid_nonce(nonce):
        raise ValueError("invalid nonce")
    return ("<!doctype html><html><head><meta charset=\"utf-8\"><title>probe</title>"
            "</head><body><script>window.PROBE_NONCE=\"%s\";</script>"
            "<script>%s</script></body></html>" % (nonce, probe_js()))
