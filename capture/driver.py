"""Drive clients sequentially at a CaptureServer and return one joined Record each.

Client strings: curl:<profile>, tls:<identifier>, stdlib:urllib,
browser:chromium (alias playwright:chromium).
"""
from __future__ import annotations

import argparse
import ssl
import sys
import tempfile
import urllib.request
import uuid
from pathlib import Path

from capture.record import Record, dump_run
from capture.server import CaptureServer

try:  # reuse the same UA as the ja3_diff experiment
    from ja3_diff import CHROME_UA
except ImportError:  # pragma: no cover
    CHROME_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

TIMEOUT = 15
DEFAULT_CLIENTS = ["curl:chrome124", "curl:safari17_0", "tls:chrome_124",
                   "stdlib:urllib", "browser:chromium"]


def _curl(url: str, profile: str) -> None:
    from curl_cffi import requests as creq
    creq.get(url, headers={"User-Agent": CHROME_UA}, impersonate=profile,
             verify=False, timeout=TIMEOUT)


def _tls(url: str, ident: str) -> None:
    import tls_client
    s = tls_client.Session(client_identifier=ident, random_tls_extension_order=True)
    s.get(url, headers={"User-Agent": CHROME_UA}, insecure_skip_verify=True,
          timeout_seconds=TIMEOUT)


def _stdlib(url: str) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": CHROME_UA})
    with urllib.request.urlopen(req, context=ctx, timeout=TIMEOUT) as r:
        r.read()


def _wait(pred, timeout: float) -> bool:
    import time
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def run_drivers(server_port: int, clients: list[str],
                server: CaptureServer | None = None) -> list[Record]:
    server = server or CaptureServer._by_port.get(server_port)
    if server is None:
        raise ValueError("no CaptureServer running on port %d" % server_port)
    out: list[Record] = []
    for client in clients:
        kind, _, arg = client.partition(":")
        before = set(server.records)
        nonce = None
        base = "https://127.0.0.1:%d" % server_port
        if kind == "curl":
            _curl(base + "/", arg)
        elif kind == "tls":
            _tls(base + "/", arg)
        elif kind == "stdlib":
            _stdlib(base + "/")
        elif kind in ("browser", "playwright"):
            nonce = "drv-" + uuid.uuid4().hex[:12]
            _browser_run(server_port, nonce, server)
        else:
            raise ValueError("unknown client %r" % client)

        def new() -> list[Record]:
            return [server.records[k] for k in list(server.records) if k not in before]

        if nonce is not None:
            want = "/probe/" + nonce
            def primary():
                return [r for r in new() if (r.http or {}).get("path") == want
                        and r.js is not None]
        else:
            def primary():
                return [r for r in new() if r.http is not None]
        if not _wait(lambda: bool(primary()), TIMEOUT):
            raise RuntimeError("no record captured for %s" % client)
        rec = primary()[0]  # R7: selected by path, incidental records ignored
        rec.client_label = client
        out.append(rec)
    return out


def _browser_run(port: int, nonce: str, server: CaptureServer) -> None:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, timeout=30000)
        try:
            page = browser.new_context(ignore_https_errors=True).new_page()
            page.goto("https://localhost:%d/probe/%s" % (port, nonce),
                      timeout=TIMEOUT * 1000)
            want = "/probe/" + nonce
            _wait(lambda: any((r.http or {}).get("path") == want and r.js is not None
                              for r in list(server.records.values())), TIMEOUT)
        finally:
            browser.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="runs/2026-10-25")
    ap.add_argument("--clients", default=",".join(DEFAULT_CLIENTS))
    a = ap.parse_args(argv)
    import subprocess
    with tempfile.TemporaryDirectory() as d:
        cert, key = str(Path(d) / "c.pem"), str(Path(d) / "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                        "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        srv = CaptureServer(cert, key)
        port = srv.start()
        try:
            recs = run_drivers(port, a.clients.split(","), server=srv)
        finally:
            srv.stop()
    dump_run(recs, a.out, command="python -m capture.driver --out %s --clients %s"
             % (a.out, a.clients))
    print("wrote %d records to %s" % (len(recs), a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
