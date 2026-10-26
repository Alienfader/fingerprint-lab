import ssl
import subprocess
import time
import urllib.request

import pytest

from capture.server import CaptureServer


@pytest.fixture
def server(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
         "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    srv = CaptureServer(str(cert), str(key))
    srv.port = srv.start()
    yield srv
    srv.stop()


def _ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get(server, path) -> str:
    url = "https://127.0.0.1:%d%s" % (server.port, path)
    with urllib.request.urlopen(url, context=_ctx(), timeout=5) as r:
        return r.read().decode("utf-8")


def _post(server, path, body: bytes):
    url = "https://127.0.0.1:%d%s" % (server.port, path)
    req = urllib.request.Request(url, data=body, method="POST")
    with urllib.request.urlopen(req, context=_ctx(), timeout=5) as r:
        return r.status


def _wait_probe_record(server, nonce, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        with server._lock:
            rid = server._nonce_records.get(nonce)
            rec = server.records.get(rid)
        if rec is not None and rec.js is not None:
            return rec
        time.sleep(0.05)
    raise AssertionError("no joined record for %s" % nonce)
