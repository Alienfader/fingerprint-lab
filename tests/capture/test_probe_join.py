import json
import ssl
import socket

import curl_cffi.requests as creq
import pytest

from tests.capture.conftest import wait_for


def _raw_h1(port, payload: bytes) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        with ctx.wrap_socket(s, server_hostname="localhost") as t:
            t.settimeout(5)
            t.sendall(payload)
            out = b""
            while True:
                c = t.recv(65536)
                if not c:
                    return out
                out += c


@pytest.mark.integration
def test_browser_probe_joins_to_connection(server):
    sync_api = pytest.importorskip("playwright.sync_api")
    nonce = "nonce-browser-1"
    with sync_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True, timeout=20000)
        except Exception as e:  # chromium not installed
            pytest.skip("chromium unavailable: %s" % type(e).__name__)
        try:
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            page.goto("https://localhost:%d/probe/%s" % (server.port, nonce),
                      timeout=15000)
            assert wait_for(lambda: any(r.js is not None
                                        for r in list(server.records.values())), 15)
        finally:
            browser.close()
    joined = [r for r in list(server.records.values()) if r.js is not None]
    assert len(joined) == 1
    r = joined[0]
    assert r.tls and r.tls["ja4"]
    assert "userAgent" in r.js and "webdriver" in r.js
    assert "canvas" in r.js and "webglRenderer" in r.js
    assert r.http is not None  # the GET connection's header layer, same record


def test_non_browser_client_records_js_none_after_timeout(server):
    resp = creq.get("https://localhost:%d/probe/nonce-curl-1" % server.port,
                    impersonate="chrome124", verify=False, timeout=5)
    assert resp.status_code == 200
    assert "PROBE_NONCE" in resp.text
    assert wait_for(lambda: any(r.tls for r in list(server.records.values())))
    recs = [r for r in list(server.records.values()) if r.tls]
    assert recs and all(r.js is None for r in recs)


def test_collect_post_h1_joins_by_nonce(server):
    nonce = "nonce-h1"
    _raw_h1(server.port, b"GET /probe/%s HTTP/1.1\r\nHost: x\r\n\r\n" % nonce.encode())
    body = json.dumps({"userAgent": "x", "webdriver": False}).encode()
    resp = _raw_h1(server.port, b"POST /collect/%s HTTP/1.1\r\nHost: x\r\n"
                   b"Content-Length: %d\r\n\r\n%s" % (nonce.encode(), len(body), body))
    assert resp.startswith(b"HTTP/1.1 204")
    assert wait_for(lambda: any(r.js for r in list(server.records.values())))
    joined = [r for r in list(server.records.values()) if r.js]
    assert len(joined) == 1 and joined[0].js["userAgent"] == "x"
    assert joined[0].http is not None  # the GET connection, not the POST one


def test_collect_post_h2_and_default_path(server):
    nonce = "nonce-h2"
    c = creq.Session(impersonate="chrome124", verify=False)
    base = "https://localhost:%d" % server.port
    assert c.get(base + "/other", timeout=5).text == "ok"
    assert c.get(base + "/probe/" + nonce, timeout=5).status_code == 200
    r = c.post(base + "/collect/" + nonce, json={"userAgent": "h2"}, timeout=5)
    assert r.status_code == 204
    assert wait_for(lambda: any(x.js for x in list(server.records.values())))
    assert [x.js for x in list(server.records.values()) if x.js] == [{"userAgent": "h2"}]


def test_collect_unknown_nonce_and_bad_json(server):
    base = "https://localhost:%d" % server.port
    assert creq.post(base + "/collect/nope", json={"a": 1}, verify=False,
                     timeout=5).status_code == 400
    _raw_h1(server.port, b"GET /probe/n1 HTTP/1.1\r\nHost: x\r\n\r\n")
    resp = _raw_h1(server.port, b"POST /collect/n1 HTTP/1.1\r\nHost: x\r\n"
                   b"Content-Length: 3\r\n\r\n{{{")
    assert resp.startswith(b"HTTP/1.1 400")
