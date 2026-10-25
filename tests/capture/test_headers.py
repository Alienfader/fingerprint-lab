import socket
import ssl

import curl_cffi.requests as creq

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
            return t.recv(4096)


def _http(server):
    return [r for r in server.records.values() if r.http is not None]


def test_h1_header_order_and_client_hints(server):
    req = (b"GET / HTTP/1.1\r\nHost: localhost\r\nSec-CH-UA: \"Chrome\";v=\"124\"\r\n"
           b"User-Agent: TestAgent/1.0\r\nAccept: */*\r\nsec-ch-ua-mobile: ?0\r\n"
           b"X-Custom: 1\r\n\r\n")
    assert _raw_h1(server.port, req).startswith(b"HTTP/1.1 200")
    assert wait_for(lambda: _http(server))
    h = _http(server)[0].http
    assert h["header_order"] == ["Host", "Sec-CH-UA", "User-Agent", "Accept",
                                 "sec-ch-ua-mobile", "X-Custom"]
    assert h["client_hints"] == {"Sec-CH-UA": '"Chrome";v="124"',
                                 "sec-ch-ua-mobile": "?0"}
    assert h["user_agent"] == "TestAgent/1.0"


def test_h1_user_agent_case_insensitive_and_absent(server):
    _raw_h1(server.port, b"GET / HTTP/1.1\r\nHost: x\r\nuSeR-aGeNt: abc\r\n\r\n")
    assert wait_for(lambda: _http(server))
    assert _http(server)[0].http["user_agent"] == "abc"
    _raw_h1(server.port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert wait_for(lambda: len(_http(server)) == 2)
    assert any(r.http["user_agent"] is None for r in _http(server))


def test_h1_malformed_does_not_kill_worker(server, caplog):
    assert _raw_h1(server.port, b"\x00\x01garbage\r\n\r\n").startswith(b"HTTP/1.1 200")
    assert wait_for(lambda: "h1 request parse failed" in caplog.text)
    _raw_h1(server.port, b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: ok\r\n\r\n")
    assert wait_for(lambda: any(r.http and r.http["user_agent"] == "ok"
                                for r in server.records.values()))


def test_h2_populates_http_without_pseudo_headers(server):
    r = creq.get(f"https://localhost:{server.port}/", impersonate="chrome124",
                 verify=False, timeout=10)
    assert r.status_code == 200
    assert wait_for(lambda: _http(server))
    rec = _http(server)[0]
    assert rec.http2 is not None
    h = rec.http["header_order"]
    assert h and not any(n.startswith(":") for n in h)
    assert rec.http["user_agent"]
    assert any(k.startswith("sec-ch-") for k in rec.http["client_hints"])
