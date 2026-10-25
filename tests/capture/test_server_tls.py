import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path

import curl_cffi.requests as creq
import pytest

from capture.server import CaptureServer

FIXTURE_BYTES = (Path(__file__).parent / "fixtures" / "chrome124_clienthello.bin").read_bytes()
CHROME124_JA4 = "t13d1516h2_8daaf6152771_02713d6af862"


@pytest.fixture
def certpair(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
         "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return str(cert), str(key)


@pytest.fixture
def server(certpair):
    srv = CaptureServer(*certpair)
    port = srv.start()
    srv.port = port
    yield srv
    srv.stop()


def wait_for(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def get(port, profile):
    return creq.get(f"https://localhost:{port}/x", impersonate=profile,
                    verify=False, timeout=10)


def test_captures_ja4_and_completes_handshake(server):
    r = get(server.port, "chrome124")
    assert r.status_code == 200
    assert wait_for(lambda: len(server.records) == 1)
    rec = next(iter(server.records.values()))
    assert rec.tls["ja4"] == CHROME124_JA4
    assert len(rec.tls["ja3_hash"]) == 32
    assert rec.client_addr[0] == "127.0.0.1"
    assert rec.captured_at


def test_partial_clienthello_across_segments(server):
    s = socket.create_connection(("127.0.0.1", server.port), timeout=5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(FIXTURE_BYTES[:40])
    time.sleep(0.4)
    s.sendall(FIXTURE_BYTES[40:])
    assert wait_for(lambda: len(server.records) == 1)
    s.close()
    rec = next(iter(server.records.values()))
    assert rec.tls["ja4"] == CHROME124_JA4


def test_handshake_timeout_records_nothing_but_cleans_up(certpair):
    srv = CaptureServer(*certpair, peek_timeout=0.5)
    port = srv.start()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        # server must close us after its peek timeout: recv sees EOF/reset
        try:
            data = s.recv(10)
        except ConnectionError:
            data = b""
        assert data == b""
        s.close()
        assert srv.records == {}
        # server still alive and serving
        r = get(port, "chrome124")
        assert r.status_code == 200
    finally:
        srv.stop()


def test_two_concurrent_clients_do_not_cross_contaminate(server):
    results = {}

    def run(p):
        results[p] = get(server.port, p).status_code

    ts = [threading.Thread(target=run, args=(p,)) for p in ("chrome124", "safari17_0")]
    [t.start() for t in ts]
    [t.join(timeout=15) for t in ts]
    assert results == {"chrome124": 200, "safari17_0": 200}
    assert wait_for(lambda: len(server.records) == 2)
    recs = list(server.records.values())
    ja4s = {r.tls["ja4"] for r in recs}
    assert len(ja4s) == 2 and None not in ja4s
    assert CHROME124_JA4 in ja4s
    assert len({r.client_addr for r in recs}) == 2


def test_tls_complete_but_no_http_is_recorded_and_cleaned_up(certpair):
    srv = CaptureServer(*certpair, io_timeout=0.5)
    port = srv.start()
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        tls = ctx.wrap_socket(raw, server_hostname="localhost")
        tls.settimeout(5)
        # send nothing; server should time out and close
        try:
            assert tls.recv(10) in (b"",)
        except (ssl.SSLError, ConnectionError):
            pass
        tls.close()
        assert len(srv.records) == 1
        assert next(iter(srv.records.values())).tls["ja4"]
    finally:
        srv.stop()
