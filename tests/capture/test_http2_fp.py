import hashlib

import curl_cffi.requests as creq
import pytest

from capture.http2_fp import akamai_fingerprint
from tests.capture.conftest import wait_for


def test_akamai_string_format():
    s, h = akamai_fingerprint([(1, 65536), (4, 131072)], 15663105, [], ["m", "a", "s", "p"])
    assert s.count("|") == 3 and len(h) == 64


def test_akamai_string_exact_values():
    s, h = akamai_fingerprint(
        [(1, 65536), (2, 0), (4, 6291456), (6, 262144)], 15663105, [], ["m", "a", "s", "p"])
    assert s == "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    assert h == hashlib.sha256(s.encode()).hexdigest()


def test_akamai_none_window_and_priorities():
    s, _ = akamai_fingerprint([(3, 100)], None, [(3, 0, 0, 201), (5, 1, 3, 101)], ["m", "p"])
    assert s == "3:100|00|3:0:0:201,5:1:3:101|m,p"


@pytest.mark.integration
@pytest.mark.integration
def test_server_records_http2_matches_oracle(server):
    try:
        o = creq.get("https://tls.peet.ws/api/all", impersonate="chrome124", timeout=15).json()
        oracle = o["http2"]["akamai_fingerprint"]
    except Exception as e:
        pytest.skip(f"oracle unavailable: {type(e).__name__}: {e}")
    r = creq.get(f"https://localhost:{server.port}/x", impersonate="chrome124",
                 verify=False, timeout=10)
    assert r.status_code == 200
    assert wait_for(lambda: any(x.http2 for x in server.records.values()))
    rec = next(r for r in server.records.values() if r.http2 is not None)
    assert rec.http2["alpn"] == "h2"
    # tls.peet.ws hashes with md5; we use sha256, so compare the canonical string
    assert rec.http2["akamai"] == oracle
    assert len(rec.http2["akamai_hash"]) == 64


@pytest.mark.integration
def test_h2_served_offline_records_fingerprint(server):
    r = creq.get(f"https://localhost:{server.port}/", impersonate="chrome124",
                 verify=False, timeout=10)
    assert r.status_code == 200
    assert wait_for(lambda: any(x.http2 is not None for x in server.records.values()))
    rec = next(x for x in server.records.values() if x.http2 is not None)
    assert rec.http2["alpn"] == "h2"
    assert len(rec.http2["akamai_hash"]) == 64
    assert rec.http2["akamai"].count("|") == 3


@pytest.mark.integration
def test_h2_garbage_after_preface_does_not_crash_server(server, caplog):
    import logging
    import socket
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    with caplog.at_level(logging.WARNING, logger="capture.server"):
        raw = socket.create_connection(("127.0.0.1", server.port), timeout=5)
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.settimeout(5)
            assert tls.selected_alpn_protocol() == "h2"
            tls.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                        + b"\x00\x00\x04\x00\x00\x00\x00\x00\x00" + b"\xff" * 4)  # DATA on stream 0
            try:
                while tls.recv(4096):
                    pass
            except (OSError, ssl.SSLError):
                pass
        assert wait_for(lambda: any("h2 protocol error" in m for m in caplog.messages))
    r = creq.get(f"https://localhost:{server.port}/", impersonate="chrome124",
                 verify=False, timeout=10)
    assert r.status_code == 200
