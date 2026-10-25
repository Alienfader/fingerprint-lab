import hashlib

import curl_cffi.requests as creq
import pytest

from capture.http2_fp import akamai_fingerprint
from tests.capture.test_server_tls import certpair, server, wait_for  # noqa: F401


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
def test_server_records_http2_matches_oracle(server):  # noqa: F811
    try:
        o = creq.get("https://tls.peet.ws/api/all", impersonate="chrome124", timeout=15).json()
        oracle = o["http2"]["akamai_fingerprint"]
    except Exception as e:
        pytest.skip(f"oracle unavailable: {type(e).__name__}: {e}")
    r = creq.get(f"https://localhost:{server.port}/x", impersonate="chrome124",
                 verify=False, timeout=10)
    assert r.status_code == 200
    assert wait_for(lambda: any(x.http2 for x in server.records.values()))
    rec = next(iter(server.records.values()))
    assert rec.http2["alpn"] == "h2"
    # tls.peet.ws hashes with md5; we use sha256, so compare the canonical string
    assert rec.http2["akamai"] == oracle
    assert len(rec.http2["akamai_hash"]) == 64
