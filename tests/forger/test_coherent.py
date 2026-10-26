import pytest

from forger.coherent import build_payload, forge
from ja3_diff import CHROME_UA


def test_build_payload_coherent_has_probe_keys_and_no_tells():
    p = build_payload()
    assert set(p) >= {"webdriver", "userAgent", "hasWindowChrome", "webglRenderer", "platform"}
    assert p["webdriver"] is False and p["hasWindowChrome"] is True
    assert "swiftshader" not in p["webglRenderer"].lower()


def test_build_payload_toggles_inject_each_tell():
    assert build_payload(webdriver=True)["webdriver"] is True
    assert "swiftshader" in build_payload(gpu="swiftshader")["webglRenderer"].lower()
    assert build_payload(window_chrome=False)["hasWindowChrome"] is False
    assert build_payload(ua_match=False)["userAgent"] != CHROME_UA


@pytest.mark.integration
def test_forge_joins_fabricated_js(server):
    rec = forge(server, payload=build_payload())
    assert rec.js is not None and rec.js["webdriver"] is False
    assert (rec.http or {})["path"].startswith("/probe/")
    assert rec.tls and rec.tls.get("ja4")


@pytest.mark.integration
def test_forge_naive_has_no_js(server):
    rec = forge(server, payload=None)
    assert rec.js is None
