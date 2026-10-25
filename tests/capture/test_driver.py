import pytest

from capture.driver import run_drivers


def test_driver_produces_one_record_per_client(server):
    clients = ["curl:chrome124", "tls:chrome_124", "stdlib:urllib"]
    recs = run_drivers(server, clients)
    assert len(recs) == 3
    assert [r.client_label for r in recs] == clients
    assert all(r.tls and r.tls["ja4"] for r in recs)
    assert all(r.http and r.http["path"] == "/" for r in recs)


def test_driver_rejects_unknown_client(server):
    with pytest.raises(ValueError):
        run_drivers(server, ["nope:x"])


@pytest.mark.integration
def test_driver_browser_record_has_js_and_probe_path(server):
    pytest.importorskip("playwright.sync_api")
    try:
        recs = run_drivers(server, ["browser:chromium"])
    except Exception as e:
        if "Executable doesn't exist" in str(e):
            pytest.skip("chromium unavailable")
        raise
    assert len(recs) == 1
    r = recs[0]
    assert r.client_label == "browser:chromium"
    assert r.tls["ja4"] and r.js and r.http["path"].startswith("/probe/")
