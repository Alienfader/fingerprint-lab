from capture.record import Record
from crosslayer.checks import (
    Contradiction,
    check_akamai_family,
    check_headless_gpu,
    check_js_absent_when_served,
    check_js_ua_mismatch,
    check_missing_client_hints,
    check_missing_sec_fetch,
    check_no_http2,
    check_perm_mismatch,
    check_webdriver,
    check_window_chrome,
    run_checks,
)
from ja3_diff import CHROME_UA

CHROME_AK = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
SAFARI_AK = "2:0;4:4194304;3:100|10485760|0|m,s,p,a"
FIREFOX_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0"


def test_akamai_family_mismatch_fires_on_safari_tls_chrome_ua():
    rec = Record(http={"user_agent": CHROME_UA, "header_order": [], "client_hints": {}},
                 http2={"akamai": SAFARI_AK, "alpn": "h2"})
    c = check_akamai_family(rec)
    assert c and c.code == "akamai_family_vs_ua" and c.severity == "strong"


def test_akamai_family_none_when_consistent_or_missing():
    ok = Record(http={"user_agent": CHROME_UA}, http2={"akamai": CHROME_AK})
    assert check_akamai_family(ok) is None
    assert check_akamai_family(Record()) is None
    assert check_akamai_family(Record(http={"user_agent": CHROME_UA})) is None


def test_missing_client_hints_under_chrome_fires():
    rec = Record(http={"user_agent": CHROME_UA, "header_order": ["accept", "user-agent"], "client_hints": {}},
                 http2={"akamai": CHROME_AK, "alpn": "h2"})
    assert check_missing_client_hints(rec).code == "missing_client_hints"


def test_missing_client_hints_none_for_firefox_or_missing():
    ff = Record(http={"user_agent": FIREFOX_UA, "header_order": [], "client_hints": {}})
    assert check_missing_client_hints(ff) is None
    assert check_missing_client_hints(Record()) is None


def test_missing_sec_fetch():
    rec = Record(http={"user_agent": CHROME_UA, "header_order": ["accept"]})
    assert check_missing_sec_fetch(rec).code == "missing_sec_fetch"
    ok = Record(http={"user_agent": CHROME_UA, "header_order": ["sec-fetch-mode"]})
    assert check_missing_sec_fetch(ok) is None
    assert check_missing_sec_fetch(Record()) is None


def test_no_http2_under_browser_ua_fires():
    rec = Record(http={"user_agent": CHROME_UA, "header_order": ["Host"], "client_hints": {}}, http2=None)
    assert check_no_http2(rec).code == "no_http2"


def test_no_http2_none_without_http_or_with_http2():
    assert check_no_http2(Record()) is None
    rec = Record(http={"user_agent": CHROME_UA}, http2={"akamai": CHROME_AK})
    assert check_no_http2(rec) is None
    assert check_no_http2(Record(http={"user_agent": "curl/8"}, http2=None)) is None


def test_webdriver_and_headless_gpu_fire():
    rec = Record(js={"webdriver": True, "webglRenderer": "ANGLE (Google, Vulkan ... SwiftShader Device ...)"})
    assert check_webdriver(rec).code == "webdriver_true"
    assert check_headless_gpu(rec).code == "headless_gpu"


def test_headless_gpu_llvmpipe_case_insensitive_and_clean():
    assert check_headless_gpu(Record(js={"webglRenderer": "Mesa LLVMPIPE"})).code == "headless_gpu"
    assert check_headless_gpu(Record(js={"webglRenderer": "ANGLE (Apple, Apple M1)"})) is None
    assert check_headless_gpu(Record(js={"webglRenderer": None})) is None
    assert check_headless_gpu(Record()) is None
    assert check_webdriver(Record(js={"webdriver": False})) is None
    assert check_webdriver(Record()) is None


def test_window_chrome():
    http = {"user_agent": CHROME_UA}
    assert check_window_chrome(Record(http=http, js={"hasWindowChrome": False})).code == "no_window_chrome"
    assert check_window_chrome(Record(http=http, js={"hasWindowChrome": True})) is None
    assert check_window_chrome(Record(http=http, js={})) is None
    assert check_window_chrome(Record(http=http)) is None
    ff = Record(http={"user_agent": FIREFOX_UA}, js={"hasWindowChrome": False})
    assert check_window_chrome(ff) is None


def test_js_ua_mismatch():
    rec = Record(http={"user_agent": CHROME_UA}, js={"userAgent": FIREFOX_UA})
    c = check_js_ua_mismatch(rec)
    assert c and c.code == "js_ua_mismatch" and c.severity == "strong"
    assert check_js_ua_mismatch(Record(http={"user_agent": CHROME_UA}, js={"userAgent": CHROME_UA})) is None
    assert check_js_ua_mismatch(Record(http={"user_agent": CHROME_UA})) is None
    assert check_js_ua_mismatch(Record(js={"userAgent": CHROME_UA})) is None


def test_perm_mismatch():
    assert check_perm_mismatch(Record(js={"permMismatch": True})).code == "perm_mismatch"
    assert check_perm_mismatch(Record(js={"permMismatch": False})) is None
    assert check_perm_mismatch(Record()) is None


def test_js_absent_only_when_probe_served():
    served = Record(http={"user_agent": CHROME_UA, "path": "/probe/abc", "client_hints": {"sec-ch-ua": "x"}},
                    http2={"akamai": CHROME_AK, "alpn": "h2"}, js=None)
    assert check_js_absent_when_served(served).code == "js_absent"
    not_served = Record(http={"user_agent": CHROME_UA, "path": "/", "client_hints": {}}, js=None)
    assert check_js_absent_when_served(not_served) is None  # observability: not served, not a signal
    assert check_js_absent_when_served(Record(js=None)) is None
    got = Record(http={"path": "/probe/abc"}, js={"webdriver": False})
    assert check_js_absent_when_served(got) is None


def test_clean_coherent_browser_has_no_contradictions():
    rec = Record(http={"user_agent": CHROME_UA, "path": "/probe/x",
                       "header_order": ["sec-ch-ua", "sec-fetch-mode", "user-agent"],
                       "client_hints": {"sec-ch-ua": "x", "sec-ch-ua-platform": "\"macOS\""}},
                 http2={"akamai": CHROME_AK, "alpn": "h2"},
                 js={"webdriver": False, "userAgent": CHROME_UA, "hasWindowChrome": True,
                     "platform": "MacIntel", "webglRenderer": "ANGLE (Apple, Apple M1, OpenGL 4.1)",
                     "permMismatch": False})
    assert run_checks(rec) == []


def test_run_checks_ordering_and_empty_record():
    assert run_checks(Record()) == []
    rec = Record(http={"user_agent": CHROME_UA, "path": "/probe/x", "header_order": [], "client_hints": {}},
                 http2=None, js=None)
    out = run_checks(rec)
    assert all(isinstance(c, Contradiction) for c in out)
    keys = [(c.severity != "strong", c.code) for c in out]
    assert keys == sorted(keys)
    assert {"no_http2", "missing_client_hints", "js_absent"} <= {c.code for c in out}
    assert run_checks(rec) == out
