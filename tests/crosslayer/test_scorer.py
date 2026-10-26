import json

from capture.record import Record
from crosslayer.scorer import Verdict, score
from ja3_diff import CHROME_UA

CHROME_AK = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
SAFARI_AK = "2:0;4:4194304;3:100|10485760|0|m,s,p,a"
FULL_ORDER = ["sec-ch-ua", "sec-fetch-mode", "user-agent"]


def _http(**kw):
    base = {"user_agent": CHROME_UA, "path": "/probe/x", "client_hints": {"sec-ch-ua": "x"},
            "header_order": list(FULL_ORDER)}
    base.update(kw)
    return base


def _codes(v):
    return {c.code for c in v.contradictions}


def coherent_real_record():
    return Record(
        tls={"ja4": "t13d1516h2_x_y", "ja4_norm": "y"},
        http2={"akamai": CHROME_AK, "alpn": "h2"},
        http=_http(),
        js={"webdriver": False, "hasWindowChrome": True, "userAgent": CHROME_UA,
            "webglRenderer": "ANGLE (Apple, Apple M1, OpenGL 4.1)"},
    )


def test_curl_cffi_chrome_caught_by_js_absence_not_ja4():
    rec = Record(tls={"ja4": "t13i1515h2_8daaf6152771_02713d6af862", "ja4_norm": "02713d6af862"},
                 http2={"akamai": CHROME_AK, "alpn": "h2"}, http=_http(), js=None)
    v = score(rec)
    assert v.label == "automated"
    assert "js_absent" in _codes(v)
    assert v.confidence == "medium"  # single layer (js)


def test_safari_tls_chrome_ua_caught_by_family():
    rec = Record(tls={"ja4": "x"}, http2={"akamai": SAFARI_AK, "alpn": "h2"}, http=_http(), js=None)
    v = score(rec)
    assert v.label == "automated" and "akamai_family_vs_ua" in _codes(v)
    assert v.confidence == "high"  # http2 + js layers


def test_tls_chrome_without_headers_caught():
    rec = Record(tls={"ja4": "x"}, http2={"akamai": CHROME_AK, "alpn": "h2"},
                 http={"user_agent": CHROME_UA, "path": "/", "client_hints": {}, "header_order": ["user-agent"]})
    v = score(rec)
    assert v.label == "automated"
    assert {"missing_client_hints", "missing_sec_fetch"} <= _codes(v)


def test_stdlib_caught_by_no_http2():
    rec = Record(tls={"ja4": "x"}, http2=None,
                 http={"user_agent": CHROME_UA, "path": "/", "header_order": ["Host"]})
    v = score(rec)
    assert v.label == "automated" and "no_http2" in _codes(v)


def test_coherent_real_browser_is_real():
    v = score(coherent_real_record())
    assert v.label == "real" and v.contradictions == []
    assert v.confidence == "high"
    assert v.observed == {"tls": True, "http2": True, "http": True, "js": True}


def test_real_with_partial_layers_is_low_confidence():
    rec = coherent_real_record()
    rec.tls = None
    v = score(rec)
    assert v.label == "real" and v.confidence == "low" and v.observed["tls"] is False


def test_weak_only_is_never_automated():
    rec = coherent_real_record()
    rec.js["permMismatch"] = True
    v = score(rec)
    assert [c.severity for c in v.contradictions] == ["weak"]
    assert v.label == "inconclusive" and v.confidence == "low"


def test_missing_layers_do_not_crash_and_scope_confidence():
    v = score(Record(http={"user_agent": CHROME_UA, "path": "/"}))
    assert v.observed == {"tls": False, "http2": False, "http": True, "js": False}
    assert v.label in {"inconclusive", "automated"}
    e = score(Record())
    assert e.label == "inconclusive" and e.confidence == "low"


def test_to_dict_is_json_safe():
    v = score(Record(http={"user_agent": CHROME_UA, "path": "/probe"}))
    d = v.to_dict()
    json.dumps(d)
    assert d["label"] == "automated" and isinstance(d["contradictions"][0], dict)
    assert isinstance(v, Verdict)


def test_verdict_ignores_ja4_fields():
    a = coherent_real_record()
    b = coherent_real_record()
    b.tls = {"ja4": "totally-different", "ja4_norm": "other"}
    assert score(a).to_dict() == score(b).to_dict()
