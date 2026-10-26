from crosslayer.features import (
    akamai_family,
    ch_ua_platform,
    has_client_hints,
    has_sec_fetch,
    js_present,
    ua_family,
    ua_major,
)


class _Rec:
    def __init__(self, js):
        self.js = js


def test_ua_family_and_major():
    chrome = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
    assert ua_family(chrome) == "chrome" and ua_major(chrome) == 124
    assert ua_family("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15") == "safari"
    assert ua_family("Mozilla/5.0 (Macintosh; rv:120.0) Gecko/20100101 Firefox/120.0") == "firefox"
    assert ua_family(None) == "other" and ua_major(None) is None


def test_akamai_family_by_shape():
    chrome = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    safari = "2:0;4:4194304;3:100|10485760|0|m,s,p,a"
    assert akamai_family(chrome) == "chrome"
    assert akamai_family(safari) == "safari"
    assert akamai_family("1:65536|12517377|0|m,p,a,s") == "firefox"
    assert akamai_family(None) == "none"
    assert akamai_family("") == "none"
    assert akamai_family("weird|0|0|x,y") == "unknown"


def test_client_hints_and_sec_fetch():
    http = {"header_order": ["sec-ch-ua", "sec-fetch-mode", "user-agent"],
            "client_hints": {"sec-ch-ua": "...", "sec-ch-ua-platform": "\"macOS\""}}
    assert has_client_hints(http) and has_sec_fetch(http)
    assert ch_ua_platform(http) == "\"macOS\""
    bare = {"header_order": ["accept", "user-agent"], "client_hints": {}}
    assert not has_client_hints(bare) and not has_sec_fetch(bare)
    assert ch_ua_platform(bare) is None


def test_none_tolerance_and_js_present():
    assert not has_client_hints(None) and not has_sec_fetch(None)
    assert ch_ua_platform(None) is None
    assert js_present(_Rec({"x": 1})) is True
    assert js_present(_Rec(None)) is False
