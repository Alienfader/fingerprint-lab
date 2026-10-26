"""Independent cross-layer contradiction checks. Each tolerates missing layers."""
from dataclasses import dataclass

from crosslayer.features import (
    akamai_family,
    has_client_hints,
    has_sec_fetch,
    js_present,
    ua_family,
    ua_major,
)

_BROWSERS = ("chrome", "safari", "firefox")


@dataclass(frozen=True)
class Contradiction:
    layer: str
    code: str
    detail: str
    severity: str  # "strong" | "weak"


def _ua(rec):
    return (rec.http or {}).get("user_agent")


def _browser_ua(rec):
    """UA family if a browser-like UA was observed on the http layer, else None."""
    if not rec.http:
        return None
    fam = ua_family(_ua(rec))
    return fam if fam in _BROWSERS else None


def check_no_http2(rec):
    fam = _browser_ua(rec)
    if fam and not rec.http2:
        return Contradiction("http2", "no_http2", f"{fam} UA but no HTTP/2 observed", "weak")
    return None


def check_akamai_family(rec):
    ua_fam = _browser_ua(rec)
    if not ua_fam or not rec.http2:
        return None
    ak = akamai_family(rec.http2.get("akamai"))
    if ak in _BROWSERS and ak != ua_fam:
        return Contradiction("http2", "akamai_family_vs_ua",
                             f"UA says {ua_fam}, HTTP/2 fingerprint says {ak}", "strong")
    return None


def check_missing_client_hints(rec):
    if _browser_ua(rec) != "chrome":
        return None
    major = ua_major(_ua(rec))
    if major is not None and major < 89:
        return None
    if not has_client_hints(rec.http):
        return Contradiction("http", "missing_client_hints",
                             "Chrome UA without Sec-CH-UA client hints", "weak")
    return None


def check_missing_sec_fetch(rec):
    if _browser_ua(rec) != "chrome":
        return None
    if not has_sec_fetch(rec.http):
        return Contradiction("http", "missing_sec_fetch",
                             "Chrome UA without Sec-Fetch-* headers", "weak")
    return None


def check_webdriver(rec):
    if js_present(rec) and rec.js.get("webdriver") is True:
        return Contradiction("js", "webdriver_true", "navigator.webdriver is true", "strong")
    return None


def check_headless_gpu(rec):
    if not js_present(rec):
        return None
    r = rec.js.get("webglRenderer")
    if isinstance(r, str) and any(s in r.lower() for s in ("swiftshader", "llvmpipe")):
        return Contradiction("js", "headless_gpu", f"software GL renderer: {r}", "strong")
    return None


def check_window_chrome(rec):
    if ua_family(_ua(rec)) == "chrome" and js_present(rec) and rec.js.get("hasWindowChrome") is False:
        return Contradiction("js", "no_window_chrome", "Chrome UA but window.chrome absent", "strong")
    return None


def check_js_ua_mismatch(rec):
    if not rec.http or not js_present(rec):
        return None
    h, j = _ua(rec), rec.js.get("userAgent")
    if not h or not j:
        return None
    if ua_family(h) != ua_family(j) or ua_major(h) != ua_major(j):
        return Contradiction("js", "js_ua_mismatch", "HTTP User-Agent differs from navigator.userAgent",
                             "strong")
    return None


def check_perm_mismatch(rec):
    if js_present(rec) and rec.js.get("permMismatch") is True:
        return Contradiction("js", "perm_mismatch",
                             "Notification.permission vs permissions API mismatch", "weak")
    return None


def check_js_absent_when_served(rec):
    """Only a signal when a probe page was actually served (observability guard)."""
    path = (rec.http or {}).get("path") or ""
    if path.startswith("/probe") and rec.js is None:
        return Contradiction("js", "js_absent", "probe served but no JS results returned", "weak")
    return None


CHECKS = (
    check_no_http2,
    check_akamai_family,
    check_missing_client_hints,
    check_missing_sec_fetch,
    check_webdriver,
    check_headless_gpu,
    check_window_chrome,
    check_js_ua_mismatch,
    check_perm_mismatch,
    check_js_absent_when_served,
)


def run_checks(rec):
    out = [c for c in (f(rec) for f in CHECKS) if c is not None]
    return sorted(out, key=lambda c: (c.severity != "strong", c.code))
