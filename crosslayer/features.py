"""Pure feature extractors over capture records (tolerate missing layers)."""
import re

_CHROME_RE = re.compile(r"Chrome/(\d+)")
_PSEUDO = {"m,a,s,p": "chrome", "m,s,p,a": "safari", "m,p,a,s": "firefox"}


def ua_family(ua):
    if not ua:
        return "other"
    if "Firefox/" in ua:
        return "firefox"
    if "Chrome/" in ua or "Chromium/" in ua or "CriOS/" in ua:
        return "chrome"
    if "Safari/" in ua and "Version/" in ua:
        return "safari"
    return "other"


def ua_major(ua):
    m = _CHROME_RE.search(ua or "")
    return int(m.group(1)) if m else None


def akamai_family(akamai):
    if not akamai:
        return "none"
    seg = akamai.rsplit("|", 1)[-1].strip()
    if not seg:
        return "none"
    return _PSEUDO.get(seg, "unknown")


def has_client_hints(http):
    if not http:
        return False
    if http.get("client_hints"):
        return True
    return any(h.lower().startswith("sec-ch-") for h in http.get("header_order") or [])


def has_sec_fetch(http):
    if not http:
        return False
    return any(h.lower().startswith("sec-fetch-") for h in http.get("header_order") or [])


def ch_ua_platform(http):
    if not http:
        return None
    return (http.get("client_hints") or {}).get("sec-ch-ua-platform")


def js_present(rec):
    return bool(getattr(rec, "js", None))
