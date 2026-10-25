#!/usr/bin/env python3
"""
JA3 / TLS-fingerprint diff experiment.

Fires the *same* HTTP request (same URL, same Chrome User-Agent string) through
several clients and asks a TLS-inspection service what fingerprint each one
actually presented on the wire. The point: a matching User-Agent header does NOT
make you look like Chrome -- the TLS ClientHello (JA3/JA4) gives you away before
a single byte of HTTP is sent. A browser-impersonating client (curl_cffi) forges
that lower layer, and the fingerprint lines up.

Clients, in order of "how Python-shaped they look":
  1. urllib               -- Python stdlib. Always available. Naked-Python fingerprint.
  2. requests             -- the popular HTTP lib (if installed). Still a Python TLS stack.
  3. curl:<profile> ...   -- curl_cffi impersonating each profile you pass (if installed).
                             Default: chrome150 AND safari17_0, so you see per-profile forgery.
                             (chrome150's JA4 matches the captured real_chrome.json; bump this
                             if your real Chrome is a different version -- sweep to find the match.)

Two checks at the end:
  * Does JA3 differ across clients even with an identical UA?  (it should)
  * Does the Chrome profile match a REAL Chrome you captured?  (fidelity check)

Capture a real-Chrome reference once (so the fidelity check has ground truth):
    1. Open  https://tls.peet.ws/api/all  in your actual Chrome.
    2. Save the raw JSON to  real_chrome.json  in this folder
       (Cmd-S, or View-Source then save). That's it.
Then every run compares curl_cffi's chrome profile JA3 to that file.

Inspection service: https://tls.peet.ws/api/all -- a public, purpose-built echo
endpoint. It reflects *your own* fingerprint back to you; you only inspect yourself.

Usage:
    python3 ja3_diff.py                               # urllib + requests + chrome150 + safari17_0
    python3 ja3_diff.py --impersonate chrome120,safari17_0,chrome124
    python3 ja3_diff.py --expect-ja3 <md5>            # assert chrome profile == this JA3
    python3 ja3_diff.py --reference-file real_chrome.json
    python3 ja3_diff.py --json
"""
from __future__ import annotations

import argparse
import json
import pathlib
import ssl
import sys
import urllib.request

# One identical, realistic Chrome UA sent by every client, so the ONLY thing that
# differs between runs is the TLS/HTTP2 layer -- which is exactly the lesson.
CHROME_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
DEFAULT_URL = "https://tls.peet.ws/api/all"
HERE = pathlib.Path(__file__).resolve().parent


def extract(doc: dict) -> dict:
    """Flatten the bits we care about from tls.peet.ws's response shape."""
    tls = doc.get("tls", {}) if isinstance(doc, dict) else {}
    http2 = doc.get("http2", {}) if isinstance(doc, dict) else {}
    return {
        "ja3": tls.get("ja3"),
        "ja3_hash": tls.get("ja3_hash"),
        "ja4": tls.get("ja4"),
        "peetprint_hash": tls.get("peetprint_hash"),
        "akamai_hash": http2.get("akamai_fingerprint_hash") or http2.get("akamai_hash"),
        "user_agent": doc.get("user_agent"),
    }


# ---- clients -----------------------------------------------------------------

def via_urllib(url: str) -> dict:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": CHROME_UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def via_requests(url: str) -> dict:
    import requests  # type: ignore
    r = requests.get(url, headers={"User-Agent": CHROME_UA, "Accept": "application/json"}, timeout=20)
    r.raise_for_status()
    return r.json()


def via_curl_cffi(url: str, impersonate: str) -> dict:
    from curl_cffi import requests as creq  # type: ignore
    # The impersonate= flag forges the TLS+HTTP2 fingerprint; we still pass the same
    # UA header so the ONLY difference from the Python clients is the lower layer.
    r = creq.get(url, headers={"User-Agent": CHROME_UA, "Accept": "application/json"},
                 impersonate=impersonate, timeout=20)
    r.raise_for_status()
    return r.json()


def via_tls_client(url: str, client_identifier: str) -> dict:
    import tls_client  # type: ignore
    # A different forgery engine: a Go TLS stack (uTLS) behind a Python binding.
    # client_identifier uses underscores (chrome_124), vs curl_cffi's chrome124.
    # random_tls_extension_order=True mirrors real Chrome 110+ shuffling, so its JA3
    # (not JA4) drifts just like a browser's -- which is the honest thing to compare.
    s = tls_client.Session(client_identifier=client_identifier, random_tls_extension_order=True)
    r = s.get(url, headers={"User-Agent": CHROME_UA, "Accept": "application/json"})
    return r.json()


# ---- runner ------------------------------------------------------------------

def run_client(name: str, fn) -> dict | None:
    try:
        raw = fn()
    except ImportError:
        print(f"  [{name:16}] not installed -- run ./bootstrap.sh to enable", file=sys.stderr)
        return None
    except Exception as e:  # network/TLS/parse -- report, don't crash the whole run
        print(f"  [{name:16}] ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        return None
    row = extract(raw)
    row["_client"] = name
    return row


def load_reference(path: pathlib.Path, expect_ja3: str | None,
                   expect_ja4: str | None) -> dict:
    """Return {'ja3','ja4','src'} ground truth for the fidelity checks.

    Explicit --expect-* flags win per field; otherwise both are read from the saved
    real_chrome.json. The two sources can be mixed (e.g. a stable JA4 from the file
    plus a pinned JA3 on the command line)."""
    ref: dict = {"ja3": None, "ja4": None, "src": ""}
    file_ref = {}
    if path.is_file():
        try:
            file_ref = extract(json.loads(path.read_text()))
            ref["src"] = path.name
        except Exception as e:
            print(f"  (could not parse {path.name}: {e})", file=sys.stderr)
    ref["ja3"] = (expect_ja3 or file_ref.get("ja3_hash") or "").strip().lower() or None
    ref["ja4"] = (expect_ja4 or file_ref.get("ja4") or "").strip() or None
    if expect_ja3 or expect_ja4:
        ref["src"] = ", ".join(
            s for s in [("--expect-ja3/ja4" if (expect_ja3 or expect_ja4) else ""), ref["src"]] if s
        )
    return ref


def print_table(rows: list[dict]) -> None:
    if not rows:
        print("No clients produced a result.")
        return
    fields = ["ja3_hash", "ja4", "akamai_hash", "peetprint_hash", "user_agent"]
    labels = {
        "ja3_hash": "JA3 (MD5)",
        "ja4": "JA4",
        "akamai_hash": "HTTP/2 (Akamai)",
        "peetprint_hash": "PeetPrint",
        "user_agent": "UA the server saw",
    }
    width = max(len(labels[f]) for f in fields)
    print()
    for f in fields:
        print(f"{labels[f]:>{width}} :")
        for row in rows:
            val = row.get(f) or "(none)"
            print(f"{'':>{width}}   {row['_client']:16} {val}")
        print()


def report_checks(rows: list[dict], ref: dict, chrome_client: str | None) -> bool:
    """Print the checks. Returns True if every assertion that could fail the build passed.

    JA4 is the authoritative fidelity check (stable for Chrome). A JA3 mismatch is only
    a WARNING, because modern Chrome shuffles extensions per connection so its JA3 is
    expected to drift -- failing the build on that would be a false alarm."""
    ok = True
    by = {r["_client"]: r for r in rows}
    print("-" * 68)

    # Check 1: do the TLS fingerprints diverge despite one identical UA header?
    ja3s = {c: r.get("ja3_hash") for c, r in by.items() if r.get("ja3_hash")}
    uniq = set(ja3s.values())
    if len(uniq) > 1:
        print(f"[1] PASS  JA3 differs across clients ({len(uniq)} distinct) with ONE identical UA.")
        print("          -> the UA header is not what TLS fingerprinting keys on.")
    else:
        print(f"[1] n/a   only {len(uniq)} distinct JA3 seen; add more clients to contrast.")

    # Check 1b: chrome profile vs safari profile should NOT match (per-profile forgery).
    chrome_ja3 = ja3s.get(chrome_client) if chrome_client else None
    safari = next((c for c in ja3s if c.startswith("curl:safari")), None)
    if chrome_ja3 and safari and ja3s.get(safari):
        if chrome_ja3 != ja3s[safari]:
            print("[1b] PASS curl chrome != curl safari JA3 -> impersonation is per-profile, not one trick.")
        else:
            print("[1b] FAIL chrome and safari profiles share a JA3 -- unexpected.")
            ok = False

    chrome_row = by.get(chrome_client) if chrome_client else None
    chrome_ja4 = chrome_row.get("ja4") if chrome_row else None
    src = ref.get("src") or "reference"

    # Check 2 (authoritative): JA4 fidelity -- stable, so a mismatch is a real failure.
    if ref.get("ja4"):
        if not chrome_ja4:
            print("[2] n/a   no curl chrome result to compare JA4 against.")
        elif chrome_ja4 == ref["ja4"]:
            print(f"[2] PASS  curl chrome JA4 == real Chrome ({src})")
            print(f"          {chrome_ja4}")
            print("          -> faithful forgery on the STABLE fingerprint. This is the one that counts.")
        else:
            print(f"[2] FAIL  curl chrome JA4 {chrome_ja4}")
            print(f"          real Chrome ({src})   {ref['ja4']}")
            print("          -> genuine mismatch (JA4 is stable). Your Chrome version likely differs")
            print("             from the profile; try --impersonate chrome120/chrome131 to match it.")
            ok = False
    else:
        print("[2] skip  no real-Chrome JA4 reference. Capture one for the fidelity check:")
        print("          open https://tls.peet.ws/api/all in Chrome, save JSON to real_chrome.json")

    # Check 4 (cross-engine): two independent engines forging the SAME Chrome version
    # should agree on JA4 (the stable fingerprint). Advisory -- engine internals and
    # minor version packaging can differ -- but agreement is strong evidence both are faithful.
    tls_chrome = next((c for c in by if c.startswith("tls:chrome")), None)
    if chrome_client and tls_chrome:
        a, b = chrome_ja4, by[tls_chrome].get("ja4")
        if a and b:
            if a == b:
                print(f"[4] PASS  curl_cffi and tls_client agree on Chrome JA4 -> two engines, one fingerprint:")
                print(f"          {a}")
            else:
                print(f"[4] note  curl_cffi JA4  {a}")
                print(f"          tls_client JA4 {b}")
                print("          -> the two engines diverge (version/build differences). Compare at matched")
                print(f"             versions, e.g. --impersonate chrome124 --tls-client chrome_124.")

    # Check 3 (advisory): JA3 fidelity -- expected to drift, so WARN, never fail.
    if ref.get("ja3"):
        if not chrome_ja3:
            print("[3] n/a   no curl chrome result to compare JA3 against.")
        elif chrome_ja3 == ref["ja3"]:
            print(f"[3] PASS  curl chrome JA3 matched the reference too: {chrome_ja3}")
        else:
            print(f"[3] WARN  curl chrome JA3 {chrome_ja3} != reference {ref['ja3']}")
            print("          Expected: Chrome 110+ shuffles TLS extensions per connection, so JA3")
            print("          drifts run-to-run. This is why JA4 (check [2]) is the reliable one.")
    print()
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=DEFAULT_URL, help="TLS inspection endpoint (default: tls.peet.ws)")
    ap.add_argument("--impersonate", default="chrome150,safari17_0",
                    help="comma-separated curl_cffi profiles (default: chrome150,safari17_0)")
    ap.add_argument("--tls-client", default="chrome_150,safari_16_0",
                    help="comma-separated tls_client profiles, '' to skip (default: chrome_150,safari_16_0)")
    ap.add_argument("--expect-ja3", default=None, help="advisory: chrome profile JA3 md5 (drifts, warns only)")
    ap.add_argument("--expect-ja4", default=None, help="authoritative: chrome profile JA4 (stable, fails build)")
    ap.add_argument("--reference-file", default="real_chrome.json",
                    help="JSON saved from opening the inspector in real Chrome (default: real_chrome.json)")
    ap.add_argument("--json", action="store_true", help="dump raw rows as JSON instead of a table")
    args = ap.parse_args()

    profiles = [p.strip() for p in args.impersonate.split(",") if p.strip()]
    # The first chrome* profile is the one we hold to the fidelity check.
    chrome_profile = next((p for p in profiles if p.startswith("chrome")), None)
    chrome_client = f"curl:{chrome_profile}" if chrome_profile else None

    # Keep stdout pure JSON under --json.
    if not args.json:
        print(f"Inspecting self via: {args.url}")
        print(f"Every client sends this identical UA header:\n  {CHROME_UA}")
        print(f"curl_cffi profiles: {', '.join(profiles) or '(none)'}")

    tls_profiles = [p.strip() for p in args.tls_client.split(",") if p.strip()]

    clients: list[tuple[str, object]] = [
        ("urllib", lambda: via_urllib(args.url)),
        ("requests", lambda: via_requests(args.url)),
    ]
    for p in profiles:
        clients.append((f"curl:{p}", (lambda prof=p: via_curl_cffi(args.url, prof))))
    for p in tls_profiles:
        clients.append((f"tls:{p}", (lambda prof=p: via_tls_client(args.url, prof))))

    rows: list[dict] = []
    for name, fn in clients:
        row = run_client(name, fn)
        if row:
            rows.append(row)

    ref = load_reference(HERE / args.reference_file, args.expect_ja3, args.expect_ja4)

    if args.json:
        print(json.dumps(rows, indent=2))
        return 0 if rows else 1

    print_table(rows)
    all_ok = report_checks(rows, ref, chrome_client)
    # Exit non-zero if a reference/assertion ran and failed, so this is CI-usable.
    if not rows:
        return 1
    return 0 if all_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
