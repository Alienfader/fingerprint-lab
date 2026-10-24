#!/usr/bin/env python3
"""
Browser-fingerprint diff experiment -- the JS-layer counterpart to ja3_diff.py.

ja3_diff.py showed the *network* layer (TLS/HTTP2). This shows the *browser* layer:
the signals a detection script reads from inside the page -- navigator.webdriver, the
UA string, plugins, window.chrome, a permissions-API inconsistency, WebGL vendor,
a canvas hash. These are what headless-browser detection keys on.

It launches the SAME Chromium three ways, along the real arms race, and counts how
many classic "headless tells" survive each step:

  vanilla  -- plain headless. Every tell present. (navigator.webdriver=true,
              "HeadlessChrome" in the UA, 0 plugins, no window.chrome, ...)
  args     -- the common half-measures: launch with
              --disable-blink-features=AutomationControlled and override the UA.
  stealth  -- add_init_script patches that hide webdriver/plugins/languages/
              window.chrome, fix the permissions mismatch, and spoof WebGL vendor.

Optional:
  --headful   also run a real headed Chromium as ground truth (opens a window;
              needs a display). Its tell count is what 'stealth' is trying to reach.

Everything runs against about:blank -- all signals come from the JS environment, no
third-party site is contacted. (Point --url at a detector you control to go further.)

    python3 browser_fp.py                 # vanilla / args / stealth
    python3 browser_fp.py --headful       # + a real headed browser row
    python3 browser_fp.py --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys

# A realistic headed-Chrome UA used to override the "HeadlessChrome" string in the
# args/stealth modes. Matching the UA is trivial; the hard tells are the rest.
REAL_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# The signal battery, run in-page. Returns a flat dict of raw values; Python decides
# which are "tells". Kept defensive (try/catch) so one failing probe never blanks the row.
SIGNAL_JS = r"""
async () => {
  const out = {};
  const safe = (f, d=null) => { try { return f(); } catch (e) { return d; } };

  out.webdriver        = safe(() => navigator.webdriver);
  out.userAgent        = safe(() => navigator.userAgent);
  out.pluginsLen       = safe(() => navigator.plugins.length);
  out.languages        = safe(() => JSON.stringify(navigator.languages));
  out.hasWindowChrome  = safe(() => typeof window.chrome !== 'undefined');
  out.hardwareConc     = safe(() => navigator.hardwareConcurrency);
  out.platform         = safe(() => navigator.platform);

  // WebGL vendor/renderer -- headless often reports SwiftShader / Google Inc.
  out.webglVendor = safe(() => {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    return gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
  });
  out.webglRenderer = safe(() => {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    return gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
  });

  // Classic headless inconsistency: Notification.permission says 'denied' while
  // permissions.query reports 'prompt'. A real browser agrees with itself.
  out.permMismatch = await (async () => {
    try {
      const q = await navigator.permissions.query({ name: 'notifications' });
      return (Notification.permission === 'denied' && q.state === 'prompt');
    } catch (e) { return null; }
  })();

  // A canvas fingerprint -- not a tell by itself, but shows the surface is readable
  // and stable per config (detectors hash this to track you).
  out.canvas = safe(() => {
    const c = document.createElement('canvas');
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top'; ctx.font = '14px Arial';
    ctx.fillStyle = '#f60'; ctx.fillRect(10, 1, 62, 20);
    ctx.fillStyle = '#069'; ctx.fillText('fp-lab \u{1F512}', 2, 15);
    return c.toDataURL();
  });

  return out;
}
"""

# Stealth patches applied BEFORE page scripts run (add_init_script). Each line kills
# one tell. This is a teaching subset of what puppeteer-extra-stealth does at scale.
STEALTH_JS = r"""
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
Object.defineProperty(navigator, 'plugins',   { get: () => [1,2,3,4,5] });
Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] });
window.chrome = { runtime: {} };
(() => {
  const orig = navigator.permissions.query.bind(navigator.permissions);
  navigator.permissions.query = (p) =>
    p && p.name === 'notifications'
      ? Promise.resolve({ state: Notification.permission })
      : orig(p);
})();
(() => {
  const gp = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function (p) {
    if (p === 37445) return 'Intel Inc.';                  // UNMASKED_VENDOR_WEBGL
    if (p === 37446) return 'Intel Iris OpenGL Engine';    // UNMASKED_RENDERER_WEBGL
    return gp.call(this, p);
  };
})();
"""


def tells(sig: dict) -> list[str]:
    """The headless tells still present in a signal dict (shorter list = more human)."""
    t = []
    if sig.get("webdriver") is True:
        t.append("navigator.webdriver=true")
    if isinstance(sig.get("userAgent"), str) and "Headless" in sig["userAgent"]:
        t.append("'HeadlessChrome' in UA")
    if sig.get("pluginsLen") == 0:
        t.append("navigator.plugins empty")
    if sig.get("hasWindowChrome") is False:
        t.append("window.chrome missing")
    if sig.get("permMismatch") is True:
        t.append("permissions/Notification mismatch")
    vend = (sig.get("webglVendor") or "")
    rend = (sig.get("webglRenderer") or "")
    if "SwiftShader" in rend or "Google" in vend or "Google" in rend:
        t.append("WebGL=software/Google (no real GPU)")
    return t


def collect(p, mode: str, url: str, headful: bool) -> dict:
    launch_args: list[str] = []
    context_kwargs: dict = {}
    init_script: str | None = None

    if mode in ("args", "stealth"):
        launch_args.append("--disable-blink-features=AutomationControlled")
        context_kwargs["user_agent"] = REAL_UA
    if mode == "stealth":
        init_script = STEALTH_JS

    browser = p.chromium.launch(headless=not headful, args=launch_args)
    try:
        ctx = browser.new_context(**context_kwargs)
        if init_script:
            ctx.add_init_script(init_script)
        page = ctx.new_page()
        page.goto(url, wait_until="domcontentloaded")
        sig = page.evaluate(SIGNAL_JS)
        ctx.close()
    finally:
        browser.close()

    # Hash the canvas data URL down to something printable.
    if sig.get("canvas"):
        sig["canvas"] = hashlib.md5(sig["canvas"].encode()).hexdigest()[:16] + " (md5)"
    sig["_mode"] = mode
    sig["_tells"] = tells(sig)
    return sig


def print_table(rows: list[dict]) -> None:
    fields = [
        ("webdriver", "navigator.webdriver"),
        ("userAgent", "UA (tail)"),
        ("pluginsLen", "plugins.length"),
        ("hasWindowChrome", "window.chrome"),
        ("permMismatch", "perm mismatch"),
        ("webglRenderer", "WebGL renderer"),
        ("canvas", "canvas hash"),
    ]
    width = max(len(lbl) for _, lbl in fields)
    print()
    for key, lbl in fields:
        print(f"{lbl:>{width}} :")
        for r in rows:
            v = r.get(key)
            if key == "userAgent" and isinstance(v, str):
                v = "..." + v[-42:]
            print(f"{'':>{width}}   {r['_mode']:9} {v}")
        print()


def report(rows: list[dict]) -> None:
    print("-" * 68)
    print("Headless tells remaining per mode (fewer = harder to flag as a bot):")
    for r in rows:
        tl = r["_tells"]
        mark = "clean" if not tl else f"{len(tl)} tell(s)"
        print(f"  {r['_mode']:9} {mark}")
        for t in tl:
            print(f"            - {t}")
    print()
    vanilla = next((r for r in rows if r["_mode"] == "vanilla"), None)
    stealth = next((r for r in rows if r["_mode"] == "stealth"), None)
    if vanilla and stealth:
        before, after = len(vanilla["_tells"]), len(stealth["_tells"])
        print(f"vanilla -> stealth: {before} tells -> {after} tells.")
        if after < before:
            print("The easy tells (webdriver, UA, plugins, window.chrome) are cheap to hide.")
        if after > 0:
            print("What survives is the hard part -- and behavioral/timing/consistency signals,")
            print("not probed here, are harder still. Evasion is an arms race, not a one-time patch.")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="about:blank", help="page to probe (default: about:blank, offline)")
    ap.add_argument("--headful", action="store_true", help="also run a real headed browser as ground truth (opens a window)")
    ap.add_argument("--json", action="store_true", help="dump raw signal dicts")
    args = ap.parse_args()

    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        print("playwright not installed. Run:", file=sys.stderr)
        print("  .venv/bin/python -m pip install playwright && .venv/bin/python -m playwright install chromium",
              file=sys.stderr)
        return 1

    modes = ["vanilla", "args", "stealth"]
    rows: list[dict] = []
    with sync_playwright() as p:
        for m in modes:
            try:
                rows.append(collect(p, m, args.url, headful=False))
            except Exception as e:
                print(f"  [{m}] ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        if args.headful:
            try:
                r = collect(p, "stealth", args.url, headful=True)
                r["_mode"] = "headful"
                r["_tells"] = tells(r)
                rows.append(r)
            except Exception as e:
                print(f"  [headful] ERROR: {type(e).__name__}: {e}", file=sys.stderr)

    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return 0 if rows else 1
    print_table(rows)
    report(rows)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
