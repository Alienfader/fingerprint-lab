# fingerprint-lab

Two small, self-contained experiments that show how servers tell automated clients
apart from real browsers — at the **network layer** (TLS/HTTP2 fingerprinting) and the
**browser layer** (headless-detection signals in JavaScript).

Both are built to be *run*, not just read. Each prints a side-by-side table and a set
of pass/fail checks, so you can watch a spoofed `User-Agent` fail to hide a Python TLS
stack, and watch headless "stealth" patches remove browser tells one at a time.

- **`ja3_diff.py`** — sends an identical request through four HTTP clients and reads back
  each one's JA3 / JA4 / HTTP-2 fingerprint from a public TLS inspector.
- **`browser_fp.py`** — launches the same Chromium three different ways and counts how
  many classic headless tells survive each level of evasion.

---

## Why this exists

A huge amount of folklore says "just set a real `User-Agent` and you look like a browser."
You don't. Modern bot detection ignores the UA header almost entirely and keys on signals
the header can't touch:

- **TLS fingerprint (JA3/JA4):** the shape of your TLS ClientHello — cipher order,
  extensions, curves, ALPN — identifies your TLS stack before any HTTP is sent. A Python
  client and Chrome look nothing alike here, whatever UA they claim.
- **HTTP/2 fingerprint:** frame settings and header/pseudo-header order. A client that
  claims to be Chrome but speaks HTTP/1.1 is contradicting itself.
- **Browser/JS signals:** `navigator.webdriver`, plugin list, `window.chrome`, WebGL
  renderer, and consistency checks a headless browser fails by default.

This repo lets you observe all of the above directly, against your own traffic.

---

## Requirements

- Python 3.10+
- Outbound HTTPS (the TLS demo inspects your own request via `tls.peet.ws`)
- ~100 MB disk for the browser demo (Playwright downloads Chromium)

## Quickstart

```bash
./bootstrap.sh                 # builds .venv, installs requests, curl_cffi, tls-client, playwright + chromium
.venv/bin/python ja3_diff.py   # network layer: TLS/HTTP2 fingerprints
.venv/bin/python browser_fp.py # browser layer: headless tells
```

The TLS demo also runs with **zero dependencies** — `python3 ja3_diff.py` works on a
stock interpreter and prints the stdlib (`urllib`) row alone. Skip the heavy Chromium
download with `SKIP_BROWSER=1 ./bootstrap.sh`.

---

## `ja3_diff.py` — the network layer

Fires the *same* request, with the *same* Chrome `User-Agent` header, through four clients
and asks a TLS inspector what each actually presented on the wire:

| client | what it is |
|---|---|
| `urllib` | Python standard library |
| `requests` | the popular HTTP library — still a Python TLS stack |
| `curl_cffi` | patched libcurl that impersonates a browser's TLS+HTTP2 |
| `tls_client` | a *second* forgery engine (Go/uTLS behind a Python binding) |

### Example output

```
        JA3 (MD5) :
                    urllib           f21f8e6cf70d5980ecfe9fa2e0ef401c
                    requests         84442eae56523a0a09a58c8ad56661b2
                    curl:chrome150   99cb3254c185be9c09a177be9ccd5926
                    tls:chrome_150   37598074abe667383bd5b9888f33355c
              JA4 :
                    urllib           t13d1711_ab0a1bf427ad_8e6e362c5eac
                    requests         t13d1712h1_ab0a1bf427ad_882d495ac381
                    curl:chrome150   t13d1516h2_8daaf6152771_806a8c22fdea
                    tls:chrome_150   t13d1516h2_8daaf6152771_806a8c22fdea
  HTTP/2 (Akamai) :
                    urllib           (none)
                    requests         (none)
                    curl:chrome150   52d84b11737d980aef856699f885ca86
                    tls:chrome_150   52d84b11737d980aef856699f885ca86
```

Read it top to bottom: the UA header is identical across all four (the inspector confirms
it), yet the fingerprints diverge. `urllib` and `requests` present **no** HTTP/2 fingerprint
at all — they fell back to HTTP/1.1, which a real Chrome never does. The two impersonation
engines, meanwhile, land on the **same** JA4 and HTTP/2 hash: two independent
implementations producing one browser fingerprint.

### Built-in checks

| check | what it asserts | on failure |
|---|---|---|
| `[1]` / `[1b]` | fingerprints diverge under one UA; chrome ≠ safari | — |
| `[2]` JA4 fidelity | the chrome profile's JA4 matches a captured real Chrome | **exit 2** (authoritative — JA4 is stable) |
| `[3]` JA3 fidelity | JA3 matches too | **warn only** (JA3 drifts by design) |
| `[4]` cross-engine | `curl_cffi` and `tls_client` agree on JA4 | warn only |

Exit codes are CI-friendly: `0` ok · `2` a JA4 assertion failed · `1` no client ran.

### Capturing a real-browser reference

The fidelity checks need ground truth. Either open <https://tls.peet.ws/api/all> in your
real browser and save the JSON as `real_chrome.json`, or pin hashes on the command line:

```bash
python ja3_diff.py --expect-ja4 t13d1516h2_...   # authoritative, fails on mismatch
python ja3_diff.py --expect-ja3 <md5>            # advisory, warns only
```

A committed `real_chrome.json` (captured from Chromium 156) ships with the repo, and the
default profiles (`chrome150`) are chosen to match it — so a bare run is green.

---

## `browser_fp.py` — the browser (JS) layer

Launches the same Chromium three ways, along the real evasion arms race, and counts the
headless **tells** a detection script would read from inside the page:

| mode | what it does | tells remaining |
|---|---|---|
| `vanilla` | plain headless, no mitigation | 6 |
| `args` | `--disable-blink-features=AutomationControlled` + UA override | 4 |
| `stealth` | init-script patches: webdriver, plugins, languages, `window.chrome`, permissions, WebGL | 0 |

Tells checked: `navigator.webdriver`, `HeadlessChrome` in the UA, an empty plugin list,
missing `window.chrome`, the `Notification` / `permissions.query` mismatch, and a
software/SwiftShader WebGL renderer (no real GPU). The canvas fingerprint is printed too —
notably, it stays **identical** across all three modes, because none of these patches
touch it.

> **"0 tells" ≠ undetectable.** It means *these* tells are gone. The WebGL spoof is itself
> detectable (a patched `getParameter.toString()` leaks native-code tampering), and
> behavioral, timing, and cross-signal consistency checks aren't probed here. Evasion is an
> ongoing arms race, not a one-time patch.

Everything runs against `about:blank` — all signals come from the JS environment. Point
`--url` at a detector you control to go further; add `--headful` for a real headed browser
as a ground-truth row.

---

## Key takeaways

- **The `User-Agent` header is theater.** Identical UA, four different JA3s.
- **JA3 is unstable for modern Chrome.** Since Chrome 110, the browser randomizes TLS
  extension order per connection, so its JA3 changes run to run (observed:
  `3fe9cb… / c1d4c9… / f64925…` for one profile). **JA4** sorts extensions before hashing
  and stays constant, which is why it has largely superseded JA3 for Chrome. A static
  "block this JA3" rule is brittle.
- **Fingerprint fidelity is version-specific.** curl_cffi's `chrome124` profile does *not*
  match a real Chrome 156 — same cipher/ALPN prefix, different extension hash. Matching the
  real JA4 required sweeping profiles and landing on `chrome150`. The flip side is a strong
  detection signal: a client advertising Chrome 156 while carrying Chrome 124's extension
  hash is almost certainly forged.
- **Consistency beats any single signal.** The reliable tells are contradictions *across*
  layers — Chrome UA + Python TLS, HTTP/2 claim + HTTP/1.1 reality, headless WebGL + human
  UA — not any one fingerprint in isolation.

---

## Scope & ethics

This is an educational project for understanding detection and evasion. Everything here
inspects **your own** outbound fingerprint against public self-inspection endpoints, or
reads the local JS environment on `about:blank`. **No third-party target is probed.**

Keep any follow-on work to systems you're authorized to test — vendor demo pages, your own
infrastructure, or in-scope bug-bounty targets.

## Layout

```
ja3_diff.py      network-layer TLS/HTTP2 fingerprint diff + fidelity checks
browser_fp.py    browser-layer headless-tell comparison
bootstrap.sh     builds the venv and installs dependencies
real_chrome.json captured real-browser reference for the fidelity checks
```
