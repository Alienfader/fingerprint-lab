# Fingerprint diff lab

Two hands-on demos of how automated clients get told apart from real browsers:

- **`ja3_diff.py`** — the **network layer**. Why a spoofed `User-Agent` header doesn't
  make you look like a browser: the TLS ClientHello (JA3/JA4) and HTTP/2 settings give
  you away first.
- **`browser_fp.py`** — the **browser/JS layer**. The signals a detection script reads
  from inside the page (navigator.webdriver, plugins, window.chrome, WebGL, a
  permissions inconsistency), and how headless "stealth" patches hide them one by one.

## Run it

```bash
./bootstrap.sh                 # one-time: build .venv, install requests + curl_cffi + tls-client
.venv/bin/python ja3_diff.py   # urllib, requests, curl_cffi (chrome150/safari17_0), tls_client (chrome_150/safari_16_0)
```

Two independent forgery engines are compared: **curl_cffi** (patched libcurl) and
**tls_client** (Go/uTLS behind a Python binding). Their profile naming differs —
curl_cffi `chrome124`, tls_client `chrome_124`. Skip tls_client with `--tls-client ''`.

Zero-dependency baseline (no venv needed): `python3 ja3_diff.py` runs the urllib
row alone.

## What you should see

- All clients send the **same Chrome UA header** — the server confirms it saw the
  same UA from every one.
- Their **JA3 / JA4 / HTTP/2 fingerprints differ anyway**. That gap is what anti-bot
  TLS fingerprinting keys on.
- `urllib` and `requests` present **no HTTP/2 fingerprint** (they negotiated H1); a
  real Chrome always speaks H2 with a characteristic signature. A "Chrome" client
  with no H2 fingerprint is a self-contradiction.
- `curl:chrome124` and `curl:safari17_0` produce **different** JA3s → impersonation
  is per-profile, not a single trick.

## The built-in checks

- **[1] / [1b]** run automatically: JA3 diverges across clients; chrome ≠ safari.
- **[2] JA4 fidelity (authoritative)** — compares the chrome profile's JA4 to a real
  Chrome. JA4 is **stable**, so a mismatch is a real failure and **exits `2`**.
- **[3] JA3 fidelity (advisory)** — compares JA3 too, but only **WARNs** on a
  mismatch and never fails the build, because modern Chrome's JA3 drifts per
  connection (see gotcha below).
- **[4] cross-engine agreement (advisory)** — curl_cffi and tls_client, both forging
  the same Chrome version (default 150), should produce the **same JA4**. When they do, that's strong evidence
  both are faithful (two independent implementations, one fingerprint). Their *JA3s*
  still differ, because each shuffles extensions independently — see the gotcha.

Capture ground truth once:
  1. Open <https://tls.peet.ws/api/all> in your **real Chrome**.
  2. Save the raw JSON as `real_chrome.json` in this folder (both JA3 and JA4 are read from it).
  3. Re-run — `[2]` and `[3]` now compare against your real browser.

Or pin hashes directly:
```bash
python ja3_diff.py --expect-ja4 t13d1516h2_...   # authoritative, fails build on mismatch
python ja3_diff.py --expect-ja3 <md5>            # advisory, warns only
```
Exit codes: `0` ok · `2` a JA4 assertion failed · `1` no client ran. (CI-usable.)

## browser_fp.py — the JS layer

```bash
.venv/bin/python browser_fp.py          # vanilla / args / stealth headless modes
.venv/bin/python browser_fp.py --headful  # + a real headed browser as ground truth (opens a window)
```

Launches the same Chromium three ways along the detection arms race and counts how
many classic headless **tells** survive each step:

| mode | what it does | tells seen here |
|---|---|---|
| `vanilla` | plain headless, no mitigation | 6 |
| `args` | `--disable-blink-features=AutomationControlled` + UA override | 4 |
| `stealth` | add_init_script patches (webdriver, plugins, languages, window.chrome, permissions, WebGL) | 0 |

Tells checked: `navigator.webdriver`, `HeadlessChrome` in UA, empty `navigator.plugins`,
missing `window.chrome`, the Notification/permissions-query mismatch, and a
software/SwiftShader WebGL renderer (no real GPU).

**Honest caveat:** "0 tells" means *these* tells are gone, not "undetectable." The WebGL
spoof is itself detectable (a patched `getParameter.toString()` leaks), and behavioral,
timing, and cross-signal-consistency checks aren't probed here. Evasion is an arms race,
not a one-time patch — which is itself the point to make in an interview.

Runs against `about:blank` — all signals come from the JS environment, no third-party
site is contacted. Point `--url` at a detector you control to go further.

## Gotcha worth knowing (and worth saying in an interview)

**JA3 is unstable for modern Chrome.** Since Chrome 110, Chrome randomizes TLS
extension order per connection (GREASE + shuffle), so the JA3 *md5 changes run to
run* — we saw `3fe9cb… / c1d4c9… / f64925…` across three runs of the same profile.
**JA4 stays constant** (`t13d1516h2_8daaf6152771…`) because it sorts extensions
before hashing. This is why JA4 largely superseded JA3 for Chrome, and why a naive
"block this exact JA3" rule is brittle. If your `--expect-ja3` fidelity check flaps,
that's the reason — compare JA4, or match on the version-specific profile.

## Next experiments

- `--impersonate chrome120,chrome131,safari17_0` — compare several real-browser profiles.
- Add a `tls_client` (Go-binding) row and compare its forgery approach to curl_cffi's.
- Point `--url` at a JA4+H2-aware target you control to see consistency checks combine.

## Scope

Everything here inspects **your own** outbound fingerprint against a public echo
service that reflects it back. No third-party target is probed. Keep any follow-on
work to targets you're authorized on (vendor demos, your own infra, bug-bounty scope).
