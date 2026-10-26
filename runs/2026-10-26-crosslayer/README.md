# Cross-layer scorer evaluation (2026-10-26)

I built a verdict that looks for contradictions between the TLS, HTTP/2, HTTP and
JavaScript layers of a single connection, and that ignores JA4 entirely. This
directory holds the artifact (`scores.json`) and my reading of it. Author: Thiago Goncalves.

## The JA4 result (why this scorer exists)

My earlier phases tried to resolve a browser version from the JA4 family. That did not
survive measurement. This is the motivating verified measurement (taken before this run,
not produced by it): curl_cffi `chrome124` and real Chrome 130 driven through Playwright
emit a byte-identical full JA4, `t13i1515h2_8daaf6152771_02713d6af862`. The normalized
extension key is dominated by the launch profile, so keys collide across versions. A
forger using curl_cffi is therefore indistinguishable from a real Chrome at the TLS layer
by JA4 alone. The details are in the "Phase 3 revision - 2026-10-26" section of
`docs/superpowers/specs/2026-10-25-version-level-crosslayer-consistency-design.md`. For that reason the verdict here is JA4-free: `scores.json` carries each
client's JA4 only as non-decisive context, and it never enters the scorer.

This run's own data fits that finding. Here `curl:chrome124` reports the collision value
above, while `browser:chromium` reports `t13d1516h2_8daaf6152771_806a8c22fdea`, which is
different. That is not a contradiction. The `d` versus `i` is destination-domain versus
IP: the browser was pointed at `localhost` and the HTTP clients at `127.0.0.1`. The
differing extension suffix comes from the different launch profile of that browser run,
which illustrates the launch-profile-dominated finding rather than undercutting it.

## Per-client verdicts

5 of 5 clients scored automated. Every client was driven at `/probe/<nonce>`, so
JS absence is an observed signal rather than an artifact of which URL was hit.

| client | label | confidence | contradictions fired (layer/code) |
|---|---|---|---|
| curl:chrome124 | automated | medium | js/js_absent |
| curl:safari17_0 | automated | high | http2/akamai_family_vs_ua, js/js_absent, http/missing_client_hints |
| tls:chrome_124 | automated | high | js/js_absent, http/missing_client_hints, http/missing_sec_fetch |
| stdlib:urllib | automated | high | js/js_absent, http/missing_client_hints, http/missing_sec_fetch, http2/no_http2 |
| browser:chromium | automated | medium | js/headless_gpu, js/no_window_chrome, js/webdriver_true, js/perm_mismatch |

## Detection by layer

The JS layer is the backbone: clients that fetch the probe HTML but never run its script
never POST `/collect`, so they have no JS layer (curl:chrome124, curl:safari17_0, tls:chrome_124, stdlib:urllib in this run).
The other layers catch clients that are inconsistent with their own claimed identity.

| client | layers with a contradiction | checks and details |
|---|---|---|
| curl:chrome124 | js | js_absent (strong): probe served but no JS results returned |
| curl:safari17_0 | http, http2, js | akamai_family_vs_ua (strong): UA says chrome, HTTP/2 fingerprint says safari; js_absent (strong): probe served but no JS results returned; missing_client_hints (strong): Chrome UA without Sec-CH-UA client hints |
| tls:chrome_124 | http, js | js_absent (strong): probe served but no JS results returned; missing_client_hints (strong): Chrome UA without Sec-CH-UA client hints; missing_sec_fetch (strong): Chrome UA without Sec-Fetch-* headers |
| stdlib:urllib | http, http2, js | js_absent (strong): probe served but no JS results returned; missing_client_hints (strong): Chrome UA without Sec-CH-UA client hints; missing_sec_fetch (strong): Chrome UA without Sec-Fetch-* headers; no_http2 (strong): chrome UA but no HTTP/2 observed |
| browser:chromium | js | headless_gpu (strong): software GL renderer: ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (LLVM 10.0.0) (0x0000C0DE)), SwiftShader driver); no_window_chrome (strong): Chrome UA but window.chrome absent; webdriver_true (strong): navigator.webdriver is true; perm_mismatch (weak): Notification.permission vs permissions API mismatch |

## Scope and caveats

- The only "real browser" is headless Playwright Chromium. It legitimately reports
  `webdriver` and a SwiftShader GPU, so scoring it automated is the expected outcome, not a
  false positive I am excusing. The scorer's `real` path is exercised only by a synthetic
  coherent record in the unit tests.
- A headed-browser true-negative baseline is deferred.
- A coherent forger (Phase 4) that fixes all layers together is deferred; these five
  clients are naive or single-layer forgeries.
- Scope is desktop Chromium on macOS/arm64. iOS Chrome and WebKit-based browsers are out of
  scope; they would trip the now-strong client-hint checks.
- Small n (5 clients, one run each). These are illustrations of which layer catches which
  forgery, not rates.

## Reproduce

```
python -m crosslayer --out runs/2026-10-26-crosslayer
```
