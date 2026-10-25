# Anti-bot detection and evasion: what fingerprint-lab actually shows

*Thiago Goncalves — 2026-10-24*

This is a writeup of what my two experiments in this repo, `ja3_diff.py` and
`browser_fp.py`, show about how servers tell automated clients apart from real browsers,
and how far the usual evasion techniques get you. I've kept it to what the code does and
what I saw when I ran it. Both tools only look at **my own** traffic: `ja3_diff.py` sends
requests to a public self-inspection echo service (`tls.peet.ws/api/all`), and
`browser_fp.py` reads the JS environment on `about:blank`. Nothing here was tested against
a commercial bot-management product, so I make no claims about how any vendor scores these
signals. Where I go past the evidence, I say so.

All numbers below come from a run on 2026-10-24 on an Apple M1 MacBook (macOS, arm64),
Python 3.15.0, with Playwright's bundled Chromium 156 and the curl_cffi / tls_client
profiles named in each section. The raw output — text and `--json`, plus the exact
environment — is saved in `runs/2026-10-24/`, so every value here is reproducible. One
caveat on the fingerprints themselves: the shuffled JA3 values vary from run to run by
design (see §1), so a re-run will show different JA3s; JA4, HTTP/2 and PeetPrint are
stable.

---

## 1. The network layer: TLS and HTTP/2 fingerprints

### What the experiment does

`ja3_diff.py` sends one GET, with one hard-coded Chrome 124 `User-Agent` header, through
six clients: `urllib`, `requests`, curl_cffi impersonating `chrome150` and `safari17_0`,
and tls_client (Go/uTLS behind a Python binding) impersonating `chrome_150` and
`safari_16_0`. The echo service sends back the JA3, JA4, HTTP/2 (Akamai-style) and
PeetPrint fingerprints it saw for each connection, and the script compares them with
each other and with a saved reference capture (`real_chrome.json`).

### What it shows

**The UA header doesn't hide the TLS stack.** All six clients sent the same UA, and the
server echoed back that same string for every one of them. They still produced six
different JA3 hashes. JA4 makes the gap easy to read:

| client | JA4 | HTTP/2 |
|---|---|---|
| urllib | `t13d1711_ab0a1bf427ad_0d46a1bf4a7c` | none (HTTP/1.1) |
| requests | `t13d1712h1_ab0a1bf427ad_8deb338c2fb1` | none (HTTP/1.1) |
| curl:chrome150 | `t13d1516h2_8daaf6152771_806a8c22fdea` | `52d84b11…` |
| tls:chrome_150 | `t13d1516h2_8daaf6152771_806a8c22fdea` | `52d84b11…` |
| curl:safari17_0 | `t13d2014h2_a09f3c656075_14788d8d241b` | `959a7e81…` |
| tls:safari_16_0 | `t13d2014h2_a09f3c656075_14788d8d241b` | `dda308d3…` |

The JA4 prefix alone gives the Python clients away: 17 ciphers and 11–12 extensions, with
no `h2` in ALPN. Chrome's shape is 15 ciphers, 16 extensions and `h2`. The stdlib clients
never negotiate HTTP/2, so they have no HTTP/2 fingerprint at all. A client that claims to
be Chrome but speaks HTTP/1.1 is contradicting itself before it sends a single header.

**Forging the ClientHello works, and it's specific to each profile.** Both impersonation
engines produced the reference JA4 *and* the reference HTTP/2 hash for Chrome, and the
Chrome and Safari profiles came out clearly different. Two independent implementations (a
patched libcurl/BoringSSL and Go's uTLS) landed on the same JA4 and PeetPrint. I read that
as good evidence that the forged fingerprint is a property of the bytes on the wire and not
an accident of one library.

One exception: for the Safari profiles the two engines agreed on JA4 but **not** on the
HTTP/2 hash (`959a7e81…` vs `dda308d3…`). They were also nominally different Safari
versions (17.0 vs 16.0). So TLS forgery can match while the HTTP/2 layer still drifts
between implementations. That's one more place where a forgery can slip.

**JA3 is the wrong thing to pin for modern Chrome.** In the same run where curl_cffi's
Chrome JA4 matched the reference exactly, its JA3 (`a80794c4…`) didn't match the
reference JA3 (`b221f968…`). Chrome 110+ shuffles the order of its TLS extensions on every
connection. JA3 hashes them in wire order, so its value changes from run to run. JA4 sorts
the extensions before hashing, so it stays put. The script treats this distinction as
policy: a JA4 mismatch fails the run (exit 2), and a JA3 mismatch only produces a warning.
For a defender, the practical point is that a static "block this JA3" rule will churn
against real Chrome. The earlier README run shows the same thing from the other side: one
profile produced several different JA3s across runs.

**Matching depends on the version.** The README records that curl_cffi's `chrome124`
profile did not match a Chromium 156 capture (same cipher/ALPN prefix, different extension
hash). I had to sweep profiles until `chrome150` lined up. Flipped around for detection:
the extension hash carries version information, so it can be checked against the version
the client claims.

### Caveats I should own

- **My "real Chrome" reference is a headless Chromium.** The `user_agent` inside
  `real_chrome.json` is `HeadlessChrome/156.0.8078.4`. That's Playwright's bundled
  Chromium, not my everyday headed Chrome. I *expect* headless and headed builds of the
  same version to share a TLS stack, but this repo doesn't prove that. The fidelity check
  proves "forged == this Chromium build", not "forged == the Chrome a user runs".
- **The tool contradicts itself across layers.** Every client sends a `Chrome/124` UA,
  while the passing Chrome forgery has a Chrome 150-era JA4 and the reference is version
  156. The script holds the UA constant on purpose to isolate the TLS layer, but the
  result is that the "faithful" forgery is itself a UA/TLS version mismatch. A detector
  that cross-checks the two would catch it. I left this alone as a teaching device, but it
  proves the point of section 3 better than anything I wrote on purpose.
- The echo service is a single third-party observer. I'm trusting its JA3/JA4/Akamai
  implementations. I haven't cross-checked them against my own packet capture.

---

## 2. The browser layer: headless tells

### What the experiment does

`browser_fp.py` launches the same Chromium three ways and runs one in-page probe script
that collects `navigator.webdriver`, the UA, `plugins.length`, `languages`,
`window.chrome`, `hardwareConcurrency`, `platform`, the WebGL vendor/renderer, a
Notification/permissions consistency check, and a canvas hash. A Python function
(`tells()`) then counts six "headless tells".

| mode | what changes | tells (this run) |
|---|---|---|
| vanilla | plain headless Playwright Chromium | 6 |
| args | `--disable-blink-features=AutomationControlled` + UA override | 4 |
| stealth | args + an init script that overrides webdriver, plugins, languages, `window.chrome`, `permissions.query`, and WebGL `getParameter` | 0 |

### What it shows

- **The cheap tells really are cheap.** One launch flag clears `navigator.webdriver`. A
  context option replaces `HeadlessChrome/156…` in the UA. Neither touches page code.
- **The rest need you to lie inside the page.** An empty plugin list, a missing
  `window.chrome`, the Notification-denied/permissions-prompt mismatch, and a SwiftShader
  WebGL renderer (`ANGLE (Google, Vulkan … SwiftShader …)`) all survive the launch flags.
  You only get rid of them by redefining browser APIs before the page's scripts run.
- **Some surfaces stay put through all three modes.** The canvas hash was identical in
  vanilla, args and stealth (`3a5a21e78b1724c1`). None of these patches touch canvas, so
  anything keyed on canvas sees one browser behind three disguises. `platform`
  (`MacIntel`) and `hardwareConcurrency` (8) also didn't change.

### Why "0 tells" is a weak result

I want to be blunt about this, because the table looks better than it is.

1. **The checks grade their own patches.** The stealth patches were written against
   exactly the six conditions `tells()` checks. Reaching zero proves the patches cover
   *my* checklist and nothing more.
2. **The lies are shallow.** Here's what a slightly smarter probe would see:
   - `navigator.plugins` returns a plain JS array `[1,2,3,4,5]`, not a `PluginArray` of
     `Plugin` objects. It passes `length > 0` and fails almost any type or content check.
   - `permissions.query` and `WebGLRenderingContext.prototype.getParameter` are replaced
     with ordinary JS functions, so their `toString()` no longer says `[native code]`.
     The patched `query` also returns a plain object, not a `PermissionStatus`.
   - The WebGL patch only covers `WebGLRenderingContext`. A probe that asks a
     `webgl2` context gets the real SwiftShader string. *(I inferred this from the code;
     the probe doesn't test WebGL2, so I haven't verified it.)*
   - `window.chrome = { runtime: {} }` is a stub. Real Chrome's object has more shape.
3. **The disguise contradicts the hardware.** Stealth mode reports an
   `Intel Iris OpenGL Engine` GPU, and this run was on an Apple M1. Chrome's UA and
   `platform` say "Intel Mac" on Apple silicon anyway, so those two fields don't expose
   it. My guess (unverified) is that other WebGL parameters, extension lists or WebGPU
   adapter info would. The UA also claims Chrome 124 while the JS engine is 156, which
   feature detection could expose.
4. **The `--headful` row isn't clean ground truth.** The docstring calls it "a real
   headed Chromium as ground truth", but the code runs `collect(p, "stealth", …,
   headful=True)`: it's the *stealth-patched* configuration in a headed window. Its tell
   count shows what headed rendering adds on top of the patches. It doesn't show what an
   unmodified browser looks like. I need to fix that, either by adding a true unpatched
   headed mode or by relabeling the row.
5. **Behavior isn't measured at all.** No mouse movement, timing, scroll, focus or
   interaction signals are collected. Everything here is a static environment snapshot.

---

## 3. The real problem is consistency across layers

Put the two experiments side by side and one pattern stands out. **No single signal
mattered as much as the contradictions *between* signals.** Every evasion here fixes one
layer and opens a mismatch with another:

| claim in one layer | contradicted by | where it shows up here |
|---|---|---|
| UA says Chrome | Python TLS ClientHello, no HTTP/2 | urllib / requests rows |
| UA says Chrome 124 | JA4 of a Chrome 150/156 build | the *passing* curl/tls Chrome rows |
| UA says Chrome 124 | JS engine is Chromium 156 | browser_fp args/stealth modes |
| GPU says Intel Iris | host is Apple M1 | stealth WebGL row |
| plugins.length = 5 | plugins aren't `Plugin` objects | stealth patch (by inspection) |
| "no automation" | canvas hash unchanged across disguises | all three browser modes |

Here's why I think this matters (my reasoning, not something I measured). One fingerprint
on its own is a weak classifier. Real users run odd browser versions, odd GPUs and privacy
extensions, so a defender who blocks on any single value gets false positives. But a
client has to get *every* layer right *at the same time*, each one consistent with the
version, OS and hardware it claims. The work for the evader grows with the number of
layers a defender cross-checks. The work for the defender mostly doesn't: each extra
cross-check is just another comparison. The tools here forge the TLS layer well and the JS
layer badly, and they never even try to make the two layers agree with each other.

The one thing that gets agreement for free is running a real browser end to end, so TLS,
HTTP/2, JS and GPU all come from one build on one machine. That suggests the more
promising evasion path is "drive a real headed browser and leave it alone", not "patch a
headless one". I haven't tested that here. It's the first item below.

---

## 4. What this repo does not show

- Any result against a production bot-management system. No vendor was probed, and
  nothing here says how any product weighs these signals.
- Behavioral, timing, IP-reputation, cookie/session or challenge (CAPTCHA, proof-of-work)
  signals.
- Whether headed and headless Chromium of the same version share a JA4 (assumed, not
  tested).
- HTTP header order, `Sec-CH-UA` client hints, or `navigator.userAgentData`. These are
  obvious places to look for UA contradictions, and neither tool collects them.

---

## 5. Open questions / next experiments

These are the places I'd take this next. Anything aimed at a real system needs proper
authorization: a vendor's own public demo/detection page, infrastructure I control, or a
bug-bounty program whose scope explicitly includes bot detection.

1. **A real headed baseline.** Add an unpatched headed mode, and capture `real_chrome.json`
   from my everyday Chrome as well as from Playwright's headless build. Diff the JA4 and
   HTTP/2 hashes between them, which settles the headless-vs-headed TLS question in §1.
2. **Make the forger consistent with itself.** Derive the UA, `Sec-CH-UA` and
   `userAgentData` from the impersonation profile instead of hard-coding Chrome 124, and
   add a check that fails when the claimed version and the JA4-implied version disagree.
   That turns the tool's own contradiction into a test.
3. **Build my own detector before trusting anyone's.** Stand up a small server I control
   that logs JA4 + HTTP/2 + header order + client hints and serves a deeper JS probe:
   prototype/`toString` integrity, `PluginArray` typing, WebGL2 and WebGPU adapter info,
   worker-scope `navigator`, font and audio surfaces. Then score every row for cross-layer
   contradictions rather than counting individual tells. The current `tells()` checklist
   would become the "naive detector" baseline.
4. **Measure the stealth patches against that detector.** How many of the six patched
   tells reappear under integrity checks? Does a maintained stealth stack
   (puppeteer-extra-stealth or similar) close those gaps, or just move them?
5. **Hardware consistency.** On M1, find which WebGL/WebGPU parameters reveal Apple GPU
   even when the vendor string is spoofed, and whether a profile can be made internally
   consistent without a real matching GPU.
6. **Track JA4 stability over time.** Run `ja3_diff.py` on a schedule across Chrome
   releases to see how fast a pinned impersonation profile goes stale. That tells me how
   long a static forgery stays credible, and how useful "claimed version vs extension
   hash" is as a detection rule.
7. **Real systems, carefully.** Only after 1–4: run the same rows (Python, forged TLS,
   patched headless, real headed) against vendors' *own* public demo or test pages and
   record which layer each one appears to react to. I'd treat any conclusion from that as
   black-box inference about one configuration on one day, not a general claim about the
   product.
8. **Behavior.** Add a scripted-vs-human interaction track (pointer paths, timing jitter,
   focus/visibility events) to see how much the static fingerprint matters once
   behavioral signals are in play.
