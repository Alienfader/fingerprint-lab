# fingerprint-lab

A runnable study of how servers tell **real browsers** from **automated clients** across
every layer of a request — TLS, HTTP/2, HTTP headers/client-hints, and the JavaScript/GPU
environment — and of how far a well-formed forgery can get before some layer gives it away.

It began as two small scripts that make the point concretely, and grew into a five-phase,
measured investigation with a loopback capture server, a cross-layer consistency scorer, a
coherent forger that defeats it, and an active challenge that catches the forger. Every
result below is produced by a committed artifact under `runs/` and is reproducible with the
command next to it.

**→ The narrative, with every headline number traced to its artifact: [`docs/FINDINGS.md`](docs/FINDINGS.md).**

Everything is **self-only**: each client is pointed at the researcher's own loopback
server, or inspects its own outbound fingerprint against a public self-inspection endpoint.
No third-party target is ever probed.

---

## Quickstart

```bash
# 1. set up (Python 3.11+; developed on 3.15)
./bootstrap.sh                      # creates .venv, installs deps + a Chromium build
#    ...or, equivalently, by hand:
#    python -m venv .venv
#    .venv/bin/pip install -r requirements.txt
#    .venv/bin/python -m playwright install chromium

# 2. prove the core instantly — 95 tests, ~9s, no browser, no network:
.venv/bin/python -m pytest -m "not integration"

# 3. run the full suite (launches a real Chromium on loopback; ~2 min):
.venv/bin/python -m pytest
```

If step 2 is green, the repo is working. Step 3 and the phase commands below add the
browser/network tiers.

---

## The five phases

Each phase is a Python package with a `python -m <pkg>` entry point (except Phase 1, a
library the others drive). Running it writes a fresh artifact to `runs/`; the committed
copy is the evidence for the write-up.

| phase | what it shows | run it | artifact |
|---|---|---|---|
| **1 — capture server** (`capture/`) | A loopback TLS server that joins a client's JA3/JA4 + HTTP/2 Akamai fingerprint + headers/client-hints + a JS/GPU probe into one record, by nonce. | *(library; driven by the phases below)* | `runs/2026-10-25/phase1_capture.json` |
| **2 — version map** (`versionmap/`) | How finely a TLS ClientHello alone resolves a Chrome version. Finding: **not well** — the normalized JA4 key is dominated by the launch profile and collides across versions. | `python -m versionmap --out runs/2026-10-25-version-map --n 10` | `runs/2026-10-25-version-map/` |
| **3 — cross-layer scorer** (`crosslayer/`) | A JA4-free verdict that flags contradictions across layers. Catches all five sample clients; the JA4-perfect `curl_cffi` is caught **only** by the absent JS layer. | `python -m crosslayer --out runs/2026-10-26-crosslayer` | `runs/2026-10-26-crosslayer/` |
| **4 — coherent forger** (`forger/`) | A forger (impersonation transport + a fabricated, internally-consistent JS payload) that **defeats** the passive scorer — scores `real`, zero contradictions. | `python -m forger --out runs/2026-10-26-forger` | `runs/2026-10-26-forger/` |
| **5 — active challenge** (`challenge/`) | A per-request seeded canvas/WebGL challenge the client must *compute live*. Catches exactly the forger passive checks could not; the honest residual (an engine-running forger still passes) is measured too. | `python -m challenge --out runs/2026-10-26-challenge` | `runs/2026-10-26-challenge/` |

All phase CLIs take `--out <dir>`; they start their own loopback server and clean it up.

---

## Reproducibility tiers (what each needs)

The project is built so the core verifies anywhere, and the heavier tiers degrade
gracefully and are documented, not assumed.

- **Tier 0 — unit tests (anywhere).** `pytest -m "not integration"` → **95 tests, ~9s**.
  Pure logic: fingerprint normalization, the scorer's contradiction checks, payload
  builders, the ladders. Needs only the `requirements.txt` deps. No browser, no network.
- **Tier 1 — browser + loopback integration.** `pytest` (full) → **113 tests, ~2 min**, and
  Phases 3–5. Needs: a Chromium build (installed by `bootstrap.sh` / `playwright install
  chromium`), `openssl` on `PATH` (for throwaway self-signed loopback certs), and the
  ability to bind a loopback TLS socket. A few network-marked tests inspect your own
  traffic via the public `tls.peet.ws` endpoint, so they need outbound HTTPS.
- **Tier 2 — the full version map (Phase 2).** The committed map was built over six
  Chrome-for-Testing builds in `~/.cache/fingerprint-lab/chromium`. With only the single
  Playwright Chromium present you get a valid but trivial one-build map; to regenerate the
  multi-version map you install several [Chrome for Testing](https://googlechromelabs.github.io/chrome-for-testing/)
  builds there first. The committed `runs/2026-10-25-version-map/` artifact is the evidence
  either way.

**Platform:** the unit tests are cross-platform. Browser integration is validated on
**macOS/arm64**; the browser-launch flags include macOS keychain-safe options
(`--password-store=basic --use-mock-keychain`) and the build discovery looks in macOS cache
paths, so other platforms may need small adjustments.

---

## Where it started — the two origin scripts

These two standalone scripts make the core point without the server, and still run:

```
                        FINGERPRINT-LAB
        "a matching User-Agent doesn't make you Chrome"

  ja3_diff.py  ──  THE NETWORK LAYER  (TLS / HTTP2) ────────────────┐
                                                                    │
   same URL + same Chrome User-Agent string, four clients:          │
                                                                    │
     urllib      ─┐  stdlib · naked-Python TLS stack                │
     requests    ─┤  popular lib · still a Python TLS stack         │
     curl_cffi   ─┼─ wire ─▶ tls.peet.ws/api/all ─ reflects ─┐      │
     tls_client  ─┘           (echoes YOU to YOU)  JA3/JA4   │      │
                                                             ▼      │
                                             ┌───────────────────┐  │
     CHECK 1  JA3 differs across clients ◀───┤ real_chrome.json  │  │
     CHECK 2  chrome profile JA4 == real? ◀──┤ captured ground   │  │
                                             │ truth (Chrome 156)│  │
     urllib ✗ screams "Python"              └───────────────────┘  │
     curl_cffi / tls_client ✓ forge the ClientHello  (same JA4)    │
                                                                    │
  browser_fp.py  ──  THE BROWSER LAYER  (JS environment) ──────────┤
                                                                    │
   same Chromium, three ways → count headless tells:                │
                                                                    │
     vanilla   ██████  6  plain headless, every tell present        │
     args      ████    4  disable AutomationControlled + UA         │
     stealth   ·       0  init-script patches (webdriver, plugins,  │
                          window.chrome, permissions, WebGL)        │
                                                                    │
  LAYER CAKE — a request is judged bottom-up ──────────────────────┤
     HTTP headers · User-Agent      ◀─ trivially spoofed            │
     JS environment (navigator…)    ◀─ browser_fp.py chips away     │
     TLS ClientHello (JA3/JA4)      ◀─ ja3_diff.py — gives you away │
                                       before byte 1 of HTTP ───────┘
```

- **`ja3_diff.py`** — sends an identical request (identical Chrome `User-Agent`) through
  `urllib`, `requests`, `curl_cffi`, and `tls_client`, and reads each one's real JA3 / JA4 /
  HTTP-2 fingerprint back from a public TLS inspector. The UA is identical; the fingerprints
  diverge. `urllib`/`requests` present no HTTP/2 fingerprint at all (they fell back to
  HTTP/1.1, which real Chrome never does); the two impersonation engines land on the *same*
  JA4. CI-friendly exit codes: `0` ok · `2` a JA4 assertion failed · `1` no client ran.
  Runs on a stock interpreter (the stdlib row needs no dependencies).
- **`browser_fp.py`** — launches the same Chromium three ways along the real evasion arms
  race (`vanilla` → `args` → `stealth`) and counts the headless tells a detection script
  would read in-page: `navigator.webdriver`, a `HeadlessChrome` UA, an empty plugin list,
  missing `window.chrome`, the `Notification`/`permissions.query` mismatch, and a software
  WebGL renderer. "0 tells" means *these* tells are gone — not that the client is
  undetectable (the stealth patches are themselves detectable, and behavioral/consistency
  checks aren't probed here).

---

## Scope & ethics

An educational / research project for understanding detection and evasion. Everything
inspects **your own** fingerprint — against your own loopback capture server, a public
self-inspection endpoint, or the local JS environment. **No third-party target is probed.**
The forger (Phase 4) and the attacker rungs (Phase 5) exist to measure the researcher's own
detector; they are not public-facing or reusable evasion tools. Keep any follow-on work to
systems you are authorized to test.

## Layout

```
capture/        Phase 1 — loopback TLS/HTTP2 capture server + nonce join (library)
versionmap/     Phase 2 — JA4-key → Chromium-version map
crosslayer/     Phase 3 — JA4-free cross-layer consistency scorer
forger/         Phase 4 — coherent forger + evasion ladder
challenge/      Phase 5 — active challenge-response + defender ladder
runs/           committed artifacts (one directory per phase) + the raw captures
docs/FINDINGS.md   the consolidated five-phase write-up
docs/superpowers/  the design spec and per-phase plans (full decision trail)
tests/          unit + integration tests  (pytest -m "not integration" for the fast path)
ja3_diff.py     origin script — network-layer TLS/HTTP2 fingerprint diff
browser_fp.py   origin script — browser-layer headless-tell comparison
bootstrap.sh    one-shot setup (venv + requirements.txt + Chromium)
requirements.txt pinned dependencies
real_chrome.json captured real-browser reference for ja3_diff.py's fidelity checks
```
