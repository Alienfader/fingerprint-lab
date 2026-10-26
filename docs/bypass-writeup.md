# Cross-layer bot detector — analysis & bypass

A client that passes a multi-layer bot detector which flags contradictions across
a request's TLS, HTTP/2, header, and JavaScript layers — plus the analysis of how
the detector works and the reasoning behind each layer of the bypass.

> **Scope.** Self-only. The detector and every client run against my own loopback
> capture server on 127.0.0.1. No third-party system is probed; this measures my
> own detector, it is not a tool aimed at anyone else's.

## Result (TL;DR)

- A naive `curl_cffi` Chrome client is flagged **automated** — caught solely by the
  absence of a JavaScript layer (every network layer already matches a real browser).
- The finished client scores **real, high confidence, zero contradictions** against
  the detector.
- The whole path is an evasion ladder: each rung neutralizes exactly one detector
  check, from a naive client (flagged) to a fully coherent one (passes).
- Reproduce: `python -m forger --out runs/2026-10-26-forger`

## Methodology

I drove the same request through five clients — `urllib`, `requests`,
`curl_cffi:chrome124`, `tls_client:chrome_124`, and a real headless Chromium — at a
loopback capture server that joins each client's TLS (JA3/JA4), HTTP/2 (Akamai)
fingerprint, HTTP headers/client-hints, and an in-page JS/GPU probe into a single
record. I then diffed each automated client against the real browser, layer by
layer, to find which layer gives it away.

## Detection surface

| signal | how the detector uses it | which naive client it catches | load-bearing? |
|---|---|---|---|
| TLS / JA4 | shape of the ClientHello | `urllib`, `requests` (Python TLS stacks) | weak — `curl_cffi` matches a real Chrome's JA4 byte-for-byte (`t13i1515h2_8daaf6152771_02713d6af862`) |
| HTTP/2 (Akamai) | H2 settings + pseudo-header order vs claimed UA | `tls_client:safari`-shaped H2 under a Chrome UA; `stdlib` (no H2 at all) | yes |
| client hints / Sec-Fetch | Chrome UA must send `Sec-CH-UA` / `Sec-Fetch-*` | `tls_client:chrome_124` | yes |
| JS / GPU environment | presence + coherence of the browser environment | **`curl_cffi:chrome124` — caught by nothing else** | **the backbone** |

Key finding: fix every network layer perfectly and a `curl_cffi` client is still
caught by one thing — there is no browser executing, so no JS layer is reported.

## Implementation

The decisions, not just the code:

- **Transport / TLS + HTTP/2:** `curl_cffi` with `impersonate=chrome124`. One move
  fixes the ClientHello, the HTTP/2 Akamai fingerprint, and header order — it matches
  a real Chrome's JA4 byte-for-byte, so the TLS and H2 checks pass outright.
- **Headers / client hints:** the Chrome impersonation profile already carries a
  coherent `Sec-CH-UA` / `Sec-Fetch-*` set, clearing the client-hint checks.
- **The JS layer (the hard part):** the capture server joins a JS payload to a
  request by a nonce in the URL — a join that is application-level, *not* bound to
  the TLS connection. So the client fetches the probe, then POSTs a fabricated but
  internally-consistent ~12-field browser-environment payload (`navigator.webdriver`
  false, a real-GPU `webglRenderer`, `window.chrome` present, a UA that matches the
  HTTP UA, coherent plugins/platform/canvas). Nothing contradicts anything else.

Code: `forger/coherent.py` (payload builder + driver), `forger/ladder.py` (the ladder).

## Verification

Every verdict is the live output of the detector (`crosslayer.scorer`) on a captured
record — never asserted:

- **Evasion ladder** (`runs/2026-10-26-forger/ladder.json`): rung0 naive → flagged by
  `js_absent`; rung1–4 each trip exactly one named check (`webdriver_true`,
  `headless_gpu`, `no_window_chrome`, `js_ua_mismatch`); rung5 fully coherent →
  `real`, high confidence, zero contradictions.
- **Cost to pass:** an impersonation library + ~12 coherent JS fields + a two-request
  nonce replay.
- **Tests:** 113 total; the pure-logic core is `python -m pytest -m "not integration"`
  (75 tests, ~2s).

## Limitations & what would still catch this

A passive consistency detector is defeatable because every signal it reads is
self-reported — a client that reports coherent values is indistinguishable from a
real one. What catches this client:

- **Active challenge-response** — a per-request seeded canvas/WebGL render the client
  must *compute live*, verified against a reference browser. The coherent client runs
  no engine, so it cannot answer and is caught. (Built and measured: `challenge/`,
  `runs/2026-10-26-challenge/`.)
- **The honest residual** — a client that actually runs a headless browser to compute
  the challenge *passes*; the active check raises the attacker's floor from "fabricate
  ~12 fields" to "run a real engine," it does not close the door.
- **The remaining gap** — the challenge answer is still joined by an application-level
  nonce, not bound to the TLS connection, so it can be relayed. Binding the proof to
  the connection (channel binding) is the next defensive step.

## Reproduce

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -m "not integration"           # core logic, ~2s
.venv/bin/python -m forger    --out runs/2026-10-26-forger      # the bypass + ladder
.venv/bin/python -m challenge --out runs/2026-10-26-challenge   # the active check that catches it
```

## Layout

```
capture/     loopback TLS/HTTP2 capture server + nonce join
crosslayer/  the cross-layer consistency detector (the thing being bypassed)
forger/      the bypass client + evasion ladder
challenge/   the active challenge that catches the bypass
runs/        committed evidence (one directory per experiment)
```
