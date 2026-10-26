# Coherent forger vs. the cross-layer scorer (2026-10-26)

Author: Thiago Goncalves.

## The attack

Phase 3 ended with one forger the scorer caught only through JS absence: curl_cffi
`chrome124`, which matches Chrome byte for byte at JA4, Akamai HTTP/2 and headers. This
phase asks what happens when that forger also supplies the JS layer. It does a normal
`GET /probe/<nonce>` with curl_cffi, then POSTs a hand-fabricated 12-field payload to
`/collect/<nonce>`. The server joins the two by nonce. That join is application-level and
is not bound to the TLS connection, so the fabricated payload attaches to the genuine
curl_cffi handshake.

## Evasion ladder

Each rung sets exactly one self-reported tell (rung 0 sends no JS at all) and is scored by
the unmodified Phase 3 scorer. 5 of 6 rungs scored non-real.

| rung | scorer label | confidence | surviving contradictions |
|---|---|---|---|
| rung0 naive | automated | medium | js_absent |
| rung1 js+webdriver | automated | medium | webdriver_true |
| rung2 no-webdriver+swiftshader | automated | medium | headless_gpu |
| rung3 real-gpu+no-window-chrome | automated | medium | no_window_chrome |
| rung4 window-chrome+ua-mismatch | automated | medium | js_ua_mismatch |
| rung5 fully-coherent | real | high | none |

Every non-top rung is caught by the contradiction it was built to trip, and only that one.
The top rung neutralizes all of them together and scores `real` with
`high` confidence and 0 contradictions.

## What this measures

The scorer catches this forger for as long as at least one self-reported JS value is
off. Every Phase 3 check inspects values the client reports about itself, so the checks
form a finite, enumerable list. A forger that reports coherent values for all of them
exhausts the list, and passive cross-layer consistency has nothing left to fire on. The
measured attacker cost is an impersonation library, about twelve coherent JS fields and a
two-request nonce replay. The asymmetry favors the attacker: the defender maintains the
checks and the forger only has to satisfy them once.

## Scope and ethics

This is self-only. It runs on loopback against my own capture server and my own scorer.
It measures my detector's limits and is not a reusable evasion product: it targets no
third-party service, and the payload is shaped to this lab's probe schema. The result
motivates the next defender move, active challenge-response, where the server asks for
something a replayed or fabricated report cannot answer.

## Reproduce

```
.venv/bin/python -m forger --out runs/2026-10-26-forger
```
