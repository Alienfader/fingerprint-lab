# Active challenge vs. the coherent forger (2026-10-26)

Author: Thiago Goncalves.

## The active challenge

Phase 4 ended with a forger the passive scorer could not catch: curl_cffi `chrome124`
plus a fabricated 12-field JS payload scored `real` with zero contradictions, because every
Phase 3 check inspects values the client reports about itself. This phase stops asking the
client what it is and makes it prove it can run an engine.

For each probe the server issues a fresh nonce and a seed. The page must render a
seeded canvas/WebGL scene live and POST the resulting hash to `/answer`, joined to the
probe by nonce. The expected value comes from a reference oracle: the lab's own Chromium
build, launched on the same host against the same challenge. The verifier is an exact
string match, with no tolerance.

## Defender ladder

Each rung is given a fresh challenge. The oracle answers it first, then the rung does.

| client | tls layer | runs engine | challenge outcome |
|---|---|---|---|
| honest-browser | real-chromium | yes | passed |
| coherent-forger | curl_cffi | no | CAUGHT |
| engine-forger | curl_cffi | yes | passed |

These rows are generated from `challenge.json` on every run. Rungs caught: 1 of
3. Rungs passing: 2 of 3.

Caught: coherent-forger

Passing: honest-browser, engine-forger

## What this measures

The active challenge catches the rungs that cannot compute the render, and only those: here,
coherent-forger. A forger can fabricate self-reported values, but it cannot compute a per-nonce
seeded render without a real engine. In Phase 4 that same coherent forger scored `real`
against the passive scorer.

The honest residual is that a rung with a real engine behind a curl_cffi connection still
passes (engine-forger). The real-Chromium baseline (honest-browser) passes by construction. The challenge does not make forging impossible. It raises the attacker
floor from "fabricate roughly 12 JSON fields" (Phase 4) to "run a real browser engine." That
is a real change in cost, but not a closed door.

The gap that remains is the join. The answer is tied to the probe by an application-level
nonce, not by the probe's TLS connection, so an engine can compute in one place and speak
from another. Binding the answer to the connection (channel binding) is the next arm.

## Scope and ethics

Self-only. Everything runs on loopback against my own detector, with browsers and clients I
launch myself. Nothing touches a third-party site.

Exact match is only defensible because rendering here is deterministic: software rendering
on one host, one browser build. The digest is Chromium-build-specific. That has two
consequences. The oracle and every client must use the same build, so the ladder passes no
explicit binary and all of them resolve the same newest one. It also shows the answer is
tied to the engine and version, which is another reason it cannot be produced without the
exact engine. Cross-GPU variance is a known caveat: on different hardware the same build
could render differently and exact match would need rethinking. This is a measurement of one
host, not a product.

## Reproduce

```
.venv/bin/python -m challenge --out runs/2026-10-26-challenge
```

It launches real browsers and takes a few minutes. Outcomes are written to `challenge.json`.
