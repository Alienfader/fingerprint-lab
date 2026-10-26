# Phase 2: version-resolution map (Chromium, macOS/arm64)

I built this to answer one question: how finely can a TLS ClientHello alone resolve a Chromium version? The map goes from a normalized ClientHello key to the set of builds that produce it. Everything below is computed from `corpus.json` and `version_map.json` in this directory.

## Normalization recipe

The key is a JA4-style ClientHello hash computed after a normalization pass (exposed as `tls.ja4_norm`). Two exclusions matter:

- **GREASE values inside `signature_algorithms`.** Chromium injects a random GREASE code point into the signature_algorithms list on each connection. Naive JA4 implementations filter GREASE from ciphers, extensions and versions but forget this list, so JA4_c changes from one connection to the next even though nothing about the build changed. I strip GREASE there too.
- **Resumption extensions `pre_shared_key` (0x0029) and `early_data` (0x002a).** These appear only when the client attempts session resumption, so they toggle between connections of the same build. They are excluded so a resumed and a fresh connection give the same key.

Each entry's `source` (cft or playwright) records only where the binary came from. Every build, including the playwright-sourced ones, was launched directly by my harness with the flags listed under Scope and caveats, so all keys are from the direct-launch profile.

The Phase 1 artifact (`runs/2026-10-25/phase1_capture.json`) predates the GREASE-in-signature_algorithms fix, so its browser JA4_c was computed by the old code. I have not re-run Phase 1.

## Stability finding

A key is only useful if one build always produces the same one. During de-risking, Chrome 156 produced about 25 distinct raw keys over 40 connections before the fix (a motivating measurement, not part of this artifact). For this artifact, each build was launched 10 times; the table compares distinct raw JA4 strings with the normalized key.

| Chromium | runnable | connections captured | distinct raw JA4 | normalized key stable |
|---|---|---|---|---|
| 120.0.6099.109 | no | 0 | 0 | no |
| 130.0.6723.116 | yes | 10 | 1 | yes |
| 140.0.7339.207 | yes | 10 | 1 | yes |
| 146.0.7680.165 | yes | 9 | 1 | yes |
| 150.0.7871.124 | yes | 10 | 1 | yes |
| 151.0.7922.34 | yes | 10 | 1 | yes |
| 156.0.8078.4 | yes | 10 | 1 | yes |

6 of 6 runnable builds gave a single normalized key across all captured connections.

## Resolution granularity

The map holds **4 keys over 6 runnable, stable builds**: 2 single-version keys and 2 range keys.

- `4980c97edce0` -> 151.0.7922.34, 156.0.8078.4 (range, Chromium 151-156)
- `cb7bf5808d99` -> 150.0.7871.124 (single version)
- `d8a2da3f94cd` -> 130.0.6723.116, 140.0.7339.207 (range, Chromium 130-140)
- `dcad5a053991` -> 146.0.7680.165 (single version)

A range key means those builds are indistinguishable by this key; the map can say 'one of these', not which.

## Scope and caveats

- Chrome/Chromium only, on mac/arm64, 6 runnable builds (130.0.6723.116, 140.0.7339.207, 146.0.7680.165, 150.0.7871.124, 151.0.7922.34, 156.0.8078.4).
- Not runnable on this machine, so excluded: 120.0.6099.109 (OS-incompatible on this macOS).
- The key is valid only for the recorded launch profile (direct launch with these flags): `--headless=new --disable-gpu --no-sandbox --no-first-run --no-default-browser-check --disable-background-networking --ignore-certificate-errors`. During de-risking I saw a different key for the same build under Playwright's automation flags (an observation outside this artifact, not computed from corpus.json).
- Multi-OS coverage is deferred; it needs my own Windows and Linux VMs.
- Enrichment from public fingerprint datasets is deferred pending a license check.

## Reproduce

```
python -m versionmap --out runs/2026-10-25-version-map --n 10
```

Generated at 2026-10-26T02:03:27.880416+00:00.

Author: Thiago Goncalves
