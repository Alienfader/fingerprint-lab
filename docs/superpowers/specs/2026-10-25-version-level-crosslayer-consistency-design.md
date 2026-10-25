# Version-level cross-layer fingerprint consistency — research design

*Thiago Goncalves — 2026-10-25*

## Intent and why

Per-signal bot detection — "block this JA4", "flag `navigator.webdriver`" — is
well-trodden and weak. The under-explored, stronger discriminator is cross-layer
**consistency**: whether the TLS stack (JA4), HTTP/2 behavior, HTTP headers and
client hints, and the JS/GPU environment all agree *with each other* and with the
browser version the client claims to be.

A throwaway spike on this repo's real run data (`runs/2026-10-24/ja3_diff.json`)
established the premise on actual bytes:

- A per-signal check ("is this JA4 a known real-browser shape?") caught 2 of 6
  clients.
- A coarse **family-level** cross-layer check (UA family vs TLS family, ALPN, and
  whether HTTP/2 was spoken) caught 4 of 6 — it additionally flagged two forgeries
  that present a flawless **Safari** TLS fingerprint while their UA claims Chrome.
- The two best forgeries (`curl_cffi` and `tls_client` Chrome profiles) passed
  *both* checks. Their only remaining contradiction is at the **version** level:
  the UA claims **Chrome 124** while the JA4 extension hash is from a **Chrome 150**
  build. The spike could not catch this because it had no map from JA4 extension
  hash to browser version.

No clean, public map from JA4 (specifically its extension-hash segment) to browser
version exists. That gap is the research opportunity.

**Research thesis (the sentence this work aims to earn):** *A version-resolving
cross-layer consistency check detects well-formed browser forgeries that both
per-signal detection and current public impersonation tools leave internally
inconsistent — and the attacker's cost to defeat it grows with the number of
layers, while the detector's cost per added cross-check stays flat.*

Research is the primary goal; the artifact doubles as credible evidence for a bot-
detection research role (secondary).

## Goals

1. **Build a version-resolution reference**: a map from JA4 extension hash (the
   third JA4 segment, which carries version-specific information) to
   browser family + version, from a corpus of real captures.
2. **Build an explainable cross-layer consistency scorer** that cross-checks the
   version a client *claims* (UA, `Sec-CH-UA`, `navigator.userAgentData`) against
   the version *implied* by its TLS extension hash, ALPN/HTTP-2 behavior, and
   JS/GPU environment, and reports every contradiction it finds.
3. **Evaluate and quantify the asymmetry**: measure how many forgeries are caught
   by per-signal vs family-level vs version-level checks, across `curl_cffi` /
   `tls_client` profiles and patched-headless browsers. Show that the detector's
   per-check cost is flat while the forger's consistency burden grows per layer.
4. **Write it up honestly**, with every number backed by a committed run artifact,
   matching the existing `docs/ANTIBOT_RESEARCH.md` + `runs/<date>/` pattern.

## Non-goals

- Testing against any production bot-management vendor or any third-party website.
- Building a production detector, or a general-purpose evasion product.
- Any claim of the form "we beat vendor X."
- An ML model in v1 (the scorer is rules-based and explainable).

## Anti-goals (these make it a failure even if it technically works)

- Collecting personally identifiable information or any non-consented user traffic.
- Overclaiming generality from a small corpus — findings must be scoped to the
  corpus and configuration they came from.
- Any number in the write-up that does not reproduce from a committed artifact.

## Constraints

- **Ethics / scope of data (fixed boundary):** self-inspection and in-scope data
  only. The version-resolution corpus comes from (a) the researcher's own
  version-pinned Chromium downloads, (b) the researcher's own everyday headed
  Chrome, (c) for multi-OS coverage, the researcher's own Windows/Linux VMs or
  cloud instances, and (d) reputable public JA4 datasets under a compatible
  license, cited. **No third-party live probing and no volunteer or non-consented
  data collection, ever.** The self-hosted capture server (below) is a self-only
  harness the researcher points their own clients at — never a public endpoint
  that records other people's fingerprints.
- **Build on the existing lab:** Python, the repo's `.venv`, `curl_cffi`,
  `tls_client`, Playwright; reuse `ja3_diff.py` plumbing. Stdlib-first where it's
  reasonable.
- **Reproducibility:** every reported number is backed by a committed
  `runs/<date>/` artifact, as the repo already does.
- **Attribution:** the researcher's name only, per repo and user convention.
- **Decision logging:** deliberate changes logged to Continuity, per the repo's
  operating contract.

## Architecture at a glance

```text
CLIENTS  (self-only — nothing third-party, no volunteer traffic)
  real browsers         curl_cffi /        patched          coherent
  multi-OS, pinned      tls_client         headless         forger
  + headed Chrome       profiles           Chromium         (Phase 4) ─┐
       │                    │                  │                 │      │
       └────────────┬───────┴───────┬──────────┴────────┬───────┘      │
                    ▼               ▼                   ▼               │
  ┌──────────────────────────────────────────────────────────────┐    │
  │ PHASE 1   self-hosted capture server  (local, never public)   │    │
  │   joins, per connection:  TLS/JA4 · HTTP/2 · header order ·   │    │
  │   client hints · JS/GPU probe (browser clients only)          │    │
  └──────────────────────────────────────────────────────────────┘    │
                    │  one joined record per client                    │
                    ▼                                                   │
  ┌──────────────────────────────────────────────────────────────┐    │
  │ PHASE 2   corpus + version map                                │    │
  │   JA4 ext-hash  ──▶  (family, version-or-range, OS)           │    │
  │   from pinned Chromium + headed Chrome + own VMs + public DB  │    │
  └──────────────────────────────────────────────────────────────┘    │
                    │  implied version / OS                            │
                    ▼                                                   │
  ┌──────────────────────────────────────────────────────────────┐    │
  │ PHASE 3   cross-layer consistency scorer                      │    │
  │   claimed version (UA / Sec-CH-UA / UAData)  vs  implied      │    │
  │   + ALPN·HTTP/2 + JS/GPU   ──▶  contradictions + confidence   │    │
  └──────────────────────────────────────────────────────────────┘    │
                    │                                                   │
                    ▼                                                   │
     VERDICT per client:   per-signal  │  family  │  version           │
                           (version-level catches what others miss)    │
                    │                                                   │
                    ▼                                                   │
  ┌──────────────────────────────────────────────────────────────┐    │
  │ PHASE 5   evaluation + write-up                               │◀───┘
  │   detection rate by layer · measured per-layer asymmetry      │
  │   (defender checks ~O(1)  vs  attacker fixes per added layer) │
  └──────────────────────────────────────────────────────────────┘
       Phase 4's forger re-enters as a client (top right) so the
       attacker side of the asymmetry is measured, not just argued.
```

## The "how" that is already decided — full build, phased

Chosen scope: the **full build**. It is large and multi-week, so it is sequenced
into phases that each produce something usable and testable on their own. A later
phase should not start until the one before it is working.

- **Stack:** Python, extending `fingerprint-lab`; reuse the request/echo plumbing
  in `ja3_diff.py` where it fits.
- **Key signal:** the version map keys on the **JA4 extension-hash segment**, not
  just the JA4_a prefix (the prefix is stable across versions; the extension hash
  is where version information lives).
- **Scorer design:** rules-based, confidence-tagged, and explainable — each verdict
  prints the specific contradictions behind it (as the spike already does). Not ML.

**Phase 1 — Self-hosted joined-capture server.** A local server the researcher
points their *own* clients at (never public). It logs, per connection and joined
into one record: JA4 + HTTP/2 fingerprint + header order + client hints, and serves
a deep JS/GPU probe page for browser clients. This solves the layer-joining problem
(today TLS and JS are captured in two disconnected places). Non-browser clients
(`curl_cffi`, `tls_client`, stdlib) produce a record with no JS layer — the schema
and the scorer treat the JS layer as present-or-absent per population.

**Phase 2 — Multi-OS, multi-version corpus + the version map.** Capture real
browsers against the Phase-1 server across: version-pinned Chromium downloads, the
researcher's everyday headed Chrome, and the researcher's own Windows/Linux VMs or
cloud instances for OS spread; enrich with a license-checked public JA4 dataset.
Build the JA4-extension-hash → (family, version-or-range, OS) map from it, recording
how fine-grained the resolution actually is.

**Phase 3 — Cross-layer consistency scorer.** Cross-check claimed version (UA /
`Sec-CH-UA` / `userAgentData`) against implied version (JA4 ext hash via the map),
ALPN/HTTP-2, and JS/GPU environment. Report per-signal vs family-level vs
version-level verdicts, each with its contradiction list and a confidence tag, and
scope every verdict to the OS/version coverage the map actually has.

**Phase 4 — Coherent-forger arm.** An evasion client that deliberately tries to make
its layers mutually consistent (version-aligned UA/client-hints/JA4). Used to
*measure* the attacker side of the asymmetry: how many distinct layers it must fix,
and which the detector still catches. This is what turns the asymmetry from an
argument into a measurement.

**Phase 5 — Evaluation + write-up.** Run the scorer over the populations — real
browsers, a sweep of `curl_cffi`/`tls_client` profiles, patched-headless configs,
and the Phase-4 forger — and report detection rates by layer plus the measured
per-layer cost asymmetry (defender-side check count vs attacker-side fixes needed).
Write-up under `docs/` with a dated `runs/` artifact, mirroring
`ANTIBOT_RESEARCH.md`; every number reproducible from the artifact.

## What is left to the builder

- Exact corpus breadth: how many Chromium versions and which OS builds make a
  defensible map (builder picks a starting spread; more can be added).
- Whether to resolve Safari/Firefox versions in this project or stay Chrome/Chromium
  first (proposed: Chrome/Chromium first, add others if time allows).
- Precise scoring form: binary contradiction list vs weighted/continuous score
  (proposed: start explainable/binary, add weighting only if the evaluation needs it).
- Server implementation details (framework, how the TLS/HTTP-2 layer is observed —
  e.g. a TLS-terminating listener vs a sidecar packet view) and how it is run
  locally only.
- How to obtain and license-verify the public dataset.

## Decisions (resolved with the author, 2026-10-25)

1. **Scope:** full build — self-hosted joined-capture server + coherent-forger arm +
   multi-OS corpus (phased as above).
2. **Data boundary:** pinned Chromium + public JA4 dataset + the author's own headed
   Chrome, plus the author's own VMs/cloud for OS spread. No third-party probing and
   no volunteer/non-consented data, ever; the server is self-only.

## Settled by the author after builder review (my calls, flagged for a check)

- **Layer joining** is done by the Phase-1 server; "cross-layer" is population-
  dependent (browser clients carry a JS layer, non-browser clients do not).
- **Version-resolution granularity:** range-level resolution is acceptable, and the
  actual granularity (how often the ext hash changes across versions) is itself a
  reported finding. Detecting a *mismatch* is the bar, not exact-version naming.
- **The asymmetry is measured both ways:** defender-side (contradictions per
  population, check count) and, via Phase 4, attacker-side (layers the forger must
  fix). The thesis word "quantify" is honored by Phase 4.
- **Forgery eval breadth:** a sweep of all available `curl_cffi`/`tls_client`
  profiles plus several patched-headless configs and the Phase-4 forger — not the
  spike's n=2.
- **OS scope:** multi-OS via the author's own VMs/cloud; every map entry and verdict
  is tagged with the OS it was built from, so a macOS-only entry never silently
  judges a Windows client.
