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

---

## Phase 3 revision — 2026-10-26 (supersedes the JA4-version-resolution approach)

**Finding (verified by spike, logged to Continuity):** JA4 — full *and* normalized
ext-hash — is **not** a usable version or forgery discriminator once real-world
launch-profile diversity is admitted. On this machine:

- The normalized ext-hash is **launch-profile-dominated, not version-dominated**:
  across direct-launch vs Playwright-headless, keys collide across versions
  (`{130,140,146}`, `{150,156}`, `{150,151}`, `{151,156}` all share keys).
- **curl_cffi `chrome124` and real Chrome 130 (Playwright) emit a byte-identical
  full JA4** (`t13i1515h2_8daaf6152771_02713d6af862`, stable). A trivial
  impersonation library is indistinguishable from a real browser by JA4, and even
  collides with a real build under a mainstream automation profile.

The Phase 2 map's clean separation was an artifact of fixing **one** launch
profile. **JA4 is therefore treated as a defeated input** for detection; the Phase 2
map stays in the repo as the evidence that produced this negative result.

**Revised Phase 3:** an explainable, multi-tier **cross-layer consistency scorer**
that does *not* rely on JA4 for its verdict. Grounded in a captured snapshot of the
forgery population vs a real browser, the surviving discriminators are:

- **HTTP/2 Akamai family** vs claimed UA family (a Safari-shaped Akamai under a
  Chrome UA is a contradiction — catches `curl_cffi safari17_0`).
- **Client-hints / Sec-Fetch completeness** under a Chrome UA (a "Chrome" that
  sends no `Sec-CH-UA`/`Sec-Fetch-*` is a contradiction — catches `tls_client`).
- **ALPN / HTTP-2 spoken** (a modern-browser UA that cannot speak h2 — catches
  `stdlib`).
- **The JS/GPU layer is the backbone** — presence and coherence. Its *absence*
  under a browser-shaped request catches the JA4- and Akamai-perfect `curl_cffi
  chrome124` that every network-layer check misses; its *contents* (`webdriver`,
  software GPU via `webglRenderer`, `window.chrome`, `navigator.userAgentData` vs
  `Sec-CH-UA`, JS `userAgent` vs HTTP `User-Agent`) expose headless/patched
  browsers and seed the Phase 4 coherent-forger evaluation.

The verdict is per-client, explainable (lists the exact contradictions), confidence-
tagged, and scoped to what was observable. A true-real headed-browser baseline (for
false-positive measurement) and the coherent forger remain later-phase work.

---

## Phase 5 — Active challenge-response arm (2026-10-26)

**Why now.** Phase 4 proved the passive cross-layer scorer is defeatable: the
coherent forger (`curl_cffi chrome124` + a fabricated `/collect` JSON payload joined
by the application-level nonce) scores `real`, zero contradictions, because *every*
passive check reads values the client reports about itself. A client that reports
coherent values is indistinguishable from a real one by inspection. Phase 5 adds the
defender move the asymmetry demands: an **active challenge** the client must *compute
live*, where the answer is produced by a real engine rather than declared — so a
forger that only fabricates static values cannot answer.

**The mechanism (de-risked by spike, 2026-10-26).** The defender issues a per-nonce
**challenge**: a same-origin page (served by the Phase-1 `CaptureServer`) carrying a
random `seed`. The client's browser renders a seed-parameterised 2D-canvas + WebGL
scene, hashes the pixels in-page (`crypto.subtle` SHA-256), and POSTs the hex digest
back, joined by nonce exactly like the passive probe. Verified facts on this host
(self-only, `--disable-gpu` → deterministic SwiftShader software rendering):

- **Stable:** the same seed yields a byte-identical digest across independent browser
  launches.
- **Seed-sensitive:** a different seed yields a different digest (so a captured answer
  cannot be replayed for a fresh challenge).
- **Engine-bound:** a real headless chromium computes it; `curl_cffi` (no JS engine)
  returns nothing.

**Verification = trusted reference execution.** The server cannot render canvas in
Python, so it establishes ground truth with a **reference/oracle browser** it
controls: `expected = oracle(seed)`. A client passes iff its answer equals the
oracle's for that seed. In this self-only lab the oracle and the honest client are
the same chromium build on the same host, so deterministic software rendering makes
exact-match sound. (Cross-GPU/driver variance is why production detectors use
fuzzy/ML matching; that variance is out of scope here and is stated as a caveat, not
engineered around.)

**Implementation note from the spike:** the challenge page MUST be served
same-origin over the loopback server — a `data:` URL's opaque origin blocks the
answer `fetch`. Reuse the existing `LAUNCH_FLAGS` (incl. `--password-store=basic
--use-mock-keychain`) + direct `subprocess` launch + `killpg(SIGKILL)` on the
Chrome-for-Testing binary, exactly as `versionmap/corpus.py` already does safely.
(The macOS keychain-wedge lesson applies only to the real Google Chrome app, not
these CfT builds.)

### Goals

- A `challenge/` arm: issue a seeded challenge, drive a real browser to answer it,
  verify the answer against the oracle, and report pass/fail — integrated with the
  existing server's nonce join.
- A **defender ladder** (mirroring Phase 4's evasion ladder) that runs, against the
  active challenge, the clients that matter and reports each one's outcome:
  1. **honest headless browser** — answers correctly → **passes** the challenge
     (baseline that the mechanism admits a real engine).
  2. **Phase-4 coherent forger** (`curl_cffi` + fabricated `/collect`) — the exact
     client that beat the passive scorer → **cannot answer** → **caught.** *This is
     the headline: the active challenge catches precisely the forger passive
     consistency could not.*
  3. **engine forger** — `curl_cffi` for the TLS/HTTP layer, but actually runs a
     headless browser to compute the challenge answer and relays it → **passes.**
     *This is the honest residual: the active challenge does not make forgery
     impossible; it raises the forger's floor from "POST 12 JSON fields" to "run a
     real browser engine," and the remaining gap is that the answer is still joined
     by application-level nonce, not bound to the probe's TLS connection.*
- A committed `runs/2026-10-26-challenge/` artifact + honest write-up: the ladder
  table (client → challenge outcome), the measured asymmetry shift, and the named
  residual (connection/channel binding) as the motivation for any further arm.

### Non-goals / anti-goals

- **Not** a production bot detector, and **not** reusable evasion tooling. Self-only,
  loopback, measuring the researcher's own detector. No third-party target, ever.
- **Not** a claim that the challenge is unbeatable — the engine-forger rung exists
  specifically to show it is not, and to measure the cost it imposes.
- **Not** solving cross-GPU hash portability or channel binding; both are named as
  caveats/future work, not built.
- **Do not** modify the Phase 3 scorer or the Phase 4 forger package to make a rung
  pass or fail — they are measured as shipped. The challenge arm is additive.

### Constraints

- Self-only / loopback (127.0.0.1); reuse `capture/`, `versionmap` launch machinery,
  and the Phase-4 `forger` driver. Stdlib-first; `curl_cffi` for the forger legs.
- Tests pass under `pytest -W error`; integration tests (real browser / curl_cffi +
  live server) carry the `integration` marker.
- Measured, not asserted: every ladder outcome is a real verify() result on a
  captured answer; every number in the write-up traces to the committed artifact.
- Attribution: Thiago Goncalves only — no AI/Claude/Anthropic attribution anywhere.

### Decided (my calls)

- **Challenge = seeded 2D-canvas + WebGL pixel-hash** (not a pure-arithmetic
  challenge, which a forger could reproduce in Python; not a layout-geometry
  challenge, heavier to author). Pixel rendering requires a real engine and the
  spike shows it is deterministic here.
- **Verification by oracle reference run**, exact match, same host/build.
- **Three-rung ladder** (honest / coherent-forger / engine-forger) as above.
- **Server integration:** add challenge/answer routes to the existing `CaptureServer`
  rather than standing up a second server, so the nonce join and TLS capture are
  reused. The route additions are additive and must not disturb `/probe`//`/collect`.

### Left to the builder (writing-plans)

- Exact module/function boundaries within `challenge/` (issuer, oracle, verifier,
  driver, ladder, CLI), the server-route wiring, the seed format/entropy, and the
  precise test cases — to be fixed in the plan, consistent with the Phase 3/4 package
  shapes.
