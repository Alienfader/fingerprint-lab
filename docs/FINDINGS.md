# Cross-layer fingerprint consistency: what survives measurement

*Thiago Goncalves — 2026-10-26*

This is the consolidated write-up of a five-phase investigation into whether a server
can tell a real browser from a well-formed forgery by checking that a client's layers —
TLS, HTTP/2, HTTP headers, and the JavaScript/GPU environment — agree *with each other*.
Every number below is produced by a committed artifact in this repo and is reproducible
with the command listed at the end of its section. Nothing here is hand-asserted.

**Scope and ethics, stated once, up front.** The whole lab is self-only. Every client —
real browser, impersonation library, or forger — is pointed at the researcher's own
capture server on `127.0.0.1` over loopback. There is no third-party probing and no
non-consented data collection, anywhere. The "forger" built in Phase 4 and the attacker
rungs in Phase 5 exist to measure the researcher's own detector; they are not
general-purpose or public-facing evasion tools. The measurements are desktop
Chrome/Chromium on macOS/arm64, with small sample sizes (a handful of clients, one run
each). They are illustrations of *which mechanism catches which forgery*, not detection
rates.

---

## The thesis I started with — and what measurement did to it

The opening bet (see `docs/superpowers/specs/2026-10-25-version-level-crosslayer-consistency-design.md`)
was that **version-resolving** cross-layer consistency would be the strong discriminator:
if I could map a TLS ClientHello to the Chrome *version* that produced it, I could catch
a forger whose UA claims Chrome 124 while its TLS fingerprint is really a Chrome 150
build. A throwaway spike on real capture data motivated it:

- a per-signal check ("is this JA4 a known real-browser shape?") caught **2 of 6** clients;
- a family-level cross-layer check (UA family vs TLS family, ALPN, HTTP/2 spoken) caught
  **4 of 6** — it additionally flagged two forgeries presenting a flawless *Safari* TLS
  fingerprint under a *Chrome* UA;
- the two best forgers (`curl_cffi` and `tls_client` Chrome profiles) passed **both**
  checks; their only remaining tell was at the version level.

So I built the version-resolution map. **Measurement then falsified the premise it rested
on.** That negative result is the first real finding, and the rest of the project is the
story of following the evidence instead of the plan.

---

## Phase 2 — The version map, and why JA4 is a defeated input

I built a map from a normalized JA4-style ClientHello key to the Chromium builds that
produce it (`runs/2026-10-25-version-map/`). Getting a *stable* key required fixing two
bugs that make naive JA4 vary between connections of the same build: GREASE values inside
`signature_algorithms` (which most JA4 code filters from ciphers/extensions but forgets
here), and the resumption extensions `pre_shared_key`/`early_data`. Before the fix, Chrome
156 produced ~25 distinct raw keys over 40 connections; after it, **6 of 6** runnable
builds gave a single normalized key across all captured connections.

But the map's resolving power was weak and, worse, fragile:

- It held only **4 keys over 6 runnable builds** — two single-version keys and two *range*
  keys (`130–140` and `151–156` each collapse to one key). A range key can say "one of
  these," never which.
- The clean separation was an artifact of fixing **one** launch profile. The normalized
  key is **launch-profile-dominated, not version-dominated**: the same build under a
  different launch profile produces a different key, and keys collide across versions.
- The decisive measurement: **`curl_cffi chrome124` and a real Chrome 130 driven through
  Playwright emit a byte-identical full JA4** — `t13i1515h2_8daaf6152771_02713d6af862`. A
  trivial impersonation library is indistinguishable from a real browser at the TLS layer,
  and can even collide with a genuine build under a mainstream automation profile.

**Conclusion: JA4 — full or normalized — is treated as a defeated input for this kind of
detection.** The map stays in the repo as the evidence that produced the negative result.
Reproduce: `python -m versionmap --out runs/2026-10-25-version-map`.

---

## Phase 3 — A JA4-free cross-layer consistency scorer

With the version idea dead, I built the consistency idea in the form that *does* survive:
an explainable scorer that looks for contradictions across layers and **never reads JA4 in
its verdict** (`runs/2026-10-26-crosslayer/`). It cross-checks what a client claims against
how it actually behaves: HTTP/2 Akamai fingerprint vs claimed UA family; Client-Hints /
`Sec-Fetch-*` completeness under a Chrome UA; whether a modern-browser UA can even speak
HTTP/2; and the JS/GPU environment.

Run against five clients, **5 of 5 scored `automated`**, each with the exact contradictions
that caught it:

| client | confidence | caught by |
|---|---|---|
| `curl:chrome124` | medium | `js_absent` **only** |
| `curl:safari17_0` | high | `akamai_family_vs_ua`, `missing_client_hints`, `js_absent` |
| `tls:chrome_124` | high | `missing_client_hints`, `missing_sec_fetch`, `js_absent` |
| `stdlib:urllib` | high | `no_http2`, `missing_client_hints`, `missing_sec_fetch`, `js_absent` |
| `browser:chromium` | medium | `headless_gpu`, `no_window_chrome`, `webdriver_true`, `perm_mismatch` |

Two things stand out. First, **the JS/GPU layer is the backbone**: the clients that fetch
the probe page but never execute its script have no JS layer at all, and the JA4- and
Akamai-perfect `curl:chrome124` is caught by **nothing but** the absence of JS. Second,
the only "real browser" available here is headless Playwright Chromium, which legitimately
reports `webdriver` and a SwiftShader GPU — so it scores `automated` too. That is the
expected outcome, not a false positive being excused, and it flags an honest gap: a
**headed-browser true-negative baseline is deferred**. Reproduce:
`python -m crosslayer --out runs/2026-10-26-crosslayer`.

---

## Phase 4 — The coherent forger defeats the passive scorer

Phase 3 catches `curl:chrome124` only by `js_absent`. That invites the obvious attack:
what if the forger also *fabricates* a JavaScript layer? The capture server joins the
JS payload to a request by a nonce in the URL — a join that is application-level, **not
bound to the TLS connection** — so a forger can `POST` a hand-made JSON payload to
`/collect/<nonce>` without running any browser at all.

I built that forger and measured it as an **evasion ladder**, each rung neutralizing
exactly one contradiction, scored by the **real** Phase 3 scorer (`runs/2026-10-26-forger/`):

| rung | what it fixes | scorer verdict | surviving contradiction |
|---|---|---|---|
| rung0 naive (no JS) | nothing | automated | `js_absent` |
| rung1 | adds JS, `webdriver=true` | automated | `webdriver_true` |
| rung2 | software GPU | automated | `headless_gpu` |
| rung3 | no `window.chrome` | automated | `no_window_chrome` |
| rung4 | UA mismatch | automated | `js_ua_mismatch` |
| **rung5 fully coherent** | all of them | **`real` (high confidence)** | **none** |

The naive rung is caught by `js_absent` *and nothing else* — empirical proof that
`curl_cffi chrome124` already satisfies the HTTP/2, Akamai, client-hints, and
`Sec-Fetch` checks on its own. Each middle rung trips exactly one named contradiction.
The top rung — `curl_cffi` plus a ~12-field fabricated JS payload reporting coherent
values — scores **`real`, high confidence, zero contradictions** against the full scorer.

**The passive scorer is defeated.** The reason is structural: every passive check reads a
value the client *reports about itself*, so a client that reports coherent values is, by
construction, indistinguishable from a real one. Passive cross-layer consistency is a
**finite, enumerable set of checks a forger can exhaust**. The attacker's measured cost to
get there: an impersonation library plus ~12 coherent JSON fields plus a two-request nonce
replay. Reproduce: `python -m forger --out runs/2026-10-26-forger`.

---

## Phase 5 — Active challenge-response catches exactly that forger

If a forger wins by *declaring* values, the defender has to stop asking and start making
it *compute*. Phase 5 adds an **active challenge** (`runs/2026-10-26-challenge/`): the
server issues a per-nonce seeded page; the client must render a seed-parameterised
canvas + WebGL scene, hash the pixels in-page (`crypto.subtle` SHA-256), and return the
digest. The answer is verified by exact match against a **trusted reference ("oracle")
browser** the defender controls. The digest is stable and seed-sensitive on this host
(deterministic software rendering under `--disable-gpu`), and — a finding in its own right
— it is **chromium-build-specific**, so the oracle and every client must use the same
build.

Measured as a three-rung ladder against the **real** verifier:

| client | TLS layer | runs a real engine? | challenge outcome |
|---|---|---|---|
| honest-browser | real Chromium | yes | **passes** |
| **coherent-forger** (the Phase 4 forger) | curl_cffi | no | **CAUGHT** |
| engine-forger | curl_cffi | yes (outsourced) | passes |

**The headline: the active challenge catches precisely the forger passive consistency
could not.** The coherent forger can fabricate self-reported values but cannot compute a
per-nonce seeded render without a real engine, so it returns no valid answer.

**The honest residual, stated plainly in the artifact:** the engine-forger *passes*. It
runs a real headless browser to compute the challenge and relays the answer over its
`curl_cffi` channel. So the active challenge does not make forgery impossible — it raises
the attacker's floor from "fabricate ~12 JSON fields" (Phase 4) to "run a real browser
engine." And the gap it leaves is exactly the one the whole project keeps circling: the
answer is joined by an application-level nonce, **not bound to the TLS connection that
served the probe**. Reproduce: `python -m challenge --out runs/2026-10-26-challenge`.

---

## The through-line

Across five phases the shape of the problem is an **asymmetry ladder**, and measurement
moved the honest version of the thesis from where it started:

- **Per-signal detection** is the weakest rung: one real-browser-shaped value defeats it.
- **Passive cross-layer consistency** is stronger but *finite and forgeable*: it is a
  closed set of self-reported checks, and a coherent forger exhausts them for the cost of
  an impersonation library plus a dozen fabricated fields. The original
  version-resolution bet died here, because its one load-bearing input — JA4 — does not
  survive launch-profile diversity.
- **Active challenge-response** changes the *kind* of thing being tested: not "do your
  declared values agree?" but "can you compute something only a real engine produces?" It
  catches the coherent forger and raises the attacker's floor to running a real browser.

What it does **not** do is close the door, and the project is honest about why. The
defender's cost per added cross-check stays roughly flat (one more check, one more
oracle), while the attacker's cost rises in discrete steps — fabricate values → run an
engine → and, past where this work stops, **bind the proof to the connection**. The
unaddressed frontier is channel binding: tying the challenge answer (and the JS layer
generally) to the same TLS connection that was fingerprinted, so a forger cannot have a
real browser answer on its behalf and relay the result. That is the natural next arm.

---

## Honest limits

- **Self-only, small n, one host.** Desktop Chrome/Chromium on macOS/arm64; a few clients,
  one run each. These are mechanism demonstrations, not rates.
- **No true-negative baseline.** The only "real browser" in the lab is headless Chromium,
  which passive checks correctly flag as automated; a headed-browser baseline for measuring
  false positives is deferred.
- **JA4 scope.** The "JA4 is defeated" result is for this normalization and these builds
  on this host; it is a strong negative result, not a proof that no TLS feature can resolve
  a version.
- **Challenge portability.** Exact-match verification works because the oracle and clients
  share a host and a Chromium build (software rendering is deterministic). Cross-GPU /
  cross-build variance is real and is named as a caveat, not engineered around — a
  production detector would need fuzzy or model-based matching.

## Artifacts

| phase | directory | reproduce |
|---|---|---|
| 2 — version map | `runs/2026-10-25-version-map/` | `python -m versionmap --out runs/2026-10-25-version-map` |
| 3 — cross-layer scorer | `runs/2026-10-26-crosslayer/` | `python -m crosslayer --out runs/2026-10-26-crosslayer` |
| 4 — coherent forger | `runs/2026-10-26-forger/` | `python -m forger --out runs/2026-10-26-forger` |
| 5 — active challenge | `runs/2026-10-26-challenge/` | `python -m challenge --out runs/2026-10-26-challenge` |

Design and the full decision trail: `docs/superpowers/specs/2026-10-25-version-level-crosslayer-consistency-design.md`.
