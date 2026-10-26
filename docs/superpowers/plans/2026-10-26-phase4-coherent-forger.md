# Phase 4 — Coherent forger + asymmetry measurement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A self-only "coherent forger" measurement harness that drives curl_cffi + a fabricated `/collect` JS payload against the researcher's own loopback capture server, and an **evasion ladder** that quantifies the attacker-side asymmetry — how many distinct layers/signals the forger must align, rung by rung, to move the Phase 3 scorer's verdict from `automated` to `real`.

**Architecture:** A `forger/` package: a pure coherent-JS payload builder with per-signal toggles, plus a driver that (over curl_cffi `chrome124`) fetches `/probe/<nonce>` and POSTs a fabricated JS payload to `/collect/<nonce>`, returning the joined `Record`. A CLI runs an ordered ladder of forger configurations — each rung neutralizing exactly one Phase 3 contradiction — scores each with the **real** `crosslayer.scorer`, and writes a committed `runs/2026-10-26-forger/` artifact + an honest write-up of the measured asymmetry.

**Tech Stack:** Python 3.15, repo `.venv`, `curl_cffi` (impersonate `chrome124`), the Phase 1 `capture/` package (`CaptureServer`, `Record`), the Phase 3 `crosslayer.scorer`. Stdlib-first. Tests under `pytest -W error`.

**Spec:** `docs/superpowers/specs/2026-10-25-version-level-crosslayer-consistency-design.md` — Phase 4 ("Coherent-forger arm… measure the attacker side of the asymmetry") + the "Phase 3 revision — 2026-10-26" addendum (the scorer this forger is measured against). Read both.

**De-risk evidence (verified, logged to Continuity):** A coherent forger = curl_cffi `chrome124` (byte-perfect JA4/Akamai/headers) + a hand-fabricated 12-field JS payload POSTed to `/collect/<nonce>` (the nonce join is application-level, NOT bound to the TLS connection) scores **`real`, high confidence, zero contradictions** against the committed Phase 3 scorer. Every Phase 3 check inspects client-self-reported values, so a forger reporting coherent values is indistinguishable by passive inspection. This plan turns that spike into a committed tool + a rung-by-rung measurement.

## Global Constraints

- **Self-only / loopback.** The forger targets ONLY a caller-provided local `CaptureServer` (127.0.0.1). It is a measurement harness for the researcher's own detector — not a public-facing or reusable evasion product (an explicit spec non-goal). No third-party endpoint capability; no network target argument beyond the local server's port.
- **Measured, not asserted.** Every ladder verdict is the REAL output of `crosslayer.scorer.score` on a captured `Record` — never a hardcoded expectation in the artifact.
- **Reproducibility:** every number in the write-up comes from the committed `runs/2026-10-26-forger/` artifact.
- **Attribution:** Thiago Goncalves only — no AI/Claude/Anthropic attribution in commits, code, docs, or README; no footers.
- **Tests:** pass under `pytest -W error`; pristine. Integration tests (curl_cffi + live server) use the `integration` marker.
- **Build on the lab:** reuse `capture/` and `crosslayer/`; do not reimplement the server or the scorer. Do not modify the Phase 3 scorer — the forger is measured against it as-is.

## Review Focus

- **The nonce replay join must actually work** (forger's fabricated JS joins to its own `/probe` record): a forger run that silently fails to join would make the whole measurement vacuous. → Task 1 integration test asserts the returned Record has `js` set.
- **The top (fully-coherent) rung must genuinely score `real`** from the real scorer — if it doesn't, the ladder's headline ("passive scorer defeated") is false. → Task 2 test.
- **Each rung must neutralize exactly the intended contradiction** — a rung that accidentally fixes two at once would misreport the asymmetry cost. → Task 2 tests assert the specific surviving contradiction code per rung.
- **A curl_cffi profile or server that fails to respond** must raise a clear error, not silently produce an empty/mis-joined Record. → Task 1.
- **Self-only boundary:** the forger must have no way to target a non-loopback host. → Task 1 (API takes a server/port, not an arbitrary URL host).

---

### Task 1: Coherent forger (payload builder + driver)

**Files:**
- Create: `forger/__init__.py`, `forger/coherent.py`
- Test: `tests/forger/test_coherent.py`

**Interfaces:**
- Consumes: `capture.server.CaptureServer` (for its `.port`/`.records`), `capture.record.Record`.
- Produces:
  - `build_payload(**toggles) -> dict` — a pure builder of the fabricated JS `/collect` payload. Toggles select how coherent it is, each defaulting to the fully-coherent value: `include_js: bool = True`, `webdriver: bool = False`, `gpu: str = "real"|"swiftshader"` (default "real"), `window_chrome: bool = True`, `ua_match: bool = True`. The returned dict uses the SAME keys the real probe emits (`webdriver`, `userAgent`, `pluginsLen`, `pluginNames`, `languages`, `hasWindowChrome`, `hardwareConc`, `platform`, `webglVendor`, `webglRenderer`, `permMismatch`, `canvas`). A non-coherent toggle injects the corresponding tell (e.g. `webdriver=True`, a SwiftShader `webglRenderer`, `hasWindowChrome=False`, or a mismatched `userAgent`).
  - `forge(server, *, payload: dict | None, profile: str = "chrome124", ua: str = CHROME_UA) -> Record` — over curl_cffi `impersonate=profile`: GET `https://127.0.0.1:<server.port>/probe/<nonce>` (fresh nonce), then, if `payload is not None`, POST it as JSON to `/collect/<nonce>`; wait for and return the joined `/probe/<nonce>` Record from `server.records`. `payload=None` models the naive no-JS forger. Raises `RuntimeError` if no joined record appears within a timeout.

- [ ] **Step 1: Write the failing tests**

```python
def test_build_payload_coherent_has_probe_keys_and_no_tells():
    p = build_payload()
    assert set(p) >= {"webdriver","userAgent","hasWindowChrome","webglRenderer","platform"}
    assert p["webdriver"] is False and p["hasWindowChrome"] is True
    assert "swiftshader" not in p["webglRenderer"].lower()

def test_build_payload_toggles_inject_each_tell():
    assert build_payload(webdriver=True)["webdriver"] is True
    assert "swiftshader" in build_payload(gpu="swiftshader")["webglRenderer"].lower()
    assert build_payload(window_chrome=False)["hasWindowChrome"] is False
    assert build_payload(ua_match=False)["userAgent"] != CHROME_UA

@pytest.mark.integration
def test_forge_joins_fabricated_js(server):
    rec = forge(server, payload=build_payload())
    assert rec.js is not None and rec.js["webdriver"] is False
    assert (rec.http or {})["path"].startswith("/probe/")
    assert rec.tls and rec.tls.get("ja4")  # real curl_cffi TLS was captured

@pytest.mark.integration
def test_forge_naive_has_no_js(server):
    rec = forge(server, payload=None)
    assert rec.js is None
```

- [ ] **Step 2: Run tests, verify they fail** — `.venv/bin/python -m pytest tests/forger/test_coherent.py -v`
- [ ] **Step 3: Implement `forger/coherent.py`.** `forge` mirrors the two-request pattern from the Phase 4 spike (curl_cffi GET `/probe/<nonce>` then POST `/collect/<nonce>` with `impersonate=profile, verify=False`), selecting the joined record by `http["path"] == "/probe/<nonce>"`. Reuse `CHROME_UA` from `ja3_diff`. The `server` fixture (TLS CaptureServer from an openssl temp cert) goes in `tests/forger/conftest.py`, mirroring `tests/crosslayer`/`tests/capture` conftest patterns. No `tests/forger/__init__.py`.
- [ ] **Step 4: Run tests to verify pass.**
- [ ] **Step 5: Commit** — `git commit -m "forger: coherent JS payload builder + nonce-replay driver"`

---

### Task 2: Evasion ladder, CLI, artifact, and write-up

**Files:**
- Create: `forger/ladder.py`, `forger/cli.py`, `forger/__main__.py`
- Create: `runs/2026-10-26-forger/ladder.json`, `runs/2026-10-26-forger/README.md`
- Test: `tests/forger/test_ladder.py`, `tests/forger/test_forger_cli.py`

**Interfaces:**
- Consumes: `forger.coherent` (Task 1), `crosslayer.scorer.score` (Phase 3), `capture.server.CaptureServer`.
- Produces:
  - `LADDER: list[Rung]` where `Rung = {name, toggles, defeats}` — an ordered ladder, each rung neutralizing exactly one Phase 3 contradiction relative to the prior: `rung0 naive` (payload=None → defeats nothing; caught by `js_absent`), `rung1 js+webdriver` (`webdriver=True` → still caught by `webdriver_true`), `rung2 no-webdriver+swiftshader` (`gpu="swiftshader"` → `headless_gpu`), `rung3 real-gpu+no-window-chrome` (`window_chrome=False` → `no_window_chrome`), `rung4 window-chrome+ua-mismatch` (`ua_match=False` → `js_ua_mismatch`), `rung5 fully-coherent` (all defaults → expected `real`). `defeats` names the contradiction code the rung is expected to still trip (None for rung5).
  - `run_ladder(server) -> list[dict]` — for each rung, `forge` + `score`, returning per-rung `{name, label, confidence, surviving_contradictions}`.
  - CLI `main(argv=None) -> int` (+ `forger/__main__.py` so `python -m forger` works), default `--out runs/2026-10-26-forger`, that starts a CaptureServer, runs the ladder, writes `ladder.json` + `README.md`.

- [ ] **Step 1: Write the failing tests**

```python
@pytest.mark.integration
def test_ladder_climbs_from_automated_to_real(server):
    rows = run_ladder(server)
    assert rows[0]["label"] == "automated"          # naive, js_absent
    assert rows[-1]["label"] == "real"              # fully coherent defeats the scorer
    # every rung below the top is caught, and by its named contradiction
    for row, rung in zip(rows[:-1], LADDER[:-1]):
        assert row["label"] == "automated"
        assert rung["defeats"] in {c["code"] for c in row["surviving_contradictions"]}

@pytest.mark.integration
def test_cli_writes_artifact(tmp_path):
    assert main(["--out", str(tmp_path)]) == 0
    doc = json.loads((tmp_path / "ladder.json").read_text())
    assert doc["rungs"][-1]["label"] == "real"
    readme = (tmp_path / "README.md").read_text()
    for h in ("## The attack", "## Evasion ladder", "## What this measures", "## Scope and ethics", "## Reproduce"):
        assert h in readme
    for banned in ("Claude", "Anthropic", "AI-generated"):
        assert banned not in readme
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement `forger/ladder.py` + `forger/cli.py` + `forger/__main__.py`,** then author `runs/2026-10-26-forger/README.md` from the generated `ladder.json`. README headings exactly: `## The attack`, `## Evasion ladder`, `## What this measures`, `## Scope and ethics`, `## Reproduce`. In the researcher's voice: describe the forger (curl_cffi + fabricated `/collect` via the application-level nonce join); the ladder table (rung → scorer label/confidence → surviving contradiction); the asymmetry finding (the scorer catches the forger until every self-reported JS tell is neutralized, then the fully-coherent rung scores `real` — i.e. passive cross-layer consistency is a finite, enumerable set of checks a forger can exhaust); **Scope and ethics** (self-only, loopback, measures the researcher's own detector, not a reusable evasion product; this motivates active challenge-response as the next defender move); exact reproduce command. Numbers from the artifact.
- [ ] **Step 4: Run the CLI for real**, then the full suite: `.venv/bin/python -m forger --out runs/2026-10-26-forger && .venv/bin/python -m pytest -q`.
- [ ] **Step 5: Commit** — `git add forger tests/forger runs/2026-10-26-forger && git commit -m "forger: evasion ladder, CLI, artifact, and asymmetry write-up"`

---

## Notes for the executor

- Do NOT modify `crosslayer/` — the forger is measured against the Phase 3 scorer exactly as shipped. If a rung's verdict surprises you, report it; the measurement is the deliverable, not a green light to tune the scorer.
- The ladder's value is honesty: if the real scorer catches a rung by a DIFFERENT contradiction than `defeats` names, fix the rung definition (its toggles) so it isolates one signal — do not loosen the test.
- curl_cffi is not a browser, so there is no keychain/GUI concern here (that only affected real-browser launches).
