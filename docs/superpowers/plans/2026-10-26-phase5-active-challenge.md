# Phase 5 — Active challenge-response arm Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A self-only active **challenge-response** arm that issues a per-nonce seeded canvas/WebGL challenge the client must *compute live*, verifies the answer against a trusted reference (oracle) browser, and runs a 3-rung **defender ladder** proving the Phase 4 coherent forger — which defeated the passive scorer — is **caught** by the active challenge, while naming the honest residual (an "engine forger" that runs a real browser still passes, because the answer is joined by application-level nonce, not bound to the TLS channel).

**Architecture:** A `challenge/` package: a pure issuer (`Challenge` + seeded same-origin page), additive `/challenge/<nonce>` + `/answer/<nonce>` routes on the existing `CaptureServer` (nonce join, reusing TLS capture), a browser-answer helper reused by the oracle and the honest/engine clients, an exact-match verifier, and a CLI that runs the ladder and writes a committed `runs/2026-10-26-challenge/` artifact + honest write-up. Real browsers are driven by direct `subprocess` launch of the lab's Chrome-for-Testing binaries with the existing keychain-safe `LAUNCH_FLAGS` (reusing `versionmap/corpus.py`'s proven pattern); the forger legs reuse the Phase 4 `forger` driver (curl_cffi).

**Tech Stack:** Python 3.15, repo `.venv`, stdlib `http.server` (via `capture.server.CaptureServer`), the lab's Chrome-for-Testing builds (`versionmap.chromium_builds` + `LAUNCH_FLAGS`), `curl_cffi` (Phase 4 `forger`), `crypto.subtle` SHA-256 in-page. Tests under `pytest -W error`; real-browser / curl_cffi legs carry the `integration` marker.

**Spec:** `docs/superpowers/specs/2026-10-25-version-level-crosslayer-consistency-design.md` — the "Phase 5 — Active challenge-response arm (2026-10-26)" addendum (intent, the de-risked mechanism, goals/non-goals, decided calls). Read it.

**De-risk evidence (spike, 2026-10-26, logged to Continuity):** On this host, with `--disable-gpu` (deterministic SwiftShader software rendering), a seeded 2D-canvas + WebGL pixel-hash is **stable** (same seed → byte-identical SHA-256 across independent browser launches), **seed-sensitive** (different seed → different digest), and **engine-bound** (a real headless chromium computes it; `curl_cffi` returns nothing). The challenge page MUST be served **same-origin** over loopback — a `data:` URL's opaque origin blocks the answer `fetch`.

## Global Constraints

- **Self-only / loopback.** Every leg targets ONLY the caller-provided local `CaptureServer` on `127.0.0.1`. No third-party endpoint capability; no host argument anywhere.
- **Measured, not asserted.** Every ladder outcome is a real `verify()` result on a captured answer; the engine forger's answer is genuinely computed by a launched browser, never copied from `expected`. Every number in the write-up traces to the committed `runs/2026-10-26-challenge/` artifact.
- **Additive only.** `/challenge` and `/answer` are added to `CaptureServer` without disturbing `/probe` or `/collect`; do NOT modify the Phase 3 scorer (`crosslayer/`) or the Phase 4 `forger` package to make a rung pass or fail — they are consumed as shipped. Do NOT modify `capture/record.py` or `capture/probe.py` (answers are held server-side, keyed by nonce).
- **Attribution:** Thiago Goncalves only — no AI/Claude/Anthropic attribution in commits, code, docs, or README; no footers.
- **Tests:** pass under `pytest -W error`; pristine. Real-browser and curl_cffi legs use the `integration` marker. Never `pkill`/`kill -9`; launch with `LAUNCH_FLAGS` + `start_new_session=True` and stop with `os.killpg(SIGKILL)` + bounded `wait`, exactly as `versionmap/corpus.py` does. Use generous timeouts.
- **Build on the lab:** reuse `capture.server.CaptureServer`, `versionmap.chromium_builds.discover_chromium_builds` + `versionmap.corpus.LAUNCH_FLAGS`, and `forger.coherent.forge`. Do not reimplement them.

## Review Focus

- **Existing `/probe` + `/collect` must not regress** when the new routes are added — a broken join would silently corrupt Phases 1–4. → Task 2 tests assert `/probe`+`/collect` still join after the routes exist.
- **The coherent forger must genuinely fail** the challenge (no engine → no/invalid answer → `verify` False) — if it passed, the headline is false. → Task 4 test.
- **Seed sensitivity:** an answer captured for one seed must `verify` False against a different seed's expected — otherwise a forger could replay one captured answer. → Task 3 test.
- **The engine forger must pass by actually computing** (a launched browser produces its answer), not by reading `expected` — otherwise the residual is faked. → Task 3/4: the engine-forger answer comes from the browser-answer helper, asserted distinct from any `expected` plumbing.
- **Same-origin requirement:** the challenge page is served by the server (not a `data:` URL), so the in-page answer `fetch` is same-origin and fires. → Task 1 page targets a relative `/answer/<nonce>`; Task 2 serves it from the server origin.
- **Self-only boundary:** no API takes an arbitrary host; URLs are built from `127.0.0.1` + `server.port`. → Tasks 2–4.

---

### Task 1: Challenge issuer + seeded page (pure)

**Files:**
- Create: `challenge/__init__.py`, `challenge/issue.py`
- Test: `tests/challenge/test_issue.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) Challenge` with `nonce: str` and `seed: str`.
  - `make_challenge() -> Challenge` — fresh nonce (`"chl" + uuid.uuid4().hex[:12]`) and high-entropy seed (`secrets.token_hex(16)`).
  - `challenge_page(challenge: Challenge) -> str` — returns a complete same-origin HTML page: embeds `seed` and `nonce`, renders a seed-parameterised 2D-canvas (seeded fill color + seeded text position) **and** a seeded WebGL `clearColor`+`readPixels`, builds `canvas.toDataURL() + "|" + <gl pixel bytes>`, SHA-256-hashes it in-page with `crypto.subtle`, and POSTs the hex digest to the **relative** URL `"/answer/" + nonce` (method POST, body = hex). The hashing/POST logic mirrors the verified spike.

- [ ] **Step 1: Write the failing tests**

```python
def test_make_challenge_unique():
    a, b = make_challenge(), make_challenge()
    assert a.nonce != b.nonce and a.seed != b.seed
    assert len(a.seed) >= 16 and a.nonce.startswith("chl")

def test_challenge_page_embeds_seed_nonce_and_posts_same_origin():
    c = Challenge(nonce="chlABC", seed="deadbeef")
    html = challenge_page(c)
    assert "deadbeef" in html and "chlABC" in html
    assert "/answer/chlABC" in html          # relative → same-origin fetch
    assert "data:" not in html.split("toDataURL")[0]  # page itself is not a data: URL
    assert "crypto.subtle" in html and "readPixels" in html
```

- [ ] **Step 2: Run tests, verify they fail** — `.venv/bin/python -m pytest tests/challenge/test_issue.py -v`
- [ ] **Step 3: Implement `challenge/issue.py`.** Port the seeded-canvas + WebGL + `crypto.subtle` hashing JS from the de-risk spike (`scratchpad/spike_challenge_stability.py`), reading `seed`/`nonce` from values embedded by `challenge_page` (not from `location.search`), and POSTing to the relative `/answer/<nonce>`. No `tests/challenge/__init__.py`.
- [ ] **Step 4: Run tests to verify pass.**
- [ ] **Step 5: Commit** — `git commit -m "challenge: seeded canvas/webgl challenge issuer + page"`

---

### Task 2: Server `/challenge` + `/answer` routes (additive)

**Files:**
- Modify: `capture/server.py` (add two routes + per-nonce challenge/answer stores; leave `/probe`, `/collect` untouched)
- Test: `tests/challenge/test_server_routes.py`

**Interfaces:**
- Consumes: `challenge.issue.challenge_page` (Task 1).
- Produces (on `CaptureServer`):
  - `register_challenge(nonce: str, seed: str) -> None` — records the seed the server will serve for `nonce` (thread-safe, mirroring the `_nonce_records` lock usage).
  - `get_answer(nonce: str) -> str | None` — the hex digest POSTed to `/answer/<nonce>`, or None.
  - GET `/challenge/<nonce>` → 200 with `challenge_page(Challenge(nonce, seed))` for the registered seed (404/400 if the nonce was never registered or is malformed, reusing `valid_nonce`).
  - POST `/answer/<nonce>` → stores the request body (hex) under `nonce`, 204. (Held in a server-side dict; do NOT modify `Record`.)

- [ ] **Step 1: Write the failing tests** (use the existing TLS `server` fixture pattern from `tests/capture/conftest.py`; a `tests/challenge/conftest.py` provides it)

```python
@pytest.mark.integration
def test_challenge_served_and_answer_joined(server):
    server.register_challenge("chlXYZ", "cafe")
    # fetch the challenge page (stdlib urllib, cert-insecure) and confirm seed present
    page = _get(server, "/challenge/chlXYZ")
    assert "cafe" in page and "/answer/chlXYZ" in page
    _post(server, "/answer/chlXYZ", b"abc123")
    assert server.get_answer("chlXYZ") == "abc123"

@pytest.mark.integration
def test_probe_collect_still_join(server):
    # the pre-existing join must be untouched by the new routes
    nonce = "prbTEST"
    _get(server, "/probe/" + nonce)
    _post(server, "/collect/" + nonce, b'{"webdriver": false}')
    rec = _wait_probe_record(server, nonce)
    assert rec.js == {"webdriver": False}
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement the routes** in `capture/server.py`: add `self._challenges: dict[str,str]` and `self._answers: dict[str,str]` (guarded by the existing `_lock`), `register_challenge`/`get_answer`, and GET/POST branches that slot in beside the existing `/probe`//`/collect` handling (same `valid_nonce` guard, same lock discipline). Keep the diff additive — do not alter the `/probe`/`/collect` code paths. Put the small `_get`/`_post`/`_wait_probe_record` helpers in `tests/challenge/conftest.py`.
- [ ] **Step 4: Run tests to verify pass**, plus the existing server suite: `.venv/bin/python -m pytest tests/capture tests/challenge/test_server_routes.py -q`.
- [ ] **Step 5: Commit** — `git commit -m "capture: additive /challenge and /answer routes with nonce join"`

---

### Task 3: Oracle, verifier, and client answer drivers

**Files:**
- Create: `challenge/oracle.py`, `challenge/verify.py`, `challenge/clients.py`
- Test: `tests/challenge/test_verify.py`, `tests/challenge/test_clients.py`

**Interfaces:**
- Consumes: `challenge.issue.make_challenge`, the Task 2 server routes, `versionmap.chromium_builds.discover_chromium_builds`, `versionmap.corpus.LAUNCH_FLAGS`, `forger.coherent.forge`.
- Produces:
  - `browser_answer(server, nonce: str, seed: str, *, exe: str | None = None, timeout: float = 12.0) -> str | None` (in `oracle.py`) — `register_challenge(nonce, seed)`, launch a CfT browser (direct `subprocess` + `LAUNCH_FLAGS` + `start_new_session`, `killpg(SIGKILL)` in `finally`) at `https://127.0.0.1:<port>/challenge/<nonce>`, poll `server.get_answer(nonce)` until set or timeout, return it. `exe=None` picks the first discovered build.
  - `run_oracle(server, challenge) -> str` (in `oracle.py`) — the trusted reference answer = `browser_answer(server, challenge.nonce, challenge.seed)`; raises `RuntimeError` if the browser produced none. (The digest depends only on the seed — verified by the spike — so any browser's answer for `seed` equals the oracle's, regardless of nonce.)
  - `verify(expected: str | None, got: str | None) -> bool` (in `verify.py`) — True iff both are non-empty and exactly equal.
  - In `clients.py`, three answer-producing clients, each `(server, seed: str) -> str | None`. Each client mints its OWN fresh challenge nonce (`make_challenge()` reused for its nonce, or a fresh `"chl"+uuid` + the passed `seed`), registers it, and tries to get that nonce answered:
    - `honest_browser(server, seed)` — fresh nonce, `browser_answer(server, nonce, seed)` (real engine → valid answer).
    - `coherent_forger(server, seed)` — fresh nonce + `register_challenge(nonce, seed)`, then drives the Phase 4 `forger.coherent.forge(server, payload=build_payload())` (curl_cffi, fabricated `/collect`) against a fresh `/probe` nonce — it has **no JS engine**, so nothing ever answers the challenge nonce. Returns `server.get_answer(nonce)`, which stays None. Models the exact Phase 4 forger facing the active challenge.
    - `engine_forger(server, seed)` — the honest residual: compute the digest with a real browser on a **throwaway** challenge nonce (`browser_answer(server, scratch_nonce, seed)`), then mint the client's own fresh challenge nonce and **relay** that computed hex to `/answer/<nonce>` over a **curl_cffi** POST (not the browser). Returns the relayed hex read back via `server.get_answer(nonce)`. This keeps the TLS/answer channel curl_cffi's while the answer is genuinely engine-computed — distinct from `honest_browser`, whose browser posts its own answer directly. Never read `expected`/oracle state.

- [ ] **Step 1: Write the failing tests**

```python
def test_verify_exact_and_seed_sensitive():
    assert verify("deadbeef", "deadbeef") is True
    assert verify("deadbeef", "feedface") is False      # different seed's digest
    assert verify(None, "deadbeef") is False
    assert verify("deadbeef", None) is False

@pytest.mark.integration
def test_oracle_and_honest_browser_agree(server):
    c = make_challenge()
    expected = run_oracle(server, c)
    assert expected                                      # a real engine answered
    got = honest_browser(server, c.seed)
    assert verify(expected, got) is True                 # deterministic on this host

@pytest.mark.integration
def test_coherent_forger_cannot_answer(server):
    c = make_challenge()
    assert coherent_forger(server, c.seed) in (None, "")

@pytest.mark.integration
def test_engine_forger_computes_a_valid_answer(server):
    c = make_challenge()
    expected = run_oracle(server, c)
    assert verify(expected, engine_forger(server, c.seed)) is True
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement** `verify.py` (trivial), `oracle.py` (reuse `versionmap/corpus.py`'s exact launch/kill pattern — read it), and `clients.py`. For `coherent_forger`, reuse `forge(server, payload=build_payload())` for the passive leg so it is literally the Phase 4 forger; the point is it has no way to produce the challenge digest.
- [ ] **Step 4: Run tests to verify pass** (integration; generous timeout).
- [ ] **Step 5: Commit** — `git commit -m "challenge: oracle reference, exact-match verifier, and client answer drivers"`

---

### Task 4: Defender ladder, CLI, artifact, and write-up

**Files:**
- Create: `challenge/ladder.py`, `challenge/cli.py`, `challenge/__main__.py`
- Create: `runs/2026-10-26-challenge/challenge.json`, `runs/2026-10-26-challenge/README.md`
- Test: `tests/challenge/test_ladder.py`, `tests/challenge/test_challenge_cli.py`

**Interfaces:**
- Consumes: Task 3 (`run_oracle`, `verify`, `honest_browser`, `coherent_forger`, `engine_forger`), `make_challenge`, `CaptureServer`.
- Produces:
  - `LADDER: list[Rung]` where `Rung = {name, client, tls_layer, runs_engine, expect_pass}` — three rungs: `honest-browser` (real chromium TLS, runs_engine True, expect pass), `coherent-forger` (curl_cffi TLS, runs_engine False, expect **fail/caught**), `engine-forger` (curl_cffi TLS, runs_engine True, expect pass). `client` is the Task 3 callable.
  - `run_ladder(server) -> list[dict]` — per rung: fresh `make_challenge`, `expected = run_oracle(server, c)`, `got = rung.client(server, c.seed)`, `passed = verify(expected, got)`; row `{name, tls_layer, runs_engine, passed}`.
  - CLI `main(argv=None) -> int` (+ `challenge/__main__.py`), default `--out runs/2026-10-26-challenge`, starts a `CaptureServer`, runs the ladder, writes `challenge.json` + `README.md`, returns 0.

- [ ] **Step 1: Write the failing tests**

```python
@pytest.mark.integration
def test_ladder_catches_only_the_coherent_forger(server):
    rows = {r["name"]: r for r in run_ladder(server)}
    assert rows["honest-browser"]["passed"] is True
    assert rows["coherent-forger"]["passed"] is False     # the headline
    assert rows["engine-forger"]["passed"] is True        # honest residual

@pytest.mark.integration
def test_cli_writes_artifact(tmp_path):
    assert main(["--out", str(tmp_path)]) == 0
    doc = json.loads((tmp_path / "challenge.json").read_text())
    byname = {r["name"]: r for r in doc["rungs"]}
    assert byname["coherent-forger"]["passed"] is False
    readme = (tmp_path / "README.md").read_text()
    for h in ("## The active challenge", "## Defender ladder", "## What this measures",
              "## Scope and ethics", "## Reproduce"):
        assert h in readme
    for banned in ("Claude", "Anthropic", "AI-generated"):
        assert banned not in readme
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement** `challenge/ladder.py` + `challenge/cli.py` + `challenge/__main__.py`, then author `runs/2026-10-26-challenge/README.md` from the generated `challenge.json`. README headings EXACTLY and in order: `## The active challenge`, `## Defender ladder`, `## What this measures`, `## Scope and ethics`, `## Reproduce`. In the researcher's voice, from the artifact's real numbers: the challenge mechanism (seeded canvas/WebGL hash computed live, verified against an oracle on the same host); the ladder table (client → TLS layer → runs-engine → challenge outcome); the measured finding (**the active challenge catches exactly the coherent forger the passive scorer could not**, because a forger can fabricate self-reported values but cannot compute a per-nonce seeded render without a real engine); the **honest residual** (the engine forger passes — the challenge raises the attacker floor from "fabricate ~12 JSON fields" to "run a real browser engine," and the remaining gap is that the answer is joined by application-level nonce, not bound to the probe's TLS connection → motivates channel binding as the next arm); **Scope and ethics** (self-only, loopback, the researcher's own detector; deterministic same-host software rendering is why exact-match suffices, with cross-GPU variance named as a caveat, not a product). Exact reproduce command: `.venv/bin/python -m challenge --out runs/2026-10-26-challenge`.
- [ ] **Step 4: Run the CLI for real**, then the full suite: `.venv/bin/python -m challenge --out runs/2026-10-26-challenge && .venv/bin/python -m pytest -q`.
- [ ] **Step 5: Commit** — `git add challenge tests/challenge runs/2026-10-26-challenge && git commit -m "challenge: defender ladder, CLI, artifact, and asymmetry write-up"`

---

## Notes for the executor

- The honest-browser and engine-forger rungs both legitimately pass — that is the intended, honest result. The ladder's value is that the **coherent forger is the only one caught**, and that passing at all now requires running a real engine. If a rung's outcome surprises you, report it; do not tune `crosslayer/`, `forger/`, or the verifier to force a verdict.
- Browser determinism was de-risked on this host; if `honest_browser` and the oracle ever disagree, that is a finding about rendering non-determinism (report it), not a reason to loosen `verify` to fuzzy matching without saying so.
- Real-browser launches use the lab's CfT binaries with `LAUNCH_FLAGS`; the macOS keychain-wedge lesson is about the real Google Chrome app, not these — follow `versionmap/corpus.py` exactly (direct `subprocess`, `start_new_session`, `killpg(SIGKILL)`, bounded `wait`). Never `pkill -9`.
- Keep `runs/2026-10-26-challenge/` numbers sourced from the committed `challenge.json`.
