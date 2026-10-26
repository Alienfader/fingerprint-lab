# Phase 3 — Cross-layer consistency scorer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An explainable, multi-tier scorer that, from one captured cross-layer `Record`, decides whether a client is automated/forged or a real browser — using HTTP/2, header/client-hint, and (chiefly) the JS/GPU layer, and **not** JA4 — reporting the exact contradictions behind each verdict.

**Architecture:** Pure feature extractors over a `Record` → a set of independent contradiction checks (per-signal, family-consistency, cross-layer) → a scorer that aggregates them into a confidence-tagged `Verdict` scoped to what was observable. A CLI drives the forgery population (curl_cffi / tls_client / stdlib) plus a real browser at the JS-probe URL, scores each, and writes a committed `runs/` artifact + an honest README headlining the verified JA4-defeated finding.

**Tech Stack:** Python 3.15, repo `.venv`, the Phase 1 `capture/` package (`CaptureServer`, `Record`, driver). Stdlib-first. Tests under `pytest -W error`.

**Spec:** `docs/superpowers/specs/2026-10-25-version-level-crosslayer-consistency-design.md` — read it, **including the "Phase 3 revision — 2026-10-26" addendum at the end**, which is the binding design for this plan (it supersedes the spec's original JA4-version-resolution approach).

## Global Constraints

- **JA4 is a defeated input.** The scorer MUST NOT use `tls.ja4` / `tls.ja4_norm` / `tls.ja3*` to decide its verdict. Verified: curl_cffi `chrome124` and real Chrome 130 (Playwright) share a byte-identical full JA4 `t13i1515h2_8daaf6152771_02713d6af862`, and the normalized key is launch-profile-dominated. JA4 may be echoed in output as context only, clearly labelled non-decisive.
- **Data boundary:** self-only, loopback 127.0.0.1 only; no third-party probing; no volunteer/non-consented data.
- **Reproducibility:** every number in the write-up comes from a committed `runs/2026-10-26-crosslayer/` artifact.
- **Attribution:** Thiago Goncalves only — no AI/Claude/Anthropic attribution in commits, code, docs, or README; no `Co-Authored-By`/"Generated with"/emoji footers.
- **Tests:** pass under `pytest -W error`; pristine output. Integration tests that launch real browsers use the `integration` marker; browser launches go through the existing driver/corpus path (keychain-safe flags already in place).
- **Build on the lab:** reuse `capture/` (`Record`, `CaptureServer`, `driver`); do not reimplement capture. Keep `capture/static/probe.js` unchanged (its `navigator.userAgentData` enrichment is deferred to Phase 4).
- **Explainability:** every verdict lists the specific contradictions (layer + code + human detail); no opaque score.

## Review Focus

- **`js` is None because the probe was never served, vs served-but-not-executed.** The scorer must treat JS-absence as a signal only when a probe WAS served (`http.path` starts with `/probe`); otherwise JS is "not observed", not "absent". → Task 3.
- **A layer is entirely missing** (`http2`/`http`/`js` is None, e.g. stdlib speaks no h2): every extractor and check must handle None without raising and mark the layer unobserved. → Tasks 1–3.
- **An unknown UA family** (not chrome/safari/firefox): family checks must return "inconclusive", never a false contradiction. → Tasks 1–2.
- **An HTTP/2 Akamai string in an unexpected shape:** `akamai_family` returns "unknown" (no crash, no false mismatch). → Task 1.
- **A coherent real browser** (webdriver false, `window.chrome` present, JS UA == HTTP UA, real GPU): the scorer MUST be able to return `label="real"` with no contradictions — proving it is not a flag-everything oracle (true-negative capability; the headed-browser baseline itself is deferred). → Task 3.

---

### Task 1: Feature extractors

**Files:**
- Create: `crosslayer/__init__.py`, `crosslayer/features.py`
- Test: `tests/crosslayer/test_features.py`

**Interfaces:**
- Produces: pure functions over a `capture.record.Record` (or its sub-dicts):
  - `ua_family(ua: str | None) -> str` → `"chrome" | "safari" | "firefox" | "other"`
  - `ua_major(ua: str | None) -> int | None` (Chrome major from `Chrome/<n>`)
  - `akamai_family(akamai: str | None) -> str` → `"chrome" | "safari" | "firefox" | "unknown" | "none"`
  - `has_client_hints(http: dict | None) -> bool` (any `sec-ch-*` header)
  - `has_sec_fetch(http: dict | None) -> bool` (any `sec-fetch-*` in `header_order`)
  - `ch_ua_platform(http: dict | None) -> str | None`
  - `js_present(rec: Record) -> bool`
- Consumes: nothing from later tasks.

- [ ] **Step 1: Write the failing tests** (values from the captured snapshot):

```python
def test_ua_family_and_major():
    chrome = "Mozilla/5.0 ... Chrome/124.0.0.0 Safari/537.36"
    assert ua_family(chrome) == "chrome" and ua_major(chrome) == 124
    assert ua_family("Mozilla/5.0 ... Version/17.0 Safari/605.1.15") == "safari"
    assert ua_family(None) == "other" and ua_major(None) is None

def test_akamai_family_by_shape():
    chrome = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    safari = "2:0;4:4194304;3:100|10485760|0|m,s,p,a"
    assert akamai_family(chrome) == "chrome"
    assert akamai_family(safari) == "safari"
    assert akamai_family(None) == "none"
    assert akamai_family("weird|0|0|x,y") == "unknown"

def test_client_hints_and_sec_fetch():
    http = {"header_order": ["sec-ch-ua","sec-fetch-mode","user-agent"],
            "client_hints": {"sec-ch-ua": "...", "sec-ch-ua-platform": "\"macOS\""}}
    assert has_client_hints(http) and has_sec_fetch(http)
    assert ch_ua_platform(http) == "\"macOS\""
    bare = {"header_order": ["accept","user-agent"], "client_hints": {}}
    assert not has_client_hints(bare) and not has_sec_fetch(bare)
```

- [ ] **Step 2: Run tests, verify they fail** — `.venv/bin/python -m pytest tests/crosslayer/test_features.py -v`
- [ ] **Step 3: Implement `crosslayer/features.py`.** `akamai_family` classifies on the pseudo-header-order segment (last `|`-field): `m,a,s,p`→chrome, `m,s,p,a`→safari, `m,p,a,s`→firefox; empty/None→none; anything else→unknown. UA parsing is substring/regex. All functions tolerate None.
- [ ] **Step 4: Run tests to verify pass.**
- [ ] **Step 5: Commit** — `git commit -m "crosslayer: cross-layer feature extractors"`

---

### Task 2: Contradiction checks

**Files:**
- Create: `crosslayer/checks.py`
- Test: `tests/crosslayer/test_checks.py`

**Interfaces:**
- Consumes: `crosslayer/features.py` (Task 1); `capture.record.Record`.
- Produces:
  - `@dataclass(frozen=True) Contradiction(layer: str, code: str, detail: str, severity: str)` — `severity ∈ {"strong","weak"}`.
  - `run_checks(rec: Record) -> list[Contradiction]` — runs every check below and returns all that fire, deterministically ordered.
  - Each check is its own function `(rec) -> Contradiction | None` so it is unit-testable in isolation: `check_no_http2`, `check_akamai_family`, `check_missing_client_hints`, `check_missing_sec_fetch`, `check_webdriver`, `check_headless_gpu`, `check_window_chrome`, `check_js_ua_mismatch`, `check_perm_mismatch`, `check_js_absent_when_served`.

- [ ] **Step 1: Write the failing tests** — one per check, using synthetic `Record`s plus assertions that the right code fires and does NOT fire on a clean record. Key cases (values from the snapshot):

```python
def test_akamai_family_mismatch_fires_on_safari_tls_chrome_ua():
    rec = Record(http={"user_agent": CHROME_UA, "header_order": [], "client_hints": {}},
                 http2={"akamai": "2:0;4:4194304;3:100|10485760|0|m,s,p,a", "alpn": "h2"})
    c = check_akamai_family(rec)
    assert c and c.code == "akamai_family_vs_ua" and c.severity == "strong"

def test_missing_client_hints_under_chrome_fires():
    rec = Record(http={"user_agent": CHROME_UA, "header_order": ["accept","user-agent"], "client_hints": {}},
                 http2={"akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", "alpn": "h2"})
    assert check_missing_client_hints(rec).code == "missing_client_hints"

def test_no_http2_under_browser_ua_fires():
    rec = Record(http={"user_agent": CHROME_UA, "header_order": ["Host"], "client_hints": {}}, http2=None)
    assert check_no_http2(rec).code == "no_http2"

def test_webdriver_and_headless_gpu_fire():
    rec = Record(js={"webdriver": True, "webglRenderer": "ANGLE (Google, Vulkan ... SwiftShader Device ...)"})
    assert check_webdriver(rec).code == "webdriver_true"
    assert check_headless_gpu(rec).code == "headless_gpu"

def test_js_absent_only_when_probe_served():
    served = Record(http={"user_agent": CHROME_UA, "path": "/probe/abc", "client_hints": {"sec-ch-ua":"x"}},
                    http2={"akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", "alpn": "h2"}, js=None)
    assert check_js_absent_when_served(served).code == "js_absent"
    not_served = Record(http={"user_agent": CHROME_UA, "path": "/", "client_hints": {}}, js=None)
    assert check_js_absent_when_served(not_served) is None  # observability: not served, not a signal

def test_clean_coherent_browser_has_no_contradictions():
    rec = Record(http={"user_agent": CHROME_UA, "path": "/probe/x", "header_order": ["sec-ch-ua","sec-fetch-mode","user-agent"],
                       "client_hints": {"sec-ch-ua":"x","sec-ch-ua-platform":"\"macOS\""}},
                 http2={"akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", "alpn": "h2"},
                 js={"webdriver": False, "userAgent": CHROME_UA, "hasWindowChrome": True,
                     "platform": "MacIntel", "webglRenderer": "ANGLE (Apple, Apple M1, OpenGL 4.1)",
                     "permMismatch": False})
    assert run_checks(rec) == []
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement `crosslayer/checks.py`.** Each check reads only the layers it needs and returns None when inputs are missing/unobserved. `check_headless_gpu` matches `SwiftShader` or `llvmpipe` (case-insensitive) in `webglRenderer`. `check_js_absent_when_served` fires only when `http.path` starts with `/probe` and `js` is None. `check_window_chrome` fires only when `ua_family=="chrome"` and `js` present and `hasWindowChrome` is False. `run_checks` calls all, drops Nones, sorts by (severity desc, code).
- [ ] **Step 4: Run tests to verify pass.**
- [ ] **Step 5: Commit** — `git commit -m "crosslayer: contradiction checks across layers"`

---

### Task 3: Scorer

**Files:**
- Create: `crosslayer/scorer.py`
- Test: `tests/crosslayer/test_scorer.py`

**Interfaces:**
- Consumes: `crosslayer/checks.py` (Task 2).
- Produces:
  - `@dataclass Verdict(label: str, confidence: str, contradictions: list[Contradiction], observed: dict)` with `to_dict()`. `label ∈ {"automated","real","inconclusive"}`; `confidence ∈ {"high","medium","low"}`; `observed` = `{"tls":bool,"http2":bool,"http":bool,"js":bool}`.
  - `score(rec: Record) -> Verdict`.

- [ ] **Step 1: Write the failing tests** — one per represented client class, asserting label + that the expected contradiction code is present and that JA4 was not consulted:

```python
def test_curl_cffi_chrome_caught_by_js_absence_not_ja4():
    rec = Record(tls={"ja4":"t13i1515h2_8daaf6152771_02713d6af862","ja4_norm":"02713d6af862"},
                 http2={"akamai":"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p","alpn":"h2"},
                 http={"user_agent":CHROME_UA,"path":"/probe/x","client_hints":{"sec-ch-ua":"x"},
                       "header_order":["sec-ch-ua","sec-fetch-mode","user-agent"]}, js=None)
    v = score(rec)
    assert v.label == "automated"
    assert any(c.code == "js_absent" for c in v.contradictions)

def test_safari_tls_chrome_ua_caught_by_family():
    # curl_cffi safari17_0 with forced Chrome UA
    ...
    assert v.label == "automated" and any(c.code == "akamai_family_vs_ua" for c in v.contradictions)

def test_stdlib_caught_by_no_http2():
    ... assert v.label == "automated" and any(c.code == "no_http2" for c in v.contradictions)

def test_coherent_real_browser_is_real():
    # webdriver False, window.chrome present, JS UA == HTTP UA, real GPU, probe executed
    v = score(coherent_real_record())
    assert v.label == "real" and v.contradictions == []

def test_missing_layers_do_not_crash_and_scope_confidence():
    v = score(Record(http={"user_agent": CHROME_UA, "path": "/"}))  # only http observed
    assert v.observed["js"] is False and v.label in {"inconclusive","automated"}
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement `crosslayer/scorer.py`.** `score` runs `run_checks`; label = `"automated"` if any `strong` contradiction, else `"real"` if JS was observed and no contradictions, else `"inconclusive"`. `confidence` rises with the number of *distinct layers* contributing strong contradictions (1 layer→low/medium, ≥2→high); a `real` verdict with full observability is `high`, with partial observability `low`. `observed` reflects which `Record` layers are non-None. The function reads no `tls` JA4 fields (a later reviewer will grep for `ja4` in scorer.py — there must be none in the decision path).
- [ ] **Step 4: Run tests to verify pass.**
- [ ] **Step 5: Commit** — `git commit -m "crosslayer: explainable multi-tier scorer (JA4-free verdict)"`

---

### Task 4: CLI, evaluation artifact, and write-up

**Files:**
- Create: `crosslayer/cli.py`, `crosslayer/__main__.py`
- Create: `runs/2026-10-26-crosslayer/scores.json`, `runs/2026-10-26-crosslayer/README.md`
- Test: `tests/crosslayer/test_cli.py`

**Interfaces:**
- Consumes: Tasks 1–3; `capture.server.CaptureServer`; a driving helper.
- Produces: `main(argv=None) -> int` that captures the population **at the probe URL**, scores each record, and writes `scores.json` + `README.md`.

- [ ] **Step 1: Write the failing test** — `@pytest.mark.integration`: `main(["--out", str(tmp_path)])` returns 0; `scores.json` and `README.md` exist; every non-browser client scores `automated`; the real browser record carries a JS layer; the README contains headings `## The JA4 result (why this scorer exists)`, `## Per-client verdicts`, `## Detection by layer`, `## Scope and caveats`, `## Reproduce`, and contains neither "Claude" nor "Anthropic".
- [ ] **Step 2: Run it, verify it fails.**
- [ ] **Step 3: Implement the CLI.** Drive these clients, each pointed at `/probe/<nonce>` so JS-absence is a fair, observed signal: `curl:chrome124`, `curl:safari17_0`, `tls:chrome_124`, `stdlib:urllib`, `browser:chromium`. (Reuse `capture.driver` helpers; add a small variant that sends the non-browser clients to the probe URL and captures their record — they fetch the page but never POST `/collect`, so `js` stays None.) Score each; write `scores.json` (per client: label, confidence, contradictions, observed, plus the non-decisive `ja4` for context). Author `README.md` in the researcher's voice: open with the verified JA4 collision (curl_cffi == real Chrome 130 full JA4, and launch-profile-dominated keys) as the reason the verdict ignores JA4; a per-client verdict table; a detection-by-layer table (which contradiction code caught each client); the JS layer as the backbone; scope/caveats (headless Playwright is the only "browser" here so it legitimately trips `webdriver`; a headed-browser true-negative baseline and the Phase 4 coherent forger are deferred; small n); and the exact reproduce command. Every number from the artifact.
- [ ] **Step 4: Run the CLI for real**, then the full suite: `.venv/bin/python -m crosslayer --out runs/2026-10-26-crosslayer && .venv/bin/python -m pytest -q`.
- [ ] **Step 5: Commit** — `git add crosslayer tests/crosslayer runs/2026-10-26-crosslayer && git commit -m "crosslayer: scorer CLI, evaluation artifact, and write-up"`

---

## Notes for the executor

- The only "real browser" available is headless Playwright chromium, which legitimately has `webdriver=true` and a SwiftShader GPU — so it scores `automated`, correctly. That is expected; the scorer's `real` path is proven by a synthetic coherent record (Task 3), and a headed-browser true-negative baseline is deferred.
- Keep browser launches on the keychain-safe path already in `capture/` (macOS pops a blocking keychain prompt otherwise).
- JA4 fields may appear in `scores.json`/README only as explicitly-labelled context; they must not enter `scorer.py`'s decision path.
