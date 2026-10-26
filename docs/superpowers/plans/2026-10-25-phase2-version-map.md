# Phase 2 — Version-resolution map Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a `normalized JA4 extension-hash → (family, version-or-range, OS, arch)` map from a real multi-version Chromium corpus captured against the Phase 1 server, keyed on a normalization recipe proven (by spike) to be stable within a version and distinct across versions.

**Architecture:** Fix the GREASE-in-sigalgs bug in `capture/ja4.py` and add a `normalized_ext_key`; a `versionmap/` package discovers installed Chromium builds, drives each N times at the Phase 1 `CaptureServer` to produce per-build corpus entries, then folds the corpus into a map that records resolution granularity and tags every entry with OS/arch. The deliverable is a committed `runs/<date>/` artifact (map + corpus + README).

**Tech Stack:** Python 3.15, repo `.venv`, Phase 1 `capture/` package (`CaptureServer`, `parse_client_hello`), Playwright (pinned Chromium builds via `executable_path`), `curl_cffi`. Stdlib-first elsewhere. Tests under `pytest -W error`.

**Spec:** `docs/superpowers/specs/2026-10-25-version-level-crosslayer-consistency-design.md` (Phase 2 section). Read it; this plan argues from it.

**De-risk evidence (already established, 2026-10-25, throwaway spikes):** Raw JA4_c is NOT a stable version key (Chrome 156 gave 25 distinct values over 40 connections). Two variance sources: (1) `compute_ja4` fails to strip GREASE from `signature_algorithms` though the FoxIO spec and the module docstring require it — recent Chrome injects a random GREASE sigalg per connection; (2) `pre_shared_key` (0x0029) toggles with session resumption. The normalized key (strip GREASE from extensions **and** sigalgs; drop resumption extensions {0x0029, 0x002a}) collapses each version to exactly one key. A full 6-build preview corpus (direct-launch, fixed flags, 5 connections each) produced a **stable single key per build** and this map — 4 keys over 6 versions, two real ranges:

| normalized key | versions |
|---|---|
| `d8a2da3f94cd` | 130, 140 |
| `dcad5a053991` | 146 |
| `cb7bf5808d99` | 150 |
| `4980c97edce0` | 151, 156 |

Range-level (not exact-version) resolution is the expected, reportable outcome. Two further execution facts the preview surfaced and this plan bakes in: **(A) launch flags change the ClientHello**, so the corpus fixes one minimal flag set and records it as provenance (a key is valid only for browsers behaving like the corpus launch profile); **(B) very old builds (120) crash on this macOS (26.x)** — the harness must mark a build that yields no ClientHello as non-runnable and exclude it, never crash the run. Curl_cffi `chrome124` (`02713d6af862`) is distinct from every real build — the forgery case Phase 3 will exploit.

## Global Constraints

- **Data boundary:** self-only, loopback 127.0.0.1 only; never a public endpoint; no third-party live probing; no volunteer/non-consented data. Corpus = the researcher's own installed browser builds only.
- **Reproducibility:** every reported number backed by a committed `runs/<date>/` artifact.
- **Attribution:** Thiago Goncalves only — no AI/Claude/Anthropic attribution in commits, code, docs, or READMEs; no `Co-Authored-By` or "Generated with" footers.
- **Decision logging:** deliberate changes logged to Continuity (`continuity log …`) immediately after each, with the commit hash.
- **Tests:** must pass under `pytest -W error`. Integration tests that launch real browsers use the `integration` marker (registered in `pytest.ini`).
- **Build on the lab:** reuse `capture/` and `ja3_diff` plumbing; do not reimplement the capture server or the ClientHello parser.
- **Scope of this increment (builder's call, flagged):** Chrome/Chromium family only; macOS/arm64 only (no Windows/Linux VMs available on this machine). Multi-OS and public-dataset enrichment are documented follow-ups, not tasks here. Every map entry carries OS+arch so a macOS entry never silently judges another platform.
- **Key recipe (fixed by spike, do not redesign):** normalized key = `sha256( sorted(hex(ext) for ext in extensions if ext not GREASE and ext not in {0x0000 SNI, 0x0010 ALPN, 0x0029 PSK, 0x002a early_data}) + "_" + ",".join(hex(s) for s in sigalgs if s not GREASE) )[:12]`.
- **Browser corpus is driven by DIRECT subprocess launch, not Playwright.** Playwright's launch flags (a) are version-coupled and crash old builds and (b) alter the ClientHello. The corpus launches each Chrome binary directly with this fixed, recorded flag set: `--headless=new --disable-gpu --no-sandbox --no-first-run --no-default-browser-check --disable-background-networking --ignore-certificate-errors --user-data-dir=<fresh temp>` plus the target URL. Each launch is its own process group; cleanup is `os.killpg(SIGKILL)` (crashing old builds leave crashpad stragglers otherwise). This flag set is recorded in the corpus/map metadata as the launch profile.
- **Browser cache dirs:** CfT downloads live in `~/.cache/fingerprint-lab/chromium/<version>/chrome-mac-arm64/...`; Playwright builds in `~/Library/Caches/ms-playwright/chromium-<rev>/...`. Both share the `chrome-mac-arm64/Google Chrome for Testing.app` layout. The 7 builds (120,130,140,146,150 downloaded + 151,156 Playwright) are already installed and de-quarantined.

## Review Focus

- **A build that fails to produce a ClientHello** (OS-incompatible, e.g. Chrome 120 on macOS 26): the harness must mark it non-runnable and exclude it from the map, never crash the whole run. → Task 3 tests.
- **A build whose normalized key is NOT stable across connections** (a future browser varying something the recipe doesn't absorb): the corpus harness must record the instability and refuse to emit a single confident key, not silently pick one. → Task 3 tests.
- **Two different versions sharing one normalized key** (legitimate when the ext set + sigalgs are unchanged between adjacent versions): the map must represent this as a version *range*, never overwrite one with the other. → Task 4 tests.
- **A ClientHello carrying GREASE in `signature_algorithms`**: both `compute_ja4` and `normalized_ext_key` must strip it. → Task 1 tests.
- **A ClientHello with an empty/absent `signature_algorithms` list**: key computation must not crash and must produce the ext-only form. → Task 1 edge test.
- **OS/arch provenance**: every map entry and corpus entry must carry `os` and `arch`; a map built on macOS/arm64 must say so in its metadata. → Task 4 schema test.

---

### Task 1: Fix `compute_ja4` GREASE-sigalg bug and add `normalized_ext_key`

**Files:**
- Modify: `capture/ja4.py` (fix `compute_ja4` line ~115; add `normalized_ext_key`)
- Test: `tests/capture/test_ja4.py` (extend)

**Interfaces:**
- Consumes: `ClientHello`, `GREASE`, `_hex`, `_ng` from `capture/ja4.py`.
- Produces: `normalized_ext_key(ch: ClientHello) -> str` (12 hex chars) — the stable per-version key used by all of Phase 2. `compute_ja4` keeps its signature; its JA4_c now strips GREASE from sigalgs.

- [ ] **Step 1: Write the failing tests**

```python
def test_compute_ja4_strips_grease_from_sigalgs():
    # Two hellos identical but for a GREASE sigalg injected at the front must
    # produce the SAME ja4 (GREASE must not reach the sigalg segment).
    base = ClientHello(legacy_ver=0x0303, ciphers=[0x1301], exts=[0x000d],
                       sigalgs=[0x0403, 0x0804], sup_vers=[0x0304])
    greased = dataclasses.replace(base, sigalgs=[0xEAEA, 0x0403, 0x0804])
    assert compute_ja4(greased) == compute_ja4(base)

def test_normalized_key_absorbs_grease_sigalg_and_resumption_exts():
    base = ClientHello(legacy_ver=0x0303, ciphers=[0x1301],
                       exts=[0x000d, 0x002b], sigalgs=[0x0403, 0x0804], sup_vers=[0x0304])
    noisy = dataclasses.replace(base, sigalgs=[0xBABA, 0x0403, 0x0804],
                                exts=[0x000d, 0x002b, 0x0029, 0x002a])  # + PSK + early_data
    assert normalized_ext_key(noisy) == normalized_ext_key(base)

def test_normalized_key_differs_on_real_ext_set_change():
    a = ClientHello(legacy_ver=0x0303, ciphers=[0x1301], exts=[0x000d, 0x002b],
                    sigalgs=[0x0403], sup_vers=[0x0304])
    b = dataclasses.replace(a, exts=[0x000d, 0x002b, 0x0033])  # key_share added
    assert normalized_ext_key(a) != normalized_ext_key(b)

def test_normalized_key_handles_empty_sigalgs():
    ch = ClientHello(legacy_ver=0x0303, ciphers=[0x1301], exts=[0x002b], sup_vers=[0x0304])
    assert re.fullmatch(r"[0-9a-f]{12}", normalized_ext_key(ch))

def test_compute_ja4_fixture_value_unchanged():
    # The chrome124 fixture has no GREASE sigalg, so the GREASE-strip fix must NOT
    # change its validated oracle value — guards against regressing the Phase 1 pin.
    ch = parse_client_hello(FIXTURE_BYTES)
    assert compute_ja4(ch) == "t13d1516h2_8daaf6152771_02713d6af862"
```

- [ ] **Step 2: Run the tests, verify the new ones fail** (`test_compute_ja4_strips_grease_from_sigalgs`, the two `normalized_*`) and `test_compute_ja4_fixture_value_unchanged` passes.

Run: `.venv/bin/python -m pytest tests/capture/test_ja4.py -v`
Expected: new behavior tests FAIL (NameError / assertion); fixture test PASSES.

- [ ] **Step 3: Implement the fix and `normalized_ext_key` in `capture/ja4.py`**

In `compute_ja4`, change the sigalg source to GREASE-filtered: `sig = ",".join(_hex(s) for s in _ng(ch.sigalgs))`. Add module constant `RESUMPTION_EXTS = frozenset({0x0029, 0x002a})`. Add `normalized_ext_key(ch)` reusing the same sorted-ext + ordered-GREASE-free-sigalg construction as `compute_ja4`'s JA4_c, additionally excluding `RESUMPTION_EXTS` from the extension list (SNI 0x0000 and ALPN 0x0010 already excluded), returning the 12-char sha256 prefix. Factor the shared ja4_c body into a private helper if it reduces duplication (DRY), but do not change `compute_ja4`'s public result beyond the GREASE-sigalg fix.

- [ ] **Step 4: Run tests to verify all pass** — `.venv/bin/python -m pytest tests/capture/test_ja4.py -v` → PASS.

- [ ] **Step 5: Commit** — `git commit -m "ja4: strip GREASE from sigalgs (spec fix); add normalized_ext_key"`

---

### Task 2: Discover installed Chromium builds

**Files:**
- Create: `versionmap/__init__.py`, `versionmap/chromium_builds.py`
- Test: `tests/versionmap/test_chromium_builds.py`

**Interfaces:**
- Produces: `@dataclass ChromiumBuild(version: str, os: str, arch: str, executable_path: str, source: str)` (`source` = "cft" or "playwright") and `discover_chromium_builds(cache_dirs: list[str] | None = None) -> list[ChromiumBuild]`. Later tasks consume this list.

- [ ] **Step 1: Write the failing test** — against the two real caches, assert the discovered `version`s include the known-installed majors {130,140,146,150,151,156}, each with an existing `executable_path`, `arch == "arm64"`, `os == "mac"`, and correct `source`. Mark `@pytest.mark.integration` (reads the real caches).

```python
@pytest.mark.integration
def test_discovers_installed_chromium_builds():
    builds = discover_chromium_builds()
    majors = {b.version.split(".")[0] for b in builds}
    assert {"130", "140", "146", "150", "151", "156"} <= majors
    for b in builds:
        assert Path(b.executable_path).exists()
        assert b.os == "mac" and b.arch == "arm64"
        assert b.source in ("cft", "playwright")
```

- [ ] **Step 2: Run it, verify it fails** (module missing). `.venv/bin/python -m pytest tests/versionmap/test_chromium_builds.py -v`

- [ ] **Step 3: Implement `discover_chromium_builds`** — default `cache_dirs` to both `~/.cache/fingerprint-lab/chromium` (source "cft": each immediate child dir is a version) and the Playwright cache `~/Library/Caches/ms-playwright` (source "playwright": `chromium-<rev>` dirs; respect `PLAYWRIGHT_BROWSERS_PATH`). For each, resolve the executable under `chrome-mac-<arch>/Google Chrome for Testing.app/Contents/MacOS/...`; read product version via `subprocess.run([exe, "--version"])`; derive `os`/`arch` from the `chrome-mac-<arch>` dir name. Skip `*_headless_shell*` dirs. De-dupe by version (prefer "cft"). Return sorted by numeric version.

- [ ] **Step 4: Run test to verify it passes.**

- [ ] **Step 5: Commit** — `git commit -m "versionmap: discover installed Chromium builds"`

---

### Task 3: Corpus capture harness

**Files:**
- Create: `versionmap/corpus.py`
- Test: `tests/versionmap/test_corpus.py`

**Interfaces:**
- Consumes: `ChromiumBuild` (Task 2), `CaptureServer` (`capture.server`), `parse_client_hello` + `normalized_ext_key` (Task 1).
- Produces: `@dataclass CorpusEntry(family, version, os, arch, source, normalized_key, raw_ja4_samples: list[str], n: int, runnable: bool, stable: bool)` with `to_dict()`; `capture_build(server, build, n=10) -> CorpusEntry`; `build_corpus(builds, n, out_dir) -> list[CorpusEntry]` (starts its own server, dumps `corpus.json`). `capture_build` launches the binary **directly** `n` times (the fixed flag set from Global Constraints, each in its own process group, `os.killpg(SIGKILL)` cleanup, fresh `--user-data-dir`), computing `normalized_ext_key` per captured ClientHello. `runnable` is False (and `normalized_key=""`, `stable=False`) when **zero** ClientHellos were captured (OS-incompatible build). Otherwise `stable` is True iff all captured keys agree; `normalized_key` is the agreed value, or the modal value with `stable=False`. Module constant `LAUNCH_FLAGS` holds the fixed flag list.

- [ ] **Step 1: Write the failing integration test** — drive several installed builds; assert runnable builds are `stable` with a single `normalized_key`, that 146 and 151 keys differ, that the known range-pair 151/156 share a key, and that a non-runnable build (120) yields `runnable is False` without raising.

```python
@pytest.mark.integration
def test_capture_resolves_and_tolerates_dead_build(server, chromium_builds):
    e146 = capture_build(server, by_major(chromium_builds, "146"), n=5)
    e151 = capture_build(server, by_major(chromium_builds, "151"), n=5)
    e156 = capture_build(server, by_major(chromium_builds, "156"), n=5)
    assert e146.runnable and e146.stable
    assert e146.normalized_key != e151.normalized_key
    assert e151.normalized_key == e156.normalized_key          # 151/156 are a range
    e120 = capture_build(server, by_major(chromium_builds, "120"), n=2)
    assert e120.runnable is False and e120.normalized_key == ""  # OS-incompatible, no crash
```

Add a non-browser unit test for the reduction logic: extract a pure helper `reduce_keys(keys: list[str]) -> tuple[str, bool, bool]` returning `(normalized_key, runnable, stable)` and assert: empty → `("", False, False)`; all-agree → `(key, True, True)`; mixed → `(modal, True, False)`.

- [ ] **Step 2: Run tests, verify they fail.**

- [ ] **Step 3: Implement `corpus.py`** — direct `subprocess.Popen([exe, *LAUNCH_FLAGS, f"--user-data-dir={tmp}", url], start_new_session=True)`, wait (bounded, ~12s) for the server's record count to grow, then `os.killpg`. Select the ClientHello from the new record and compute its normalized key. Implement `reduce_keys`. `build_corpus` creates a temp cert (openssl, as `driver.main` does), starts `CaptureServer`, iterates builds, writes `corpus.json` via a dumper mirroring `capture.record.dump_run` (include `generated_at`, `recipe`, `launch_flags`, and the command). Do **not** import Playwright here.

- [ ] **Step 4: Run tests to verify pass** (`-m integration` and the unit test).

- [ ] **Step 5: Commit** — `git commit -m "versionmap: corpus capture harness with stability check"`

---

### Task 4: Build the version map

**Files:**
- Create: `versionmap/build_map.py`
- Test: `tests/versionmap/test_build_map.py`

**Interfaces:**
- Consumes: `CorpusEntry` (Task 3).
- Produces: `build_version_map(entries: list[CorpusEntry]) -> VersionMap`; `VersionMap` holds `entries_by_key: dict[str, list[MapEntry]]` and `granularity() -> dict` (counts of keys resolving to a single version vs a range, and the version span per collision); `dump_map(vmap, out_dir, metadata) -> None` writing `version_map.json`. `MapEntry` = `{family, version, os, arch, source}`. A key mapping to multiple distinct versions is a *range*, never overwritten.

- [ ] **Step 1: Write the failing tests** (pure, no browser):

```python
def test_single_version_key_resolves_exactly():
    vmap = build_version_map([entry("151", "k1"), entry("156", "k2")])
    assert vmap.granularity()["single_version_keys"] == 2
    assert vmap.resolve("k1") == [("chrome", "151", "mac", "arm64")]

def test_shared_key_becomes_range_not_overwrite():
    vmap = build_version_map([entry("150", "kX"), entry("151", "kX")])
    versions = {m.version for m in vmap.entries_by_key["kX"]}
    assert versions == {"150", "151"}                      # both retained
    assert vmap.granularity()["range_keys"] == 1

def test_dump_map_carries_os_arch_and_recipe(tmp_path):
    dump_map(build_version_map([entry("151", "k1")]), tmp_path,
             metadata={"recipe": "normalized-ext-key-v1", "os": "mac", "arch": "arm64"})
    doc = json.loads((tmp_path / "version_map.json").read_text())
    assert doc["metadata"]["os"] == "mac" and doc["metadata"]["recipe"]
    assert doc["keys"]["k1"][0]["arch"] == "arm64"
```

- [ ] **Step 2: Run tests, verify they fail.**

- [ ] **Step 3: Implement `build_map.py`** — group entries by `normalized_key`, dedupe `MapEntry` within a key, compute granularity, serialize with a top-level `metadata` block and a `keys` map. Keep it pure/deterministic (sorted output) so the artifact is diff-stable.

- [ ] **Step 4: Run tests to verify pass.**

- [ ] **Step 5: Commit** — `git commit -m "versionmap: build map with range handling and granularity report"`

---

### Task 5: Produce the real artifact + README

**Files:**
- Create: `versionmap/cli.py` (or extend as `python -m versionmap`)
- Create: `runs/<date>/version_map.json`, `runs/<date>/corpus.json`, `runs/<date>/README.md`
- Test: `tests/versionmap/test_cli.py`

**Interfaces:**
- Consumes: Tasks 2–4.
- Produces: a CLI `main(argv)` that discovers builds, captures the corpus (N per build), builds the map, and writes the three artifact files; returns 0.

- [ ] **Step 1: Write the failing test** — `@pytest.mark.integration`: run `main(["--out", str(tmp_path), "--n", "4"])`; assert `version_map.json`, `corpus.json`, `README.md` exist, the map JSON is valid schema with ≥3 distinct keys and at least one range key (a key with >1 version), carries `metadata.launch_flags`/`os`/`arch`, and the README contains the required section headings (`## Normalization recipe`, `## Stability finding`, `## Resolution granularity`, `## Scope and caveats`, `## Reproduce`).

- [ ] **Step 2: Run it, verify it fails.**

- [ ] **Step 3: Implement the CLI** and author `runs/<date>/README.md`. The README must state, in the researcher's voice: the normalization recipe and *why* each exclusion exists (the GREASE-in-sigalgs bug in naive JA4; resumption extensions); the raw-vs-normalized stability finding with measured numbers (Chrome 156: 25 raw keys → 1 normalized over 40 connections); the resolution granularity actually achieved (expected ≈4 keys over 6 runnable builds, with ranges 130–140 and 151–156); the scope (**Chrome/Chromium, macOS/arm64, 6 runnable builds**, Chrome 120 excluded as OS-incompatible) and that the key is valid only for the recorded **launch profile**; the explicit deferred caveats (multi-OS needs the author's own Windows/Linux VMs; public-dataset enrichment needs a license check); and the exact reproduce command. Every number in the README must come from the committed artifact, not prose.

- [ ] **Step 4: Run the CLI for real** to generate the committed artifact, then run the full suite. `.venv/bin/python -m versionmap --out runs/<date> --n 10 && .venv/bin/python -m pytest -q`

- [ ] **Step 5: Commit** — `git add versionmap tests/versionmap runs/<date> && git commit -m "versionmap: version-resolution map artifact + README"`

---

## Notes for the executor

- **Corpus browsers are already installed** (controller did this at setup, user-approved): 7 Chrome for Testing builds under `~/.cache/fingerprint-lab/chromium/` (120,130,140,146,150) and `~/Library/Caches/ms-playwright/` (151,156), de-quarantined. 6 run on this macOS; 120 is OS-incompatible and must be tolerated (a test case, not a failure). No further downloads needed.
- **The GREASE-sigalg fix changes the Phase 1 artifact's browser JA4_c.** After Task 1, the value in `runs/2026-10-25/phase1_capture.json` for `browser:chromium` was computed by the old (buggy) code. Do not silently rewrite history; note in the Phase 2 README that the Phase 1 artifact predates the fix. Re-running Phase 1 is out of scope here.
- **Launch-method matters:** the same Chrome 156 yields a different key under Playwright's automation flags vs the fixed direct-launch flags. The map is defined against the direct-launch profile recorded in metadata. Do not switch corpus capture to Playwright.
