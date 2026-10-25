# Phase 1: Self-Hosted Joined-Capture Server — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A local-only server that, per client connection, records one joined fingerprint record spanning the TLS (JA3/JA4), HTTP/2, HTTP-header, and JS/GPU layers.

**Architecture:** A plain TCP listener peeks the ClientHello with `MSG_PEEK` (non-consuming, no privilege), computes JA3/JA4 from it, then hands the untouched socket to stdlib `ssl` so the real handshake completes on the same connection. Over that TLS connection the server speaks HTTP/2 (ALPN `h2`, via the `h2` library) or HTTP/1.1, records the HTTP/2 (Akamai) fingerprint, header order, and client hints, and — for browsers — serves a JS/GPU probe page whose POSTed results are joined back to the connection by a nonce. All four approaches were validated in throwaway spikes before this plan.

**Tech Stack:** Python (repo `.venv`), stdlib `socket`/`ssl`, the `h2` library for HTTP/2, `curl_cffi` + `tls_client` + Playwright (already present) as driver clients.

**Spec:** `docs/superpowers/specs/2026-10-25-version-level-crosslayer-consistency-design.md` (Phase 1).

## Global Constraints

- Python 3 on the repo's `.venv`; stdlib-first, except `h2` (new dependency, required for the HTTP/2 fingerprint) added to the lock file.
- The server binds `127.0.0.1` only and is never exposed publicly — it captures only the researcher's own clients. No third-party or volunteer traffic, ever.
- No root / no raw sockets (the `MSG_PEEK` approach needs neither).
- JA4 is computed per the FoxIO JA4 spec: GREASE values excluded; JA4_a counts all non-GREASE extensions (including SNI and ALPN); JA4_c excludes SNI (`0x0000`) and ALPN (`0x0010`), sorts the remaining extensions, and appends signature algorithms in order after a `_`.
- Every run writes a reproducible artifact under `runs/<date>/`, matching the existing repo pattern.
- Attribution: the researcher's name only (no AI-tool attribution) in any commit or file.
- Deliberate changes logged to Continuity per the repo operating contract.

## Review Focus

- **ClientHello split across TCP segments:** the peek loop must keep reading until it has the full record (`5 + length`), or JA4 is computed on a truncated hello. → Task 2.
- **GREASE in ciphers/extensions:** must be excluded from counts and hashes, or JA4 is wrong and unstable. → Task 1.
- **Non-browser client (no JS layer):** the join must not block waiting for a probe POST that never arrives; the record marks the JS layer absent after a timeout. → Task 5.
- **Concurrent connections:** records are keyed per connection; two clients at once must not cross-contaminate layers. → Task 2 / Task 6.
- **Client completes TLS but sends no HTTP (or never completes handshake):** the server still records the captured TLS layer and cleans the connection up on timeout. → Task 2.

---

### Task 1: TLS ClientHello parser + JA3/JA4

**Files:**
- Create: `capture/__init__.py`, `capture/ja4.py`
- Test: `tests/capture/test_ja4.py`, fixture `tests/capture/fixtures/chrome124_clienthello.bin`

**Interfaces:**
- Produces:
  - `parse_client_hello(rec: bytes) -> ClientHello` where `ClientHello` is a dataclass with `legacy_ver: int`, `ciphers: list[int]`, `exts: list[int]`, `sni: bool`, `alpns: list[str]`, `sigalgs: list[int]`, `sup_vers: list[int]`.
  - `compute_ja4(ch: ClientHello) -> str`
  - `compute_ja3(ch: ClientHello) -> tuple[str, str]` (ja3 string, md5 hash)
  - `GREASE: frozenset[int]`

- [ ] **Step 1: Create the fixture.** Capture one real `chrome124` ClientHello to `tests/capture/fixtures/chrome124_clienthello.bin` (a known-good hello; its JA4 is `t13d1516h2_8daaf6152771_02713d6af862`, established by spike against the peet.ws oracle).

- [ ] **Step 2: Write the failing tests**

```python
def test_compute_ja4_matches_oracle():
    ch = parse_client_hello(FIXTURE_BYTES)
    assert compute_ja4(ch) == "t13d1516h2_8daaf6152771_02713d6af862"

def test_grease_excluded_from_counts():
    ch = parse_client_hello(FIXTURE_BYTES)
    assert all(c not in GREASE for c in ch.ciphers_nongrease)  # helper or inline filter

def test_ja4_a_fields():
    ch = parse_client_hello(FIXTURE_BYTES)
    a = compute_ja4(ch).split("_")[0]
    assert a == "t13d1516h2"   # TLS1.3, SNI present, 15 ciphers, 16 exts, h2
```

- [ ] **Step 3: Run tests, verify they fail** — Run: `.venv/bin/python -m pytest tests/capture/test_ja4.py -v` → FAIL (module/function missing).

- [ ] **Step 4: Implement `capture/ja4.py`** — port the validated parser and JA4/JA3 computation from the spike (`parse_client_hello`, `compute_ja4`, add `compute_ja3`). JA3 string = `version,ciphers,extensions,curves,point_formats` (dash-joined, GREASE excluded), md5 of it.

- [ ] **Step 5: Run tests, verify they pass** — Run: `.venv/bin/python -m pytest tests/capture/test_ja4.py -v` → PASS.

- [ ] **Step 6: Commit** — `git add capture/ tests/capture/ && git commit -m "capture: TLS ClientHello parser + JA3/JA4"`

---

### Task 2: Non-consuming capture + TLS termination

**Files:**
- Create: `capture/server.py`
- Test: `tests/capture/test_server_tls.py`

**Interfaces:**
- Consumes: `capture.ja4` (Task 1).
- Produces:
  - `class CaptureServer` with `__init__(self, certfile: str, keyfile: str, host: str = "127.0.0.1", port: int = 0)`, `start() -> int` (returns bound port, serves in a background thread), `stop()`, and `records: dict[str, Record]` keyed by a per-connection id.
  - A partial `Record` (dict/dataclass) with at least `tls: {ja3, ja4, ja4_raw?}` and `client_addr` filled after a connection.

- [ ] **Step 1: Write the failing tests**

```python
def test_captures_ja4_and_completes_handshake():
    srv = CaptureServer(CERT, KEY); port = srv.start()
    r = curl_cffi.get(f"https://localhost:{port}/x", impersonate="chrome124", verify=False)
    srv.stop()
    assert r.status_code == 200
    rec = only_record(srv)
    assert rec.tls["ja4"] == "t13d1516h2_8daaf6152771_02713d6af862"

def test_partial_clienthello_across_segments():
    # feed a ClientHello in two writes with a delay; JA4 still correct
    ...

def test_handshake_timeout_records_nothing_but_cleans_up():
    # open TCP, send no bytes; server times out, no crash, connection closed
    ...

def test_two_concurrent_clients_do_not_cross_contaminate():
    # chrome124 and safari17_0 at once -> two records, each its own JA4
    ...
```

- [ ] **Step 2: Run tests, verify they fail** — Run: `.venv/bin/python -m pytest tests/capture/test_server_tls.py -v` → FAIL.

- [ ] **Step 3: Implement `CaptureServer`** — accept loop in a thread; per connection: `recv(.., MSG_PEEK)` until the full record is buffered (loop on length), `parse_client_hello` + `compute_ja4`/`compute_ja3`, store under a new connection id, then `ssl_context.wrap_socket(conn, server_side=True)` (ALPN offering `h2`,`http/1.1`) and hand off to the HTTP handler (a minimal HTTP/1.1 200 for now; Task 3 adds HTTP/2). Per-connection state only; timeouts on peek and on the handshake; always close.

- [ ] **Step 4: Run tests, verify they pass** — Run: `.venv/bin/python -m pytest tests/capture/test_server_tls.py -v` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "capture: peek+continue TLS-terminating server"`

---

### Task 3: HTTP/2 (Akamai) fingerprint capture

**Files:**
- Create: `capture/http2_fp.py`
- Modify: `capture/server.py` (dispatch to HTTP/2 when ALPN negotiated `h2`)
- Modify: `handoff/requirements-lock.txt` equivalent / repo lock (add `h2`)
- Test: `tests/capture/test_http2_fp.py`

**Interfaces:**
- Consumes: Task 2's server + connection.
- Produces:
  - `akamai_fingerprint(settings: list[tuple[int,int]], window_update: int|None, priorities: list, pseudo_header_order: list[str]) -> tuple[str, str]` returning the Akamai string (`"settings|window|priority|pseudo-order"`) and its sha256 hash.
  - The server fills `record.http2 = {akamai, akamai_hash, alpn}` for `h2` connections.

- [ ] **Step 1: Write the failing tests**

```python
def test_akamai_string_format():
    s, h = akamai_fingerprint([(1,65536),(4,131072)], 15663105, [], ["m","a","s","p"])
    assert s.count("|") == 3 and len(h) == 64

def test_server_records_http2_matches_oracle():
    # chrome124 over h2 to our server; akamai_hash == peet.ws akamai_hash same run
    ...   # network/integration test, marked @pytest.mark.integration
```

- [ ] **Step 2: Run tests, verify they fail** — Run: `.venv/bin/python -m pytest tests/capture/test_http2_fp.py -v` → FAIL.

- [ ] **Step 3: Add `h2` to the lockfile and `.venv`**, implement `capture/http2_fp.py` using `h2.connection.H2Connection` server-side: capture the client SETTINGS frame values, the initial WINDOW_UPDATE increment, any PRIORITY frames, and the pseudo-header order from the first HEADERS; format per the Akamai spec; wire it into `server.py` for `h2` connections (serve a 200 so the client completes).

- [ ] **Step 4: Run tests, verify they pass** — Run: `.venv/bin/python -m pytest tests/capture/test_http2_fp.py -v` (unit) and `-m integration` when online → PASS.

- [ ] **Step 5: Commit** — `git commit -am "capture: HTTP/2 Akamai fingerprint"`

---

### Task 4: HTTP header-order + client-hints capture

**Files:**
- Modify: `capture/server.py`
- Test: `tests/capture/test_headers.py`

**Interfaces:**
- Produces: the server fills `record.http = {header_order: list[str], client_hints: dict[str,str], user_agent: str}` for every request (h1 and h2).

- [ ] **Step 1: Write the failing test**

```python
def test_header_order_and_client_hints_recorded():
    # a request with Sec-CH-UA set -> record preserves the on-the-wire order
    # and captures user_agent + any sec-ch-* headers
    ...
```

- [ ] **Step 2: Run test, verify it fails** — `.venv/bin/python -m pytest tests/capture/test_headers.py -v` → FAIL.

- [ ] **Step 3: Implement** — record the request header names in received order (h1: raw request line parse; h2: HEADERS order from `h2` events), split out `sec-ch-*` into `client_hints`, capture `user-agent`.

- [ ] **Step 4: Run test, verify it passes** — → PASS.

- [ ] **Step 5: Commit** — `git commit -am "capture: HTTP header order + client hints"`

---

### Task 5: JS/GPU probe page + join-by-nonce

**Files:**
- Create: `capture/probe.py` (serves the probe HTML + JS), `capture/static/probe.js`
- Modify: `capture/server.py` (routes `/probe/<nonce>` and `POST /collect/<nonce>`)
- Test: `tests/capture/test_probe_join.py`

**Interfaces:**
- Consumes: the `browser_fp.py` probe JS (reuse the existing in-page collection of `navigator.webdriver`, UA, plugins, `window.chrome`, permissions check, WebGL, canvas hash).
- Produces: the server fills `record.js = {...}` for the connection whose nonce matches; records with no POST within a timeout get `record.js = None`.

- [ ] **Step 1: Write the failing tests**

```python
def test_browser_probe_joins_to_connection():
    # Playwright Chromium loads https://localhost:port/probe/<nonce>;
    # server joins its POSTed JS record to the same connection's TLS record
    ...  # integration

def test_non_browser_client_records_js_none_after_timeout():
    # curl_cffi hits /probe/<nonce> but runs no JS -> record.js is None, no hang
    ...
```

- [ ] **Step 2: Run tests, verify they fail** — → FAIL.

- [ ] **Step 3: Implement** — `/probe/<nonce>` serves HTML embedding `probe.js` (adapted from `browser_fp.py`); the JS POSTs its JSON to `/collect/<nonce>`; the server matches `nonce` to the connection that requested `/probe/<nonce>` and fills `record.js`; a bounded wait marks `js=None` for clients that never POST.

- [ ] **Step 4: Run tests, verify they pass** — → PASS.

- [ ] **Step 5: Commit** — `git commit -am "capture: JS/GPU probe + nonce join"`

---

### Task 6: Joined record schema + run dumper + driver harness

**Files:**
- Create: `capture/record.py`, `capture/driver.py`
- Test: `tests/capture/test_record.py`, `tests/capture/test_driver.py`

**Interfaces:**
- Consumes: `CaptureServer` and its `records` (Tasks 2–5).
- Produces:
  - `@dataclass Record` with `client_label, client_addr, tls, http2, http, js, captured_at` and `to_dict()`.
  - `dump_run(records: list[Record], out_dir: str) -> None` writing `records.json` + a `README.md` (environment + command), matching the `runs/<date>/` pattern.
  - `run_drivers(server_port: int, clients: list[str]) -> list[Record]` driving curl_cffi profiles, tls_client, a Playwright browser, and stdlib at the server and returning their joined records.

- [ ] **Step 1: Write the failing tests**

```python
def test_record_roundtrips_all_layers():
    rec = Record(client_label="chrome124", tls={...}, http2={...}, http={...}, js={...})
    d = rec.to_dict()
    assert set(d) >= {"tls","http2","http","js","client_label"}

def test_driver_produces_one_record_per_client():
    recs = run_drivers(port, ["curl:chrome124", "tls:chrome_150", "stdlib:urllib"])
    assert len(recs) == 3 and all(r.tls["ja4"] for r in recs)
```

- [ ] **Step 2: Run tests, verify they fail** — → FAIL.

- [ ] **Step 3: Implement** `record.py` (schema + `dump_run`) and `driver.py` (`run_drivers`, reusing `ja3_diff.py` client plumbing; the browser client via Playwright hitting `/probe/<nonce>`).

- [ ] **Step 4: Run tests, verify they pass** — → PASS.

- [ ] **Step 5: Produce a real artifact** — Run the driver against a live server and write `runs/<today>/phase1_capture.json` + README; confirm one joined record per client with a populated `tls` layer (and `js` for the browser).

- [ ] **Step 6: Commit** — `git add capture/ tests/capture/ runs/ && git commit -m "capture: joined record schema + run dumper + driver"`
