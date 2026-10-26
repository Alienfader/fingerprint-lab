"""Drive the forgery population plus a real browser at the probe URL, score each
record with the cross-layer scorer, and write scores.json + README.md."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from capture.driver import (DEFAULT_CLIENTS, TIMEOUT, _curl, _stdlib, _tls, _wait,
                            run_drivers)
from capture.record import Record
from capture.server import CaptureServer
from crosslayer.scorer import score

POPULATION = list(DEFAULT_CLIENTS)
REPRODUCE = "python -m crosslayer --out runs/2026-10-26-crosslayer"
SPEC = "docs/superpowers/specs/2026-10-25-version-level-crosslayer-consistency-design.md"


def _drive_probe(server: CaptureServer, client: str) -> Record:
    """Drive a non-browser client at /probe/<nonce>; it never POSTs /collect, so js stays None."""
    kind, _, arg = client.partition(":")
    nonce = "cli-" + uuid.uuid4().hex[:12]
    url = "https://127.0.0.1:%d/probe/%s" % (server.port, nonce)
    before = set(server.records)
    if kind == "curl":
        _curl(url, arg)
    elif kind == "tls":
        _tls(url, arg)
    elif kind == "stdlib":
        _stdlib(url)
    else:
        raise ValueError("unknown client %r" % client)
    want = "/probe/" + nonce

    def new() -> list[Record]:
        return [server.records[k] for k in list(server.records)
                if k not in before and (server.records[k].http or {}).get("path") == want]

    if not _wait(lambda: bool(new()), TIMEOUT):
        raise RuntimeError("no record with path %s captured for %s" % (want, client))
    rec = new()[0]
    rec.client_label = client
    return rec


def _capture(clients: list[str]) -> list[Record]:
    with tempfile.TemporaryDirectory() as d:
        cert, key = str(Path(d) / "c.pem"), str(Path(d) / "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                        "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        srv = CaptureServer(cert, key)
        srv.start()
        try:
            out = []
            for c in clients:
                if c.partition(":")[0] in ("browser", "playwright"):
                    out.extend(run_drivers(srv, [c]))
                else:
                    out.append(_drive_probe(srv, c))
            return out
        finally:
            srv.stop()


def _row(rec: Record) -> dict:
    v = score(rec).to_dict()
    return {"client_label": rec.client_label, **v,
            "ja4_context_non_decisive": (rec.tls or {}).get("ja4")}


def _codes(row: dict) -> str:
    return ", ".join("%s/%s" % (c["layer"], c["code"]) for c in row["contradictions"]) or "none"


def render_readme(scores: dict) -> str:
    rows = scores["clients"]
    verdicts = "\n".join("| %s | %s | %s | %s |" % (r["client_label"], r["label"], r["confidence"], _codes(r))
                         for r in rows)
    layers = "\n".join(
        "| %s | %s | %s |" % (r["client_label"],
                              ", ".join(sorted({c["layer"] for c in r["contradictions"]})) or "none",
                              "; ".join("%s (%s): %s" % (c["code"], c["severity"], c["detail"])
                                        for c in r["contradictions"]) or "none")
        for r in rows)
    n = len(rows)
    n_auto = sum(r["label"] == "automated" for r in rows)
    js_absent = [r["client_label"] for r in rows if not r["observed"].get("js")]
    return f"""# Cross-layer scorer evaluation (2026-10-26)

I built a verdict that looks for contradictions between the TLS, HTTP/2, HTTP and
JavaScript layers of a single connection, and that ignores JA4 entirely. This
directory holds the artifact (`scores.json`) and my reading of it. Author: Thiago Goncalves.

## The JA4 result (why this scorer exists)

My earlier phases tried to resolve a browser version from the JA4 family. That did not
survive measurement. This is the motivating verified measurement (taken before this run,
not produced by it): curl_cffi `chrome124` and real Chrome 130 driven through Playwright
emit a byte-identical full JA4, `t13i1515h2_8daaf6152771_02713d6af862`. The normalized
extension key is dominated by the launch profile, so keys collide across versions. A
forger using curl_cffi is therefore indistinguishable from a real Chrome at the TLS layer
by JA4 alone. The details are in the "Phase 3 revision - 2026-10-26" section of
`{SPEC}`. For that reason the verdict here is JA4-free: `scores.json` carries each
client's JA4 only as non-decisive context, and it never enters the scorer.

## Per-client verdicts

{n_auto} of {n} clients scored automated. Every client was driven at `/probe/<nonce>`, so
JS absence is an observed signal rather than an artifact of which URL was hit.

| client | label | confidence | contradictions fired (layer/code) |
|---|---|---|---|
{verdicts}

## Detection by layer

The JS layer is the backbone: clients that fetch the probe HTML but never run its script
never POST `/collect`, so they have no JS layer ({", ".join(js_absent) or "none"} in this run).
The other layers catch clients that are inconsistent with their own claimed identity.

| client | layers with a contradiction | checks and details |
|---|---|---|
{layers}

## Scope and caveats

- The only "real browser" is headless Playwright Chromium. It legitimately reports
  `webdriver` and a SwiftShader GPU, so scoring it automated is the expected outcome, not a
  false positive I am excusing. The scorer's `real` path is exercised only by a synthetic
  coherent record in the unit tests.
- A headed-browser true-negative baseline is deferred.
- A coherent forger (Phase 4) that fixes all layers together is deferred; these five
  clients are naive or single-layer forgeries.
- Scope is desktop Chromium on macOS/arm64. iOS Chrome and WebKit-based browsers are out of
  scope; they would trip the now-strong client-hint checks.
- Small n ({n} clients, one run each). These are illustrations of which layer catches which
  forgery, not rates.

## Reproduce

```
{REPRODUCE}
```
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="runs/2026-10-26-crosslayer")
    ap.add_argument("--clients", default=",".join(POPULATION))
    a = ap.parse_args(argv)
    recs = _capture(a.clients.split(","))
    scores = {"command": "python -m crosslayer --out %s" % a.out,
              "note": "ja4 fields are non-decisive context; the verdict does not use JA4",
              "clients": [_row(r) for r in recs]}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "scores.json").write_text(json.dumps(scores, indent=2) + "\n")
    (out / "README.md").write_text(render_readme(scores))
    for r in scores["clients"]:
        print("%-18s %-10s %-6s %s" % (r["client_label"], r["label"], r["confidence"], _codes(r)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
