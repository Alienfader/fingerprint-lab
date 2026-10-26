"""Run the defender ladder on loopback and write challenge.json + README.md."""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from capture.server import CaptureServer
from challenge.ladder import run_ladder

DEFAULT_OUT = "runs/2026-10-26-challenge"
REPRODUCE = ".venv/bin/python -m challenge --out runs/2026-10-26-challenge"

_TEMPLATE = """# Active challenge vs. the coherent forger (2026-10-26)

Author: Thiago Goncalves.

## The active challenge

Phase 4 ended with a forger the passive scorer could not catch: curl_cffi `chrome124`
plus a fabricated 12-field JS payload scored `real` with zero contradictions, because every
Phase 3 check inspects values the client reports about itself. This phase stops asking the
client what it is and makes it prove it can run an engine.

For each probe the server issues a fresh nonce and a seed. The page must render a
seeded canvas/WebGL scene live and POST the resulting hash to `/answer`, joined to the
probe by nonce. The expected value comes from a reference oracle: the lab's own Chromium
build, launched on the same host against the same challenge. The verifier is an exact
string match, with no tolerance.

## Defender ladder

Each rung is given a fresh challenge. The oracle answers it first, then the rung does.

| client | tls layer | runs engine | challenge outcome |
|---|---|---|---|
{table}

These rows are generated from `challenge.json` on every run. Rungs caught: {caught_count} of
{total}. Rungs passing: {pass_count} of {total}.

Caught: {caught_names}

Passing: {pass_names}

## What this measures

The active challenge catches the rungs that cannot compute the render, and only those: here,
{caught_names}. A forger can fabricate self-reported values, but it cannot compute a per-nonce
seeded render without a real engine. In Phase 4 that same coherent forger scored `real`
against the passive scorer.

The honest residual is that a rung with a real engine behind a curl_cffi connection still
passes ({residual_names}). The real-Chromium baseline ({baseline_names}) passes by construction. The challenge does not make forging impossible. It raises the attacker
floor from "fabricate roughly 12 JSON fields" (Phase 4) to "run a real browser engine." That
is a real change in cost, but not a closed door.

The gap that remains is the join. The answer is tied to the probe by an application-level
nonce, not by the probe's TLS connection, so an engine can compute in one place and speak
from another. Binding the answer to the connection (channel binding) is the next arm.

## Scope and ethics

Self-only. Everything runs on loopback against my own detector, with browsers and clients I
launch myself. Nothing touches a third-party site.

Exact match is only defensible because rendering here is deterministic: software rendering
on one host, one browser build. The digest is Chromium-build-specific. That has two
consequences. The oracle and every client must use the same build, so the ladder passes no
explicit binary and all of them resolve the same newest one. It also shows the answer is
tied to the engine and version, which is another reason it cannot be produced without the
exact engine. Cross-GPU variance is a known caveat: on different hardware the same build
could render differently and exact match would need rethinking. This is a measurement of one
host, not a product.

## Reproduce

```
{command}
```

It launches real browsers and takes a few minutes. Outcomes are written to `challenge.json`.
"""


def render_readme(doc: dict) -> str:
    rows = doc["rungs"]
    table = "\n".join("| %s | %s | %s | %s |" % (
        r["name"], r["tls_layer"], "yes" if r["runs_engine"] else "no",
        "passed" if r["passed"] else "CAUGHT") for r in rows)
    caught = [r["name"] for r in rows if not r["passed"]]
    passing = [r["name"] for r in rows if r["passed"]]
    residual = [r["name"] for r in rows
                if r["passed"] and r["tls_layer"] == "curl_cffi" and r["runs_engine"]]
    baseline = [r["name"] for r in rows if r["passed"] and r["tls_layer"] != "curl_cffi"]
    return _TEMPLATE.format(
        residual_names=", ".join(residual) or "none",
        baseline_names=", ".join(baseline) or "none",
        table=table, total=len(rows), caught_count=len(caught), pass_count=len(passing),
        caught_names=", ".join(caught) or "none", pass_names=", ".join(passing) or "none",
        command=doc["command"])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=DEFAULT_OUT)
    a = ap.parse_args(argv)
    with tempfile.TemporaryDirectory() as d:
        cert, key = str(Path(d) / "c.pem"), str(Path(d) / "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                        "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        srv = CaptureServer(cert, key)
        srv.port = srv.start()
        try:
            rungs = run_ladder(srv)
        finally:
            srv.stop()
    doc = {"command": REPRODUCE.replace(DEFAULT_OUT, a.out), "rungs": rungs}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "challenge.json").write_text(json.dumps(doc, indent=2) + "\n")
    (out / "README.md").write_text(render_readme(doc))
    for r in rungs:
        print("%-16s %-14s engine=%-5s passed=%s" % (
            r["name"], r["tls_layer"], r["runs_engine"], r["passed"]))
    return 0
