"""Run the evasion ladder against the Phase 3 scorer on loopback and write
ladder.json (+ README.md when one is not already authored)."""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from capture.server import CaptureServer
from forger.ladder import run_ladder

DEFAULT_OUT = "runs/2026-10-26-forger"
REPRODUCE = ".venv/bin/python -m forger --out runs/2026-10-26-forger"


def _codes(row: dict) -> str:
    return ", ".join(c["code"] for c in row["surviving_contradictions"]) or "none"


def render_readme(doc: dict) -> str:
    rows = doc["rungs"]
    table = "\n".join("| %s | %s | %s | %s |" % (r["name"], r["label"], r["confidence"], _codes(r))
                      for r in rows)
    caught = [r for r in rows if r["label"] != "real"]
    top = rows[-1]
    return f"""# Coherent forger vs. the cross-layer scorer (2026-10-26)

Author: Thiago Goncalves.

## The attack

Phase 3 ended with one forger the scorer caught only through JS absence: curl_cffi
`chrome124`, which matches Chrome byte for byte at JA4, Akamai HTTP/2 and headers. This
phase asks what happens when that forger also supplies the JS layer. It does a normal
`GET /probe/<nonce>` with curl_cffi, then POSTs a hand-fabricated 12-field payload to
`/collect/<nonce>`. The server joins the two by nonce. That join is application-level and
is not bound to the TLS connection, so the fabricated payload attaches to the genuine
curl_cffi handshake.

## Evasion ladder

Each rung sets exactly one self-reported tell (rung 0 sends no JS at all) and is scored by
the unmodified Phase 3 scorer. {len(caught)} of {len(rows)} rungs scored non-real.

| rung | scorer label | confidence | surviving contradictions |
|---|---|---|---|
{table}

Every non-top rung is caught by the contradiction it was built to trip, and only that one.
The top rung neutralizes all of them together and scores `{top["label"]}` with
`{top["confidence"]}` confidence and {len(top["surviving_contradictions"])} contradictions.

## What this measures

The scorer catches this forger for as long as at least one self-reported JS value is
off. Every Phase 3 check inspects values the client reports about itself, so the checks
form a finite, enumerable list. A forger that reports coherent values for all of them
exhausts the list, and passive cross-layer consistency has nothing left to fire on. The
measured attacker cost is an impersonation library, about twelve coherent JS fields and a
two-request nonce replay. The asymmetry favors the attacker: the defender maintains the
checks and the forger only has to satisfy them once.

## Scope and ethics

This is self-only. It runs on loopback against my own capture server and my own scorer.
It measures my detector's limits and is not a reusable evasion product: it targets no
third-party service, and the payload is shaped to this lab's probe schema. The result
motivates the next defender move, active challenge-response, where the server asks for
something a replayed or fabricated report cannot answer.

## Reproduce

```
{REPRODUCE}
```
"""


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
    (out / "ladder.json").write_text(json.dumps(doc, indent=2) + "\n")
    (out / "README.md").write_text(render_readme(doc))
    for r in rungs:
        print("%-34s %-10s %-6s %s" % (r["name"], r["label"], r["confidence"], _codes(r)))
    return 0
