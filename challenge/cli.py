"""Run the defender ladder on loopback and write challenge.json (+ README.md when
one is not already authored)."""
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

_HEADINGS = ("## The active challenge", "## Defender ladder", "## What this measures",
             "## Scope and ethics", "## Reproduce")


def render_readme(doc: dict) -> str:
    rows = doc["rungs"]
    table = "\n".join("| %s | %s | %s | %s |" % (
        r["name"], r["tls_layer"], "yes" if r["runs_engine"] else "no",
        "passed" if r["passed"] else "CAUGHT") for r in rows)
    caught = [r["name"] for r in rows if not r["passed"]]
    return "# Active challenge\n\nAuthor: Thiago Goncalves.\n\n" + "\n\n".join(
        "%s\n\nSee the authored write-up." % h for h in _HEADINGS) + (
        "\n\n| client | tls | engine | outcome |\n|---|---|---|---|\n%s\n\nCaught: %s\n\n"
        "    %s\n" % (table, ", ".join(caught) or "none", doc["command"]))


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
    readme = out / "README.md"
    if not readme.exists():
        readme.write_text(render_readme(doc))
    for r in rungs:
        print("%-16s %-14s engine=%-5s passed=%s" % (
            r["name"], r["tls_layer"], r["runs_engine"], r["passed"]))
    return 0
