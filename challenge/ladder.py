"""Defender ladder: three clients answer a fresh per-nonce challenge; each answer is
checked by exact match against the reference oracle browser on the same host."""
from __future__ import annotations

from challenge.clients import coherent_forger, engine_forger, honest_browser
from challenge.issue import make_challenge
from challenge.oracle import run_oracle
from challenge.verify import verify

LADDER: list[dict] = [
    {"name": "honest-browser", "client": honest_browser, "tls_layer": "real-chromium",
     "runs_engine": True, "expect_pass": True},
    {"name": "coherent-forger", "client": coherent_forger, "tls_layer": "curl_cffi",
     "runs_engine": False, "expect_pass": False},
    {"name": "engine-forger", "client": engine_forger, "tls_layer": "curl_cffi",
     "runs_engine": True, "expect_pass": True},
]


def run_ladder(server) -> list[dict]:
    rows = []
    for rung in LADDER:
        c = make_challenge()
        expected = run_oracle(server, c)
        got = rung["client"](server, c.seed)
        rows.append({"name": rung["name"], "tls_layer": rung["tls_layer"],
                     "runs_engine": rung["runs_engine"], "passed": verify(expected, got)})
    return rows
