"""Evasion ladder: each rung sets one self-reported tell; the real Phase 3
scorer says what still catches it."""
from __future__ import annotations

from crosslayer.scorer import score
from forger.coherent import build_payload, forge

# toggles=None means payload=None (naive, no JS). defeats is the contradiction
# code the rung is expected to still trip (None for the top rung).
LADDER: list[dict] = [
    {"name": "rung0 naive", "toggles": None, "defeats": "js_absent"},
    {"name": "rung1 js+webdriver", "toggles": {"webdriver": True}, "defeats": "webdriver_true"},
    {"name": "rung2 no-webdriver+swiftshader", "toggles": {"gpu": "swiftshader"}, "defeats": "headless_gpu"},
    {"name": "rung3 real-gpu+no-window-chrome", "toggles": {"window_chrome": False}, "defeats": "no_window_chrome"},
    {"name": "rung4 window-chrome+ua-mismatch", "toggles": {"ua_match": False}, "defeats": "js_ua_mismatch"},
    {"name": "rung5 fully-coherent", "toggles": {}, "defeats": None},
]


def run_ladder(server) -> list[dict]:
    rows = []
    for rung in LADDER:
        toggles = rung["toggles"]
        payload = None if toggles is None else build_payload(**toggles)
        v = score(forge(server, payload=payload))
        rows.append({
            "name": rung["name"],
            "toggles": toggles,
            "label": v.label,
            "confidence": v.confidence,
            "surviving_contradictions": [
                {"layer": c.layer, "code": c.code, "detail": c.detail, "severity": c.severity}
                for c in v.contradictions],
        })
    return rows
