import json
import re
from pathlib import Path

RUN = Path(__file__).resolve().parents[2] / "runs" / "2026-10-26-challenge"
HEADINGS = ("## The active challenge", "## Defender ladder", "## What this measures",
            "## Scope and ethics", "## Reproduce")


def _load():
    doc = json.loads((RUN / "challenge.json").read_text())
    return doc["rungs"], (RUN / "README.md").read_text()


def test_headings_in_order_and_no_banned_strings():
    _, readme = _load()
    pos = [readme.index(h) for h in HEADINGS]
    assert pos == sorted(pos)
    for banned in ("Claude", "Anthropic", "AI-generated"):
        assert banned not in readme


def test_every_rung_status_matches_json():
    rungs, readme = _load()
    for r in rungs:
        assert r["name"] in readme
        m = re.search(r"^\| %s \|.*\| (\w+) \|$" % re.escape(r["name"]), readme, re.M)
        assert m, r["name"]
        assert m.group(1) == ("passed" if r["passed"] else "CAUGHT")


def test_caught_set_in_prose_equals_json():
    rungs, readme = _load()
    line = re.search(r"^Caught: (.*)$", readme, re.M).group(1)
    named = {n.strip() for n in line.split(",") if n.strip() != "none"}
    assert named == {r["name"] for r in rungs if not r["passed"]}
    pline = re.search(r"^Passing: (.*)$", readme, re.M).group(1)
    assert {n.strip() for n in pline.split(",")} == {r["name"] for r in rungs if r["passed"]}
    assert "Rungs caught: %d of %d" % (len(named), len(rungs)) in readme.replace("\n", " ")
