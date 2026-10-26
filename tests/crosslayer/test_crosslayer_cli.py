import json

import pytest

from crosslayer.cli import DEFAULT_OUT, main, render_readme

COLLISION = "t13i1515h2_8daaf6152771_02713d6af862"
HEADINGS = ["## The JA4 result (why this scorer exists)", "## Per-client verdicts",
            "## Detection by layer", "## Scope and caveats", "## Reproduce"]


def _check_honesty(text):
    assert COLLISION in text
    for s in ("iOS Chrome", "headless", "deferred", "baseline", "Thiago Goncalves"):
        assert s in text, s
    for bad in ("Claude", "Anthropic", "AI-generated"):
        assert bad not in text, bad


def test_default_out_constant():
    assert DEFAULT_OUT == "runs/2026-10-26-crosslayer"


def test_render_readme_fixture():
    scores = {"clients": [{
        "client_label": "curl:x", "label": "automated", "confidence": "medium",
        "contradictions": [{"layer": "js", "code": "js_absent", "detail": "d", "severity": "strong"}],
        "observed": {"tls": True, "http2": True, "http": True, "js": False},
        "ja4_context_non_decisive": "x"}]}
    text = render_readme(scores)
    for h in HEADINGS:
        assert h in text
    _check_honesty(text)


def test_empty_clients_rejected(capsys):
    assert main(["--clients", " , "]) == 1
    assert "empty" in capsys.readouterr().err


@pytest.mark.integration
def test_cli_end_to_end(tmp_path):
    assert main(["--out", str(tmp_path)]) == 0
    scores = json.loads((tmp_path / "scores.json").read_text())
    by = {s["client_label"]: s for s in scores["clients"]}
    assert len(by) == 5
    for label, s in by.items():
        if not label.startswith("browser:"):
            assert s["label"] == "automated", label
    assert by["browser:chromium"]["observed"]["js"] is True
    assert by["curl:chrome124"]["observed"]["js"] is False
    readme = (tmp_path / "README.md").read_text()
    for h in ["## The JA4 result (why this scorer exists)", "## Per-client verdicts",
              "## Detection by layer", "## Scope and caveats", "## Reproduce"]:
        assert h in readme
    _check_honesty(readme)
    assert "ja4" in scores["note"].lower() and "non-decisive" in scores["note"]
    assert all("ja4_context_non_decisive" in c for c in scores["clients"])
