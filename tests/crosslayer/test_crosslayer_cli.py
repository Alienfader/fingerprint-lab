import json

import pytest

from crosslayer.cli import main


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
    assert "Claude" not in readme and "Anthropic" not in readme
