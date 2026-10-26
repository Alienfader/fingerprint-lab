import json

import pytest

from challenge.cli import main


@pytest.mark.integration
def test_cli_writes_artifact(tmp_path):
    assert main(["--out", str(tmp_path)]) == 0
    doc = json.loads((tmp_path / "challenge.json").read_text())
    byname = {r["name"]: r for r in doc["rungs"]}
    assert byname["coherent-forger"]["passed"] is False
    readme = (tmp_path / "README.md").read_text()
    for h in ("## The active challenge", "## Defender ladder", "## What this measures",
              "## Scope and ethics", "## Reproduce"):
        assert h in readme
    for banned in ("Claude", "Anthropic", "AI-generated"):
        assert banned not in readme
