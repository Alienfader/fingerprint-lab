from pathlib import Path

import pytest

from versionmap.chromium_builds import discover_chromium_builds


@pytest.mark.integration
def test_discovers_installed_chromium_builds():
    builds = discover_chromium_builds()
    majors = {b.version.split(".")[0] for b in builds}
    assert {"130", "140", "146", "150", "151", "156"} <= majors
    for b in builds:
        assert Path(b.executable_path).exists()
        assert b.os == "mac" and b.arch == "arm64"
        assert b.source in ("cft", "playwright")


def _make_build(root, dirname, output, exit_code=0):
    exe = (
        root / dirname / "chrome-mac-arm64" / "Google Chrome for Testing.app"
        / "Contents" / "MacOS" / "Google Chrome for Testing"
    )
    exe.parent.mkdir(parents=True)
    exe.write_text(f"#!/bin/sh\necho '{output}'\nexit {exit_code}\n")
    exe.chmod(0o755)
    return exe


def test_discover_synthetic_cache(tmp_path):
    cft = tmp_path / "cft"
    pw = tmp_path / "pw"
    _make_build(cft, "9.0.1.2", "Google Chrome for Testing 9.0.1.2")
    _make_build(cft, "10.0.1.2", "Google Chrome for Testing 10.0.1.2")
    _make_build(cft, "120.0.1.2", "Google Chrome for Testing 120.0.1.2")
    _make_build(cft, "130.0.1.2", "Google Chrome for Testing 130.0.1.2")
    _make_build(pw, "chromium-1234", "Google Chrome for Testing 130.0.1.2")
    _make_build(pw, "chromium-1300", "Google Chrome for Testing 131.0.1.2")
    _make_build(pw, "chromium_headless_shell-1234", "Google Chrome for Testing 140.0.1.2")
    _make_build(pw, "ffmpeg-1011", "Google Chrome for Testing 141.0.1.2")
    _make_build(pw, "chromium-1400", "garbage output here", 0)
    _make_build(pw, "chromium-1500", "Google Chrome for Testing 150.0.1.2", 1)
    missing = tmp_path / "does-not-exist"

    builds = discover_chromium_builds([str(missing), str(cft), str(pw)])

    assert [b.version for b in builds] == [
        "9.0.1.2", "10.0.1.2", "120.0.1.2", "130.0.1.2", "131.0.1.2",
    ]
    by_version = {b.version: b for b in builds}
    assert by_version["130.0.1.2"].source == "cft"
    assert by_version["131.0.1.2"].source == "playwright"
    assert by_version["120.0.1.2"].source == "cft"
    for b in builds:
        assert b.os == "mac" and b.arch == "arm64"
        assert Path(b.executable_path).exists()
