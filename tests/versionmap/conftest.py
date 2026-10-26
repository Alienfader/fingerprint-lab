import subprocess

import pytest

from capture.server import CaptureServer
from versionmap.chromium_builds import discover_chromium_builds


@pytest.fixture
def server(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
         "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    srv = CaptureServer(str(cert), str(key))
    srv.port = srv.start()
    yield srv
    srv.stop()


@pytest.fixture(scope="session")
def chromium_builds():
    return discover_chromium_builds()


def by_major(builds, major):
    for b in builds:
        if b.version.split(".")[0] == major:
            return b
    pytest.skip("no Chromium %s build installed" % major)
