import subprocess
import time

import pytest

from capture.server import CaptureServer


@pytest.fixture
def certpair(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
         "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return str(cert), str(key)


@pytest.fixture
def server(certpair):
    srv = CaptureServer(*certpair)
    port = srv.start()
    srv.port = port
    yield srv
    srv.stop()


def wait_for(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False
