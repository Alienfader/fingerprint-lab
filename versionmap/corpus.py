"""Capture one normalized TLS key per installed Chromium build."""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from capture.server import CaptureServer
from versionmap.chromium_builds import ChromiumBuild

LAUNCH_FLAGS = [
    "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
    "--no-default-browser-check", "--disable-background-networking",
    "--ignore-certificate-errors",
]
CAPTURE_TIMEOUT = 12.0


@dataclass
class CorpusEntry:
    family: str
    version: str
    os: str
    arch: str
    source: str
    normalized_key: str
    raw_ja4_samples: list[str] = field(default_factory=list)
    n: int = 0
    runnable: bool = False
    stable: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def reduce_keys(keys: list[str]) -> tuple[str, bool, bool]:
    """Return (normalized_key, runnable, stable) for the captured keys."""
    if not keys:
        return "", False, False
    modal = Counter(keys).most_common(1)[0][0]
    return modal, True, len(set(keys)) == 1


def _capture_once(server: CaptureServer, exe: str) -> tuple[str, str] | None:
    """Launch the browser once; return (ja4_norm, ja4) or None if no ClientHello."""
    before = set(server.records)
    tmp = tempfile.mkdtemp(prefix="fplab-udd-")
    p = None
    try:
        try:
            p = subprocess.Popen(
                [exe, *LAUNCH_FLAGS, f"--user-data-dir={tmp}",
                 f"https://127.0.0.1:{server.port}/"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
        except OSError:
            return None  # binary cannot exec at all: failed launch
        end = time.time() + CAPTURE_TIMEOUT
        while time.time() < end:
            for rid in list(server.records):
                if rid in before:
                    continue
                tls = server.records[rid].tls
                if tls and "ja4_norm" in tls:
                    return tls["ja4_norm"], tls["ja4"]
            time.sleep(0.05)
        return None
    finally:
        if p is not None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            try:
                p.wait(timeout=5)
            except Exception:
                pass
        shutil.rmtree(tmp, ignore_errors=True)


def capture_build(server: CaptureServer, build: ChromiumBuild, n: int = 10) -> CorpusEntry:
    keys: list[str] = []
    ja4s: list[str] = []
    for _ in range(n):
        got = _capture_once(server, build.executable_path)
        if got:
            keys.append(got[0])
            ja4s.append(got[1])
    key, runnable, stable = reduce_keys(keys)
    return CorpusEntry(
        family="chromium", version=build.version, os=build.os, arch=build.arch,
        source=build.source, normalized_key=key, raw_ja4_samples=ja4s, n=n,
        runnable=runnable, stable=stable)


def dump_corpus(entries: list[CorpusEntry], out_dir: str, command: str,
                filename: str = "corpus.json") -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    doc = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "recipe": "direct-launch chromium, normalized ClientHello key",
        "launch_flags": LAUNCH_FLAGS,
        "command": command,
        "entries": [e.to_dict() for e in entries],
    }
    (out / filename).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def build_corpus(builds: list[ChromiumBuild], n: int, out_dir: str,
                 command: str | None = None) -> list[CorpusEntry]:
    with tempfile.TemporaryDirectory() as d:
        cert, key = str(Path(d) / "c.pem"), str(Path(d) / "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                        "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        srv = CaptureServer(cert, key)
        srv.port = srv.start()
        try:
            entries = [capture_build(srv, b, n) for b in builds]
        finally:
            srv.stop()
    dump_corpus(entries, out_dir,
                command or "python -m versionmap --out %s --n %d" % (out_dir, n))
    return entries
