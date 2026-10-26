"""Reference answer from a real browser engine."""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time

from challenge.issue import Challenge
from versionmap.chromium_builds import discover_chromium_builds
from versionmap.corpus import LAUNCH_FLAGS


def _vkey(b) -> tuple[int, ...]:
    return tuple(int(x) for x in b.version.split(".") if x.isdigit())


def browser_answer(server, nonce: str, seed: str, *, exe: str | None = None,
                   timeout: float = 12.0) -> str | None:
    """Register the challenge, load its page in a real browser, return the posted answer."""
    if exe is None:
        builds = discover_chromium_builds()
        if not builds:
            return None
        # Pin one deterministic build so every answer for a seed comes from the
        # same renderer. The first discovered build (120) never answers and
        # pre-140 builds render differently, so take the newest version.
        exe = max(builds, key=_vkey).executable_path
    server.register_challenge(nonce, seed)
    tmp = tempfile.mkdtemp(prefix="fplab-udd-")
    p = None
    try:
        try:
            p = subprocess.Popen(
                [exe, *LAUNCH_FLAGS, f"--user-data-dir={tmp}",
                 f"https://127.0.0.1:{server.port}/challenge/{nonce}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
        except OSError:
            return None
        end = time.time() + timeout
        while time.time() < end:
            ans = server.get_answer(nonce)
            if ans:
                return ans
            time.sleep(0.05)
        return server.get_answer(nonce)
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


def run_oracle(server, challenge: Challenge) -> str:
    ans = browser_answer(server, challenge.nonce, challenge.seed)
    if not ans:
        raise RuntimeError("oracle browser produced no answer")
    return ans
