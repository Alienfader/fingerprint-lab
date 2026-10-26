"""Discover Chrome for Testing builds installed on this machine."""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

_APP = "Google Chrome for Testing.app"
_EXE = Path("Contents") / "MacOS" / "Google Chrome for Testing"
_PLATFORM_RE = re.compile(r"^chrome-(mac)-(.+)$")


@dataclass
class ChromiumBuild:
    version: str
    os: str
    arch: str
    executable_path: str
    source: str  # "cft" or "playwright"


def _default_cache_dirs() -> list[str]:
    pw = os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or str(
        Path.home() / "Library" / "Caches" / "ms-playwright"
    )
    return [str(Path.home() / ".cache" / "fingerprint-lab" / "chromium"), pw]


def _resolve_executable(build_dir: Path) -> tuple[Path, str, str] | None:
    for child in sorted(build_dir.iterdir()):
        m = _PLATFORM_RE.match(child.name)
        if not m:
            continue
        exe = child / _APP / _EXE
        if exe.is_file():
            return exe, m.group(1), m.group(2)
    return None


def _product_version(exe: Path) -> str | None:
    try:
        proc = subprocess.run(
            [str(exe), "--version"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    tokens = proc.stdout.split()
    if tokens and re.match(r"^\d+(\.\d+)+$", tokens[-1]):
        return tokens[-1]
    return None


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split(".") if p.isdigit())


def discover_chromium_builds(cache_dirs: list[str] | None = None) -> list[ChromiumBuild]:
    dirs = cache_dirs if cache_dirs is not None else _default_cache_dirs()
    found: dict[str, ChromiumBuild] = {}
    for cache in dirs:
        root = Path(cache).expanduser()
        if not root.is_dir():
            continue
        for d in sorted(root.iterdir()):
            if not d.is_dir():
                continue
            if "headless_shell" in d.name or d.name.startswith("ffmpeg"):
                continue
            if d.name.startswith("chromium-"):
                source = "playwright"
            elif d.name.startswith("chromium"):
                continue
            elif re.match(r"^\d+(\.\d+)+$", d.name):
                source = "cft"
            else:
                continue
            resolved = _resolve_executable(d)
            if resolved is None:
                continue
            exe, os_name, arch = resolved
            version = _product_version(exe)
            if not version:
                continue
            existing = found.get(version)
            if existing is not None and not (
                existing.source != "cft" and source == "cft"
            ):
                continue
            found[version] = ChromiumBuild(version, os_name, arch, str(exe), source)
    return sorted(found.values(), key=lambda b: _version_key(b.version))
