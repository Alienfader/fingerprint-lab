from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Record:
    client_label: str | None = None
    client_addr: tuple | None = None
    tls: dict | None = None
    http2: dict | None = None
    http: dict | None = None
    js: dict | None = None
    captured_at: str | None = field(default_factory=_now)

    def to_dict(self) -> dict:
        """JSON-safe dict of every layer (client_addr tuple becomes a list)."""
        return {
            "client_label": self.client_label,
            "client_addr": list(self.client_addr) if self.client_addr is not None else None,
            "tls": self.tls,
            "http2": self.http2,
            "http": self.http,
            "js": self.js,
            "captured_at": self.captured_at,
        }


def _version(dist: str) -> str:
    from importlib import metadata
    try:
        return metadata.version(dist)
    except metadata.PackageNotFoundError:
        return "not installed"


def dump_run(records: list[Record], out_dir: str, command: str | None = None,
             filename: str = "records.json") -> None:
    """Write <filename> plus a README.md (environment + reproduce command)."""
    import json
    import platform
    import sys
    from pathlib import Path

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    data = [r.to_dict() for r in records]
    (out / filename).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    command = command or "python -m capture.driver --out %s" % out_dir
    rows = "\n".join("| `%s` | %s | %s |" % (
        d["client_label"], (d["tls"] or {}).get("ja4"),
        "yes" if d["js"] else "no") for d in data)
    readme = (
        "# Capture run\n\n"
        "Joined TLS / HTTP/2 / HTTP / JS records captured by the self-hosted capture "
        "server (`%s`).\n\n"
        "Environment: %s, Python %s, curl_cffi %s, tls_client %s, h2 %s, playwright %s.\n\n"
        "| Client | JA4 | JS layer |\n|--------|-----|----------|\n%s\n\n"
        "## Reproduce\n\n```\n%s\n```\n"
    ) % (filename, platform.platform(), platform.python_version(), _version("curl_cffi"),
         _version("tls_client"), _version("h2"), _version("playwright"), rows, command)
    (out / "README.md").write_text(readme, encoding="utf-8")
