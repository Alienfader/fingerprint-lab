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
