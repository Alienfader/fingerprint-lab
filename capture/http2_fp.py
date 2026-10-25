"""Akamai-style HTTP/2 fingerprint: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order."""
from __future__ import annotations

import hashlib


def akamai_fingerprint(settings: list[tuple[int, int]], window_update: int | None,
                       priorities: list, pseudo_header_order: list[str]) -> tuple[str, str]:
    """Return (akamai_string, sha256_hexdigest).

    priorities: iterable of (stream_id, exclusive, depends_on, weight).
    """
    seg_settings = ";".join(f"{i}:{v}" for i, v in settings)
    seg_window = "00" if window_update is None else str(window_update)
    seg_prio = ",".join(f"{s}:{int(bool(e))}:{d}:{w}" for s, e, d, w in priorities) or "0"
    seg_pseudo = ",".join(pseudo_header_order)
    s = "|".join((seg_settings, seg_window, seg_prio, seg_pseudo))
    return s, hashlib.sha256(s.encode()).hexdigest()
