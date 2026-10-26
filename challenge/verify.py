from __future__ import annotations


def verify(expected: str | None, got: str | None) -> bool:
    """True iff both answers are non-empty and exactly equal."""
    return bool(expected) and bool(got) and expected == got
