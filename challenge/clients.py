"""Answer-producing clients the defender ladder runs against a challenge."""
from __future__ import annotations

import uuid

from curl_cffi import requests as creq

from challenge.oracle import browser_answer
from forger.coherent import build_payload, forge


def _nonce() -> str:
    return "chl" + uuid.uuid4().hex[:12]


def honest_browser(server, seed: str) -> str | None:
    return browser_answer(server, _nonce(), seed)


def coherent_forger(server, seed: str) -> str | None:
    """The Phase 4 forger (no JS engine) facing the active challenge."""
    nonce = _nonce()
    server.register_challenge(nonce, seed)
    forge(server, payload=build_payload())
    return server.get_answer(nonce)


def engine_forger(server, seed: str) -> str | None:
    """Digest computed by a real engine on a throwaway nonce, relayed over curl_cffi."""
    digest = browser_answer(server, _nonce(), seed)
    n2 = _nonce()
    server.register_challenge(n2, seed)
    if digest:
        creq.post(f"https://127.0.0.1:{server.port}/answer/{n2}", data=digest,
                  impersonate="chrome124", verify=False, timeout=10)
    return server.get_answer(n2)
