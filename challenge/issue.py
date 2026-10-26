"""Issue seeded canvas/WebGL challenges and render the page that answers them.

The page renders a seed-parameterised 2D canvas and a seed-parameterised WebGL
clear colour, hashes ``canvas.toDataURL() + "|" + <gl pixels>`` with
``crypto.subtle`` SHA-256, and POSTs the hex digest back to the same origin at
``/answer/<nonce>``.
"""

from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class Challenge:
    nonce: str
    seed: str


def make_challenge() -> Challenge:
    return Challenge(nonce="chl" + uuid.uuid4().hex[:12], seed=secrets.token_hex(16))


_PAGE_TEMPLATE = """<!doctype html>
<meta charset="utf-8">
<title>challenge</title>
<body><script>
(async () => {
  const seed = __SEED__;
  const answerUrl = __ANSWER_URL__;
  const c = document.createElement('canvas'); c.width = 200; c.height = 60;
  const x = c.getContext('2d');
  let h = 0; for (const ch of seed) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  x.fillStyle = '#' + (h & 0xffffff).toString(16).padStart(6, '0'); x.fillRect(0, 0, 200, 60);
  x.fillStyle = '#069'; x.font = '16px Arial'; x.textBaseline = 'top';
  x.fillText('fp-lab ' + seed, 2, 10 + (h % 20));
  const g = document.createElement('canvas'); g.width = 32; g.height = 32;
  const gl = g.getContext('webgl') || g.getContext('experimental-webgl');
  let wv = 'nogl';
  if (gl) {
    gl.clearColor(((h & 255) / 255), ((h >> 8 & 255) / 255), ((h >> 16 & 255) / 255), 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    const px = new Uint8Array(4);
    gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px);
    wv = Array.from(px).join(',');
  }
  const payload = c.toDataURL() + '|' + wv;
  const hb = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload));
  const hex = Array.from(new Uint8Array(hb)).map(b => b.toString(16).padStart(2, '0')).join('');
  try { await fetch(answerUrl, {method: 'POST', body: hex}); } catch (e) {}
})();
</script></body>
"""


def _js_literal(value: str) -> str:
    # JSON string literal, with '<' escaped so the value cannot close the script tag.
    return json.dumps(value).replace("<", "\\u003c")


def challenge_page(challenge: Challenge) -> str:
    return (
        _PAGE_TEMPLATE
        .replace("__SEED__", _js_literal(challenge.seed))
        .replace("__ANSWER_URL__", _js_literal("/answer/" + challenge.nonce))
    )
