from challenge.issue import Challenge, challenge_page, make_challenge


def test_make_challenge_unique():
    a, b = make_challenge(), make_challenge()
    assert a.nonce != b.nonce and a.seed != b.seed
    assert len(a.seed) >= 16 and a.nonce.startswith("chl")


def test_challenge_page_embeds_seed_nonce_and_posts_same_origin():
    c = Challenge(nonce="chlABC", seed="deadbeef")
    html = challenge_page(c)
    assert "deadbeef" in html and "chlABC" in html
    assert "/answer/chlABC" in html          # relative → same-origin fetch
    assert "data:" not in html.split("toDataURL")[0]  # page itself is not a data: URL
    assert "crypto.subtle" in html and "readPixels" in html
