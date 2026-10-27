"""Tests for evasion helpers."""

from dropoutjeep_lib.utils.evasion import rotate_headers, build_referer_chain


def test_rotate_headers_changes_user_agent():
    headers = {'User-Agent': 'bot/1.0', 'Accept': '*/*'}
    rotated = rotate_headers(headers)
    assert 'Mozilla' in rotated['User-Agent']
    assert 'Accept-Language' in rotated


def test_rotate_headers_deterministic_with_seed():
    h1 = rotate_headers({}, seed='abc')
    h2 = rotate_headers({}, seed='abc')
    assert h1['User-Agent'] == h2['User-Agent']


def test_rotate_headers_different_without_seed():
    # Random draws can collide, so sample several times.
    agents = {rotate_headers({})['User-Agent'] for _ in range(20)}
    assert len(agents) > 1


def test_build_referer_chain_ends_at_final():
    final = 'https://example.com/login'
    chain = build_referer_chain(final, length=2)
    assert len(chain) == 3
    assert chain[-1] == final
    assert all(url.startswith('http') for url in chain)
