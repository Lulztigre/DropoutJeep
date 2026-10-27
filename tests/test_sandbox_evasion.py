"""Unit tests for sandbox evasion fingerprint logic."""

from dropoutjeep_lib.utils.sandbox_evasion import (
    is_sandbox_ua,
    fingerprint_request,
)


def test_is_sandbox_ua_detects_crawlers():
    assert is_sandbox_ua('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
    assert is_sandbox_ua('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
    assert is_sandbox_ua('curl/7.68.0')


def test_is_sandbox_ua_allows_normal_browsers():
    assert not is_sandbox_ua('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36')
    assert not is_sandbox_ua('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15')


def test_is_sandbox_ua_empty_is_sandbox():
    assert is_sandbox_ua('')


def test_fingerprint_request_deterministic():
    ip = '192.0.2.1'
    ua = 'Mozilla/5.0 Test'
    assert fingerprint_request(ip, ua) == fingerprint_request(ip, ua)
    assert len(fingerprint_request(ip, ua)) == 32


def test_fingerprint_request_differs():
    assert fingerprint_request('192.0.2.1', 'UA1') != fingerprint_request('192.0.2.2', 'UA1')
    assert fingerprint_request('192.0.2.1', 'UA1') != fingerprint_request('192.0.2.1', 'UA2')
