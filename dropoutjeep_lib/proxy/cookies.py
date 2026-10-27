"""Cookie capture helpers for the reverse proxy."""

import logging
from http.cookies import SimpleCookie
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def parse_set_cookie_headers(headers: dict, target_url: str) -> list[dict]:
    """Extract Set-Cookie values from response headers into structured dicts."""
    cookies = []
    parsed_target = urlparse(target_url)
    default_domain = parsed_target.hostname or ''

    # httpx may return Set-Cookie as a single string or multiple values.
    raw_values = headers.get('set-cookie') or headers.get('Set-Cookie') or []
    if isinstance(raw_values, str):
        raw_values = [raw_values]

    for raw in raw_values:
        if not raw:
            continue
        try:
            sc = SimpleCookie()
            sc.load(raw)
            for name in sc:
                m = sc[name]
                cookies.append({
                    'name': name,
                    'value': m.value or '',
                    'domain': m.get('domain') or default_domain,
                    'path': m.get('path') or '/',
                })
        except Exception:
            logger.exception("Failed to parse Set-Cookie header: %s", raw)

    return cookies


def parse_request_cookie_header(cookie_header: str | None) -> list[dict]:
    """Extract Cookie header values into name/value pairs."""
    cookies = []
    if not cookie_header:
        return cookies
    try:
        sc = SimpleCookie()
        sc.load(cookie_header)
        for name in sc:
            cookies.append({
                'name': name,
                'value': sc[name].value or '',
            })
    except Exception:
        logger.exception("Failed to parse Cookie header: %s", cookie_header)
    return cookies
