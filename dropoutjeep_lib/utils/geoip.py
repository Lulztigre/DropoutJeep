"""IP geolocation enrichment for campaign events.

Uses ipapi.co by default. Caches results in memory for 1 hour to avoid
hammering the API. Set ``IPAPI_API_KEY`` in the environment for higher rate
limits, or replace ``_fetch_ipapi`` with a MaxMind reader if you have local DB.
"""

import logging
import os
import time
from functools import lru_cache
from typing import Any

import requests

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 3600
_cache: dict[str, tuple[float, dict]] = {}


def _api_key() -> str | None:
    """Return IPAPI key from settings or env."""
    from dropoutjeep_lib.utils.settings import get_setting
    return get_setting('ipapi_api_key') or os.environ.get('IPAPI_API_KEY')


def _fetch_ipapi(ip: str) -> dict[str, Any]:
    """Query ipapi.co for one IP."""
    url = f"https://ipapi.co/{ip}/json/"
    headers = {}
    api_key = _api_key()
    if api_key:
        headers['Authorization'] = f"Bearer {api_key}"
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if data.get('error'):
            logger.warning("ipapi.co error for %s: %s", ip, data.get('reason'))
            return {}
        return data
    except Exception as exc:
        logger.warning("GeoIP lookup failed for %s: %s", ip, exc)
        return {}


def _from_cache(ip: str) -> dict | None:
    now = time.time()
    ts, data = _cache.get(ip, (0, None))
    if data is not None and now - ts < _CACHE_TTL_SECONDS:
        return data
    return None


def enrich_ip(ip: str | None) -> dict[str, Any]:
    """Return geo fields for an IP address."""
    if not ip or ip in ('127.0.0.1', 'localhost', '::1'):
        return {}

    cached = _from_cache(ip)
    if cached is not None:
        return cached

    data = _fetch_ipapi(ip)
    result = {
        'country': data.get('country_name') or data.get('country'),
        'country_code': data.get('country_code'),
        'city': data.get('city'),
        'region': data.get('region'),
        'org': data.get('org'),
        'asn': data.get('asn'),
        'latitude': data.get('latitude'),
        'longitude': data.get('longitude'),
    }
    _cache[ip] = (time.time(), result)
    return result


def format_geo(enrichment: dict) -> str:
    """Human-readable geo string, e.g. 'New York, US'."""
    parts = [p for p in [enrichment.get('city'), enrichment.get('region'), enrichment.get('country')] if p]
    return ', '.join(parts) if parts else 'Unknown'
