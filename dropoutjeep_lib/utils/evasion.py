"""Evasion helpers for authorized red-team engagements.

Provides header rotation profiles and referer-chain simulation so proxy/landing
requests can blend with typical target traffic.

Browser profiles updated to current versions (Chrome 131, Firefox 133, Edge 131,
Safari 17) per gap analysis item 24. Stale browser versions in the UA are a signal.
"""

import random
import secrets
from typing import Dict, List, Optional


# Browser-like header profiles — updated to current versions.
# Chrome 131, Firefox 133, Edge 131, Safari 17.
HEADER_PROFILES = [
    {
        'user_agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        ),
        'accept_language': 'en-US,en;q=0.9',
        'accept': (
            'text/html,application/xhtml+xml,application/xml;q=0.9,'
            'image/avif,image/webp,image/apng,*/*;q=0.8,'
            'application/signed-exchange;v=b3;q=0.7'
        ),
        'sec_ch_ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec_ch_ua_mobile': '?0',
        'sec_ch_ua_platform': '"Windows"',
        'sec_fetch_dest': 'document',
        'sec_fetch_mode': 'navigate',
        'sec_fetch_site': 'none',
        'sec_fetch_user': '?1',
        'upgrade_insecure_requests': '1',
    },
    {
        'user_agent': (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        ),
        'accept_language': 'en-GB,en;q=0.9',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'sec_ch_ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec_ch_ua_mobile': '?0',
        'sec_ch_ua_platform': '"macOS"',
        'sec_fetch_dest': 'document',
        'sec_fetch_mode': 'navigate',
        'sec_fetch_site': 'none',
        'sec_fetch_user': '?1',
        'upgrade_insecure_requests': '1',
    },
    {
        'user_agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) '
            'Gecko/20100101 Firefox/133.0'
        ),
        'accept_language': 'en-US,en;q=0.5',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'sec_fetch_dest': 'document',
        'sec_fetch_mode': 'navigate',
        'sec_fetch_site': 'none',
        'upgrade_insecure_requests': '1',
    },
    {
        'user_agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0'
        ),
        'accept_language': 'en-US,en;q=0.9',
        'accept': (
            'text/html,application/xhtml+xml,application/xml;q=0.9,'
            'image/avif,image/webp,image/apng,*/*;q=0.8,'
            'application/signed-exchange;v=b3;q=0.7'
        ),
        'sec_ch_ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec_ch_ua_mobile': '?0',
        'sec_ch_ua_platform': '"Windows"',
        'sec_fetch_dest': 'document',
        'sec_fetch_mode': 'navigate',
        'sec_fetch_site': 'none',
        'sec_fetch_user': '?1',
        'upgrade_insecure_requests': '1',
    },
    {
        'user_agent': (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 '
            '(KHTML, like Gecko) Version/17.6 Safari/605.1.15'
        ),
        'accept_language': 'en-US,en;q=0.9',
        'accept': (
            'text/html,application/xhtml+xml,application/xml;q=0.9,'
            'image/avif,image/webp,image/apng,*/*;q=0.8'
        ),
        'sec_fetch_dest': 'document',
        'sec_fetch_mode': 'navigate',
        'sec_fetch_site': 'none',
        'upgrade_insecure_requests': '1',
    },
]


def rotate_headers(headers: Dict[str, str], seed: Optional[str] = None) -> Dict[str, str]:
    """Return a copy of headers with a rotated browser-like profile.

    Sim headers (X-DropoutJeep-Sim, X-Mailer) are stripped if present.
    """
    if seed:
        rng = random.Random(seed)
        profile = rng.choice(HEADER_PROFILES)
    else:
        profile = random.choice(HEADER_PROFILES)
    rotated = dict(headers)
    rotated['User-Agent'] = profile['user_agent']
    rotated['Accept-Language'] = profile['accept_language']
    rotated['Accept'] = profile['accept']
    # Add sec-ch-ua and sec-fetch headers for Chromium-based profiles
    for key in ('sec_ch_ua', 'sec_ch_ua_mobile', 'sec_ch_ua_platform',
                'sec_fetch_dest', 'sec_fetch_mode', 'sec_fetch_site',
                'sec_fetch_user', 'upgrade_insecure_requests'):
        val = profile.get(key)
        if val:
            # Convert Python-style key names to HTTP header names
            header_name = key.replace('_', '-').replace('sec-ch', 'Sec-Ch').replace('sec-fetch', 'Sec-Fetch')
            if key.startswith('sec_ch'):
                header_name = key.replace('_', '-').title().replace('Sec-Ch', 'Sec-CH')
                header_name = f"Sec-CH-{key.split('_', 2)[-1].replace('_', '-').title()}" if 'platform' in key or 'mobile' in key else header_name
            # Simpler: just use the proper header names directly
            header_map = {
                'sec_ch_ua': 'Sec-CH-UA',
                'sec_ch_ua_mobile': 'Sec-CH-UA-Mobile',
                'sec_ch_ua_platform': 'Sec-CH-UA-Platform',
                'sec_fetch_dest': 'Sec-Fetch-Dest',
                'sec_fetch_mode': 'Sec-Fetch-Mode',
                'sec_fetch_site': 'Sec-Fetch-Site',
                'sec_fetch_user': 'Sec-Fetch-User',
                'upgrade_insecure_requests': 'Upgrade-Insecure-Requests',
            }
            rotated[header_map.get(key, key)] = val
    rotated.pop('X-DropoutJeep-Sim', None)
    rotated.pop('X-Mailer', None)
    return rotated


def build_referer_chain(final_url: str, length: int = 2) -> List[str]:
    """Return a list of intermediate URLs ending at ``final_url``.

    The chain simulates a realistic navigation path so the final request does
    not arrive with a bare or missing referer.
    """
    if length <= 0:
        return [final_url]
    intermediate_hosts = [
        'https://www.google.com/search',
        'https://www.bing.com/search',
        'https://duckduckgo.com/',
        'https://outlook.office.com/mail/',
    ]
    rng = random.Random(final_url)
    chain = []
    for i in range(length):
        host = rng.choice(intermediate_hosts)
        chain.append(f"{host}?q={secrets.token_urlsafe(8)}")
    chain.append(final_url)
    return chain
