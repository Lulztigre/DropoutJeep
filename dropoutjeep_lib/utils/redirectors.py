"""Redirector chain builder and health checks.

Redirectors hide the real phishing infrastructure behind one or more hop URLs.
Each redirector template is a URL that contains a ``{url}`` placeholder or,
if no placeholder is present, receives the next URL in the ``dj_next`` query
parameter.

Example chain configuration in campaign flow_config::

    {
        "redirector_chains_enabled": true,
        "redirectors": [
            "https://r1.example.com/out?to={url}",
            "https://r2.example.com/go?u={url}",
            "https://r3.example.com/redirect"
        ]
    }

When an email is sent the final proxy URL is wrapped from the inside out so
that the victim first hits ``r1``, which redirects to ``r2``, then ``r3``,
and finally lands on the real proxy URL.
"""

import logging
import random
from urllib.parse import quote

import httpx

from dropoutjeep_lib.models import Redirector

logger = logging.getLogger(__name__)

# Sentinel URL used for health checks. It must be a stable public domain that
# returns a 2xx response so we can verify the redirector is alive.
_HEALTH_CHECK_TARGET = "https://example.com"

# Known legitimate open-redirect endpoints. Abusing these makes the final URL
# look like a link to a trusted domain. The target URL is placed in the query
# parameter that the service normally uses for outgoing redirects.
_OPEN_REDIRECT_ENDPOINTS = [
    "https://www.google.com/url?q={url}&sa=D",
    "https://l.facebook.com/l.php?u={url}",
    "https://www.youtube.com/redirect?q={url}",
    "https://www.linkedin.com/redir/redirect?url={url}",
    "https://out.reddit.com/submit?url={url}",
    "https://steamcommunity.com/linkfilter/?url={url}",
]


def _apply_redirector(url_template: str, target_url: str) -> str:
    """Wrap ``target_url`` inside a single redirector template."""
    if "{url}" in url_template:
        return url_template.replace("{url}", quote(target_url, safe=""))
    sep = "&" if "?" in url_template else "?"
    return f"{url_template}{sep}dj_next={quote(target_url, safe='')}"


def build_redirect_chain(final_url: str, redirector_templates: list[str]) -> str:
    """Wrap ``final_url`` in a chain of redirector templates.

    ``redirector_templates`` is ordered from first hop (closest to victim) to
    last hop (closest to real infrastructure). The chain is built inside-out.
    """
    url = final_url
    for template in reversed(redirector_templates):
        template = template.strip()
        if not template:
            continue
        url = _apply_redirector(template, url)
    return url


def filter_healthy_redirector_templates(templates: list[str]) -> list[str]:
    """Return only redirector templates that pass a health probe."""
    healthy: list[str] = []
    for template in templates:
        if not template or not isinstance(template, str):
            continue
        ok, error = check_redirector_health(template)
        if ok:
            healthy.append(template)
        else:
            logger.warning("Skipping unhealthy redirector %s: %s", template, error)
    return healthy


def obfuscate_with_open_redirect(url: str, endpoint: str | None = None) -> str:
    """Wrap ``url`` in a trusted open-redirect endpoint.

    If ``endpoint`` is not provided a random endpoint from the built-in list is
    used. The caller is responsible for ensuring the chosen endpoint still
    performs an open redirect; many sites change their parameters over time.
    """
    template = endpoint or random.choice(_OPEN_REDIRECT_ENDPOINTS)
    return _apply_redirector(template, url)


def check_redirector_health(
    url_template: str,
    timeout: float = 10.0,
    client: httpx.Client | None = None,
) -> tuple[bool, str | None]:
    """Probe a redirector template and return (healthy, error_or_none).

    A redirector is considered healthy when it returns a 2xx or 3xx status
    code for a test redirect target.
    """
    test_url = _apply_redirector(url_template, _HEALTH_CHECK_TARGET)
    close_client = client is None
    client = client or httpx.Client(follow_redirects=False, timeout=timeout)
    try:
        response = client.head(test_url, follow_redirects=False)
        if response.status_code in (200, 301, 302, 303, 307, 308):
            return True, None
        return False, f"status {response.status_code}"
    except httpx.RequestError as exc:
        return False, str(exc)
    finally:
        if close_client:
            client.close()


def refresh_redirector_health(redirector: Redirector) -> bool:
    """Check a redirector, update its DB state, and return health."""
    from dropoutjeep_lib import db

    healthy, error = check_redirector_health(redirector.url_template)
    redirector.health_status = "healthy" if healthy else "unhealthy"
    redirector.last_error = error
    from datetime import datetime
    redirector.last_checked_at = datetime.utcnow()
    db.session.add(redirector)
    db.session.commit()
    return healthy


def get_active_redirector_templates() -> list[str]:
    """Return URL templates for redirectors marked active and healthy."""
    rows = Redirector.query.filter_by(is_active=True).all()
    return [r.url_template for r in rows if r.health_status != "unhealthy"]


def get_campaign_redirector_templates(campaign) -> list[str]:
    """Return redirector templates from a campaign's flow_config."""
    config = campaign.get_flow_config()
    if not config.get("redirector_chains_enabled"):
        return []
    templates = config.get("redirectors", [])
    if isinstance(templates, str):
        templates = [templates]
    return [t.strip() for t in templates if t and isinstance(t, str)]


def check_all_redirectors() -> list[dict]:
    """Check all redirectors and return results with health log entries."""
    import time
    from datetime import datetime
    from dropoutjeep_lib import db
    from dropoutjeep_lib.models import Redirector, RedirectorHealthLog

    results = []
    redirectors = Redirector.query.all()
    client = httpx.Client(follow_redirects=False, timeout=10.0)
    try:
        for r in redirectors:
            test_url = _apply_redirector(r.url_template, _HEALTH_CHECK_TARGET)
            start = time.monotonic()
            try:
                resp = client.head(test_url, follow_redirects=False)
                elapsed_ms = int((time.monotonic() - start) * 1000)
                healthy = resp.status_code in (200, 301, 302, 303, 307, 308)
                status_code = resp.status_code
                error = None if healthy else f"status {resp.status_code}"
            except httpx.RequestError as exc:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                healthy = False
                status_code = None
                error = str(exc)

            r.health_status = "healthy" if healthy else "unhealthy"
            r.last_error = error
            r.last_checked_at = datetime.utcnow()
            db.session.add(r)

            log = RedirectorHealthLog(
                redirector_id=r.id,
                is_healthy=healthy,
                status_code=status_code,
                response_time_ms=elapsed_ms,
                error_message=error,
            )
            db.session.add(log)

            results.append({
                'id': r.id,
                'name': r.name,
                'healthy': healthy,
                'status_code': status_code,
                'response_time_ms': elapsed_ms,
                'error': error,
            })
    finally:
        client.close()
    db.session.commit()
    return results


def get_redirector_health_history(redirector_id: int, limit: int = 50) -> list[dict]:
    """Return recent health check logs for a redirector."""
    from dropoutjeep_lib.models import RedirectorHealthLog
    logs = RedirectorHealthLog.query.filter_by(redirector_id=redirector_id) \
        .order_by(RedirectorHealthLog.checked_at.desc()) \
        .limit(limit).all()
    return [
        {
            'id': l.id,
            'is_healthy': l.is_healthy,
            'status_code': l.status_code,
            'response_time_ms': l.response_time_ms,
            'error_message': l.error_message,
            'checked_at': l.checked_at.isoformat() if l.checked_at else None,
        }
        for l in logs
    ]


def wrap_campaign_link(
    final_url: str,
    campaign,
    fallback_to_db: bool = True,
    templates: list[str] | None = None,
    obfuscate_final: bool = False,
) -> str:
    """Wrap a final campaign URL in configured redirector chains.

    ``templates`` can be passed pre-filtered (e.g. after a launch-time health
    check) so dead redirectors are skipped during sending. When
    ``obfuscate_final`` is true the outermost hop is a legitimate open-redirect
    endpoint from the built-in list.
    """
    if templates is None:
        templates = get_campaign_redirector_templates(campaign)
        if not templates and fallback_to_db:
            templates = get_active_redirector_templates()
    if not templates:
        wrapped = final_url
    else:
        wrapped = build_redirect_chain(final_url, templates)
    if obfuscate_final:
        wrapped = obfuscate_with_open_redirect(wrapped)
    return wrapped
