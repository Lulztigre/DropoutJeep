"""Current-events pretext generator.

Pulls real, current public data from four open sources and turns it into
plausible phishing-simulation pretext suggestions (subject lines + body
templates) that reference genuine events. The sources are:

* **Company news** — Google News RSS feed (no API key required).
* **Severe weather alerts** — U.S. National Weather Service public alerts API.
* **Recent CVEs** — NVD (National Vulnerability Database) public CVE API.
* **SEC filings** — SEC EDGAR full-text search (company filings).

The combined data lets an operator craft pretexts grounded in verifiable
current events — a security-bulletin luring pretext citing a real CVE, a
severe-weather remote-work pretext citing a real NWS alert, a financial-pretext
email referencing a real SEC filing — all of which read as plausible internal
corporate communications.

Only ``requests`` is required for API calls. Every fetch degrades gracefully:
network or parse failures return empty lists and log a warning rather than
raising, so the public :func:`generate_pretexts` entry point always returns a
usable (possibly partial) dict.

This module is intended for **authorized** red-team / phishing-simulation use
only, against targets the operator has written permission to test.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from urllib.parse import quote_plus

import requests

logger = logging.getLogger("dropoutjeep")

# --- Configuration -----------------------------------------------------------

DEFAULT_TIMEOUT = 15
MAX_RETRIES = 2
BACKOFF_BASE = 1.5

GOOGLE_NEWS_RSS = "https://news.google.com/rss/search?q={query}&hl=en"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NWS_ALERTS_API = "https://api.weather.gov/alerts"
SEC_EDGAR_SEARCH = "https://efts.sec.gov/LATEST/search-index?q={query}&dateRange=custom&startdt={start}&enddt={end}"

# Realistic desktop UA; NWS API *requires* a UA with contact info per their
# usage policy, so we include a placeholder operator contact in the UA string.
_USER_AGENT = (
    "DropoutJeep-PretextGen/1.0 (authorized red-team simulation; "
    "operator@example.com)"
)

# Cap on the number of items fetched per source to keep response sizes sane.
MAX_NEWS_ITEMS = 10
MAX_WEATHER_ITEMS = 10
MAX_CVE_ITEMS = 15
MAX_SEC_ITEMS = 8


# --- HTTP helper -------------------------------------------------------------

def _session() -> requests.Session:
    """Build a requests.Session with sensible default headers."""
    s = requests.Session()
    s.headers.update({
        "User-Agent": _USER_AGENT,
        "Accept": "application/json, application/atom+xml, application/xml, */*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    return s


def _get_json(url: str, session: Optional[requests.Session] = None) -> Optional[dict]:
    """GET a JSON endpoint with retries; return parsed JSON or None on failure."""
    return _get(url, session, want_json=True)  # type: ignore[return-value]


def _get_text(url: str, session: Optional[requests.Session] = None) -> Optional[str]:
    """GET a text endpoint (e.g. RSS) with retries; return text or None."""
    return _get(url, session, want_json=False)  # type: ignore[return-value]


def _get(
    url: str,
    session: Optional[requests.Session] = None,
    want_json: bool = True,
):
    """Internal fetch with retry/backoff. Returns parsed JSON (if want_json) or text."""
    import time, random
    sess = session or _session()
    last_exc: Optional[Exception] = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = sess.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if resp.status_code == 200:
                if want_json:
                    try:
                        return resp.json()
                    except ValueError:
                        logger.warning("JSON parse failed for %s", url)
                        return None
                return resp.text
            if resp.status_code in (429, 503):
                wait = BACKOFF_BASE * (2 ** attempt) + random.uniform(0, 1)
                logger.warning("Rate-limit %s for %s; backing off %.1fs", resp.status_code, url, wait)
                time.sleep(wait)
                continue
            logger.warning("GET %s returned HTTP %s", url, resp.status_code)
            return None
        except requests.RequestException as exc:
            last_exc = exc
            wait = BACKOFF_BASE * (2 ** attempt)
            logger.warning("GET error for %s: %s (retry in %.1fs)", url, exc, wait)
            time.sleep(wait)
    if last_exc:
        logger.error("GET ultimately failed for %s: %s", url, last_exc)
    return None


# --- Source fetchers ---------------------------------------------------------

def _fetch_company_news(company: str) -> List[Dict[str, str]]:
    """Fetch recent news headlines about ``company`` from Google News RSS.

    Args:
        company: Company name (e.g. ``"Acme Corp"``).

    Returns:
        List of dicts ``{"title", "url", "date", "source"}``. Empty on error
        or if ``company`` is falsy. Capped at :data:`MAX_NEWS_ITEMS`.
    """
    if not company:
        return []
    url = GOOGLE_NEWS_RSS.format(query=quote_plus(company))
    text = _get_text(url)
    if not text:
        logger.warning("No company-news data for %r", company)
        return []

    items: List[Dict[str, str]] = []
    # Lightweight RSS <item> parser — avoids a feedparser dependency.
    for m in re.finditer(r"<item>(.*?)</item>", text, re.DOTALL | re.IGNORECASE):
        block = m.group(1)
        title = _rss_tag(block, "title")
        link = _rss_tag(block, "link")
        pub = _rss_tag(block, "pubDate")
        source = _rss_tag(block, "source")
        # Google News wraps the real article URL in a redirect URL param.
        real_url = _extract_google_news_url(link) or link
        items.append({
            "title": _strip_cdata(title),
            "url": real_url,
            "date": pub,
            "source": _strip_cdata(source),
        })
        if len(items) >= MAX_NEWS_ITEMS:
            break

    logger.info("Company news for %r: %d items", company, len(items))
    return items


def _fetch_weather_alerts(location: Optional[str] = None) -> List[Dict[str, str]]:
    """Fetch active severe-weather alerts from the NWS public API.

    Args:
        location: Optional U.S. state/area code (e.g. ``"CA"``, ``"NY"``) to
            filter alerts. If omitted, all currently-active U.S. alerts are
            returned.

    Returns:
        List of dicts ``{"event", "headline", "area", "severity", "url",
        "onset"}``. Empty on error. Capped at :data:`MAX_WEATHER_ITEMS`.
    """
    params: Dict[str, str] = {}
    if location:
        # NWS accepts an `area` param as a comma-separated list of FIPS/zone
        # codes or state abbreviations. We pass the raw value; the API is
        # tolerant of two-letter state codes.
        params["area"] = location
    url = NWS_ALERTS_API + ("?" + "&".join(f"{k}={v}" for k, v in params.items()) if params else "")
    data = _get_json(url)
    if not data or not isinstance(data, dict):
        logger.warning("No weather-alert data for %r", location or "US")
        return []

    items: List[Dict[str, str]] = []
    for feature in data.get("features", []) or []:
        props = feature.get("properties", {}) or {}
        event = props.get("event", "")
        if not event:
            continue
        # Only keep genuinely severe alerts (skip advisories by default).
        severity = props.get("severity", "")
        area_desc = props.get("areaDesc", "")
        headline = props.get("headline", event)
        onset = props.get("onset", "")
        web_url = props.get("id") or (feature.get("id") if isinstance(feature, dict) else "")
        items.append({
            "event": event,
            "headline": headline,
            "area": area_desc,
            "severity": severity,
            "url": web_url,
            "onset": onset,
        })
        if len(items) >= MAX_WEATHER_ITEMS:
            break

    logger.info("Weather alerts (%s): %d items", location or "US", len(items))
    return items


def _fetch_recent_cves(days: int = 7) -> List[Dict[str, str]]:
    """Fetch recently-published CVEs from the NVD CVE 2.0 API.

    Args:
        days: Look-back window in days (default 7).

    Returns:
        List of dicts ``{"cve_id", "description", "cvss", "published",
        "url"}``. Empty on error. Capped at :data:`MAX_CVE_ITEMS`.
    """
    if days <= 0:
        return []
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    # NVD expects ISO-8601 timestamps without the trailing 'Z' offset colon.
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = (
        f"?pubStartDate={start.strftime(fmt)}-00:00"
        f"&pubEndDate={end.strftime(fmt)}-00:00"
        f"&resultsPerPage={MAX_CVE_ITEMS}"
    )
    url = NVD_CVE_API + params
    data = _get_json(url)
    if not data or not isinstance(data, dict):
        logger.warning("No CVE data for last %d days", days)
        return []

    items: List[Dict[str, str]] = []
    for vuln in data.get("vulnerabilities", []) or []:
        cve = vuln.get("cve", {}) if isinstance(vuln, dict) else {}
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", []) or []
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        # CVSS score — prefer CVSS v3.1, then v3.0, then v2.
        cvss = ""
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                first = metrics[key][0] if isinstance(metrics[key], list) else {}
                cvss_data = first.get("cvssData", {}) if isinstance(first, dict) else {}
                cvss = str(cvss_data.get("baseScore", "")) if cvss_data else ""
                break
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        items.append({
            "cve_id": cve_id,
            "description": desc,
            "cvss": cvss,
            "published": cve.get("published", ""),
            "url": url,
        })
        if len(items) >= MAX_CVE_ITEMS:
            break

    logger.info("CVE fetch (last %d days): %d items", days, len(items))
    return items


def _fetch_sec_filings(company: str) -> List[Dict[str, str]]:
    """Fetch recent SEC EDGAR filings for ``company``.

    Uses the EDGAR full-text search JSON endpoint (no API key required).

    Args:
        company: Company name or ticker.

    Returns:
        List of dicts ``{"title", "form_type", "filed", "url", "company"}``.
        Empty on error or if ``company`` is falsy. Capped at
        :data:`MAX_SEC_ITEMS`.
    """
    if not company:
        return []
    today = datetime.now(timezone.utc)
    start = today - timedelta(days=30)
    url = SEC_EDGAR_SEARCH.format(
        query=quote_plus(company),
        start=start.strftime("%Y-%m-%d"),
        end=today.strftime("%Y-%m-%d"),
    )
    # EDGAR's full-text search returns JSON under /LATEST/search-index.
    data = _get_json(url)
    if not data or not isinstance(data, dict):
        # The efts endpoint shape has historically shifted; try the documented
        # https://efts.sec.gov/LATEST/search-index?q=... form too.
        alt = f"https://efts.sec.gov/LATEST/search-index?q={quote_plus(company)}"
        data = _get_json(alt)
    if not data or not isinstance(data, dict):
        logger.warning("No SEC filing data for %r", company)
        return []

    hits = data.get("hits", {}) or {}
    total = hits.get("hits", []) or []
    items: List[Dict[str, str]] = []
    for hit in total:
        src = hit.get("_source", {}) if isinstance(hit, dict) else {}
        form_type = src.get("form_type", "")
        title = src.get("display_names", [src.get("adsh", "")])
        if isinstance(title, list):
            title = title[0] if title else ""
        filed = src.get("file_date", src.get("date", ""))
        adsh = src.get("adsh", "").replace("-", "")
        filing_url = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=&type={form_type}&dateb=&owner=include&count=10"
        if adsh:
            filing_url = f"https://www.sec.gov/Archives/edgar/data/{src.get('ciks',[''])[0] if isinstance(src.get('ciks'), list) else ''}/{adsh}/"
        items.append({
            "title": title,
            "form_type": form_type,
            "filed": filed,
            "url": filing_url,
            "company": company,
        })
        if len(items) >= MAX_SEC_ITEMS:
            break

    logger.info("SEC filings for %r: %d items", company, len(items))
    return items


# --- Pretext suggestion builder ---------------------------------------------

def _build_pretext_suggestions(
    news: List[Dict[str, str]],
    weather: List[Dict[str, str]],
    cves: List[Dict[str, str]],
    sec_filings: Optional[List[Dict[str, str]]] = None,
) -> List[Dict[str, str]]:
    """Combine fetched data into realistic pretext suggestions.

    Each suggestion is a dict ``{"subject", "body_template", "type"}`` where
    ``type`` is one of ``"security_bulletin"``, ``"weather"``, ``"company_news"``,
    ``"financial"``. The ``body_template`` contains ``{phish_link}`` and
    ``{company}`` placeholders for the operator to substitute.

    Args:
        news: Output of :func:`_fetch_company_news`.
        weather: Output of :func:`_fetch_weather_alerts`.
        cves: Output of :func:`_fetch_recent_cves`.
        sec_filings: Optional output of :func:`_fetch_sec_filings`.

    Returns:
        List of pretext suggestion dicts (deduplicated by subject).
    """
    suggestions: List[Dict[str, str]] = []
    seen_subjects = set()

    def _add(subject: str, body: str, ptype: str) -> None:
        if not subject or subject in seen_subjects:
            return
        seen_subjects.add(subject)
        suggestions.append({
            "subject": subject,
            "body_template": body,
            "type": ptype,
        })

    # --- Security-bulletin pretexts (from CVEs) ---
    for cve in cves[:6]:
        cve_id = cve.get("cve_id", "")
        cvss = cve.get("cvss", "")
        desc = cve.get("description", "")
        # Shorten the description for the subject.
        short_desc = re.sub(r"^\s*[A-Z ]+:\s*", "", desc)  # strip leading label
        short_desc = short_desc[:80].rsplit(" ", 1)[0] + "…" if len(short_desc) > 80 else short_desc
        severity_note = f" (CVSS {cvss})" if cvss else ""
        subject = f"Security bulletin: {cve_id} affects our infrastructure{severity_note}"
        body = (
            "Team,\n\n"
            "A new vulnerability ({cve_id}) was published by the NVD that affects "
            "software we use in production. Details below:\n\n"
            "  CVE: {cve_id}\n"
            "  CVSS: {cvss}\n"
            "  Description: {short_desc}\n"
            "  Reference: {cve_url}\n\n"
            "Security requires all employees to re-authenticate and confirm their "
            "account is not impacted. Please sign in at the link below to "
            "complete the mandatory security check:\n\n"
            "  {phish_link}\n\n"
            "This check is required before end of business today.\n\n"
            "— IT Security"
        ).format(
            cve_id=cve_id,
            cvss=cvss or "N/A",
            short_desc=short_desc or desc,
            cve_url=cve.get("url", ""),
            phish_link="{phish_link}",
        )
        _add(subject, body, "security_bulletin")

    # --- Severe-weather remote-work pretexts ---
    for alert in weather[:5]:
        event = alert.get("event", "")
        area = alert.get("area", "")
        if not event:
            continue
        subject = f"Due to {event.lower()} in {area}, please confirm your remote work status"
        body = (
            "Hello,\n\n"
            "Due to the active {event} affecting {area}, all employees in the "
            "impacted region are instructed to work remotely until further notice.\n\n"
            "Please confirm your remote-work status and VPN connectivity by "
            "signing in at the link below so we can account for everyone's "
            "safety:\n\n"
            "  {phish_link}\n\n"
            "Alert source: NWS ({alert_url})\n\n"
            "Stay safe,\n"
            "— {company} Facilities & Security"
        ).format(
            event=event,
            area=area or "your area",
            phish_link="{phish_link}",
            alert_url=alert.get("url", ""),
            company="{company}",
        )
        _add(subject, body, "weather")

    # --- Company-news pretexts ---
    for item in news[:5]:
        title = item.get("title", "")
        if not title:
            continue
        subject = f"Reminder: Q3 all-hands meeting link inside — re: {title[:50]}"
        body = (
            "Hi,\n\n"
            "Following the recent news (\"{news_title}\"), leadership has "
            "scheduled an all-hands to discuss the implications for our team. "
            "The meeting agenda and a confidential briefing document are "
            "available at the link below:\n\n"
            "  {phish_link}\n\n"
            "Please review the briefing before the call. If the link prompts "
            "for your corporate credentials, use your standard login.\n\n"
            "News reference: {news_url}\n\n"
            "— {company} Internal Communications"
        ).format(
            news_title=title,
            news_url=item.get("url", ""),
            phish_link="{phish_link}",
            company="{company}",
        )
        _add(subject, body, "company_news")

    # --- Financial / SEC-filing pretexts ---
    if sec_filings:
        for filing in sec_filings[:4]:
            form = filing.get("form_type", "")
            title = filing.get("title", "")
            if not form:
                continue
            subject = f"Action required: review {form} filing — {title[:40]}"
            body = (
                "Colleagues,\n\n"
                "Our latest {form} filing (\"{title}\") has been submitted to "
                "the SEC. As part of our compliance review, certain employees "
                "must acknowledge the filing before it is finalized.\n\n"
                "Please sign in at the link below to review and acknowledge:\n\n"
                "  {phish_link}\n\n"
                "Filing reference: {filing_url}\n\n"
                "— {company} Finance & Compliance"
            ).format(
                form=form,
                title=title,
                filing_url=filing.get("url", ""),
                phish_link="{phish_link}",
                company="{company}",
            )
            _add(subject, body, "financial")

    logger.info(
        "Built %d pretext suggestions (sec:%d wx:%d news:%d cve:%d filings:%d)",
        len(suggestions),
        sum(1 for s in suggestions if s["type"] == "security_bulletin"),
        sum(1 for s in suggestions if s["type"] == "weather"),
        sum(1 for s in suggestions if s["type"] == "company_news"),
        sum(1 for s in suggestions if s["type"] == "financial"),
        len(sec_filings or []),
    )
    return suggestions


# --- Public entry point ------------------------------------------------------

def generate_pretexts(
    company: Optional[str] = None,
    sector: Optional[str] = None,
) -> Dict:
    """Generate current-events-grounded pretext suggestions.

    Pulls from Google News, the NWS alerts API, the NVD CVE API, and SEC
    EDGAR, then combines them into ready-to-use subject/body pretext templates.

    Args:
        company: Target company name (used for news + SEC filings). If
            omitted, company-news and financial pretexts are skipped.
        sector: Optional industry sector keyword (e.g. ``"finance"``,
            ``"healthcare"``). When ``company`` is absent, ``sector`` is used
            as the news query so generic sector-level pretexts can still be
            produced.

    Returns:
        Dict with keys:
            * ``company_news`` (list[dict]) — ``{title, url, date, source}``.
            * ``weather_alerts`` (list[dict]) — ``{event, headline, area,
              severity, url, onset}``.
            * ``cve_alerts`` (list[dict]) — ``{cve_id, description, cvss,
              published, url}``.
            * ``sec_filings`` (list[dict]) — ``{title, form_type, filed, url,
              company}``.
            * ``pretext_suggestions`` (list[dict]) — ``{subject, body_template,
              type}``.
            * ``errors`` (list[str]) — non-fatal warnings encountered.
    """
    result: Dict = {
        "company_news": [],
        "weather_alerts": [],
        "cve_alerts": [],
        "sec_filings": [],
        "pretext_suggestions": [],
        "errors": [],
    }

    session = _session()

    # Company news (falls back to sector query if no company given).
    news_query = company or sector
    if news_query:
        result["company_news"] = _fetch_company_news(news_query)
    else:
        result["errors"].append("No company or sector provided; skipping company news.")

    # Weather alerts (U.S.-wide by default).
    result["weather_alerts"] = _fetch_weather_alerts()

    # Recent CVEs.
    result["cve_alerts"] = _fetch_recent_cves(days=7)

    # SEC filings (company only).
    if company:
        result["sec_filings"] = _fetch_sec_filings(company)
    else:
        result["errors"].append("No company provided; skipping SEC filings.")

    # Build pretext suggestions from the gathered data.
    result["pretext_suggestions"] = _build_pretext_suggestions(
        result["company_news"],
        result["weather_alerts"],
        result["cve_alerts"],
        result["sec_filings"],
    )

    logger.info(
        "Pretext generation complete: news=%d weather=%d cves=%d sec=%d suggestions=%d",
        len(result["company_news"]),
        len(result["weather_alerts"]),
        len(result["cve_alerts"]),
        len(result["sec_filings"]),
        len(result["pretext_suggestions"]),
    )
    return result


# --- Small parsing helpers --------------------------------------------------

def _rss_tag(block: str, tag: str) -> str:
    """Extract the inner text of an RSS ``<tag>`` from ``block``."""
    m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", block, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _strip_cdata(text: str) -> str:
    """Remove CDATA wrapping from an RSS field value."""
    m = re.match(r"^\s*<!\[CDATA\[(.*?)\]\]>\s*$", text, re.DOTALL)
    return m.group(1) if m else text


def _extract_google_news_url(link: str) -> str:
    """Google News RSS wraps article URLs in a redirect; extract the real URL.

    The link typically looks like
    ``https://news.google.com/rss/articles/<id>?...`` or contains the target
    URL base64-encoded. We best-effort extract the underlying article URL;
    on failure we return the raw link so the operator still has a clickable
    reference.
    """
    if not link:
        return ""
    # Some items embed the real URL as a query param (rare).
    m = re.search(r"[?&]url=([^&]+)", link)
    if m:
        from urllib.parse import unquote
        return unquote(m.group(1))
    return link
