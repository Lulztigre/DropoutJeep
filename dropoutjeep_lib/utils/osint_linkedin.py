"""LinkedIn OSINT scraper for pretext generation.

Performs lightweight public-source scraping of LinkedIn-style profile pages
and company directories to extract job titles, departments, manager names,
recent posts, and company news. From that structured data it generates a
pretext brief: suggested subject lines and body templates that reference the
real projects and people discovered, so downstream phishing-simulation emails
read as plausible internal messages.

This module is intended for **authorized** red-team / phishing-simulation use
only, against targets the operator has written permission to test. It does not
authenticate to LinkedIn and respects rate-limit / 999 / challenge responses by
backing off and returning empty results rather than hammering the endpoint.

Two scraping paths are supported:

* ``requests`` + BeautifulSoup (default) — fast, works against publicly
  cacheable profile pages and directory listings.
* Playwright headless browser (optional) — used only when the operator sets
  ``LINKEDIN_USE_PLAYWRIGHT=1``; falls back to requests if Playwright is not
  installed.
"""

from __future__ import annotations

import logging
import os
import random
import re
import time
from typing import Dict, List, Optional
from urllib.parse import quote_plus, urljoin

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger("dropoutjeep")

# --- Configuration -----------------------------------------------------------

LINKEDIN_BASE = "https://www.linkedin.com"
DEFAULT_TIMEOUT = 15
MAX_RETRIES = 2
BACKOFF_BASE = 2.0  # seconds, doubled per retry

# Rotate a small pool of realistic desktop UAs to dodge naive UA filters.
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]


def _api_key(name: str) -> Optional[str]:
    """Resolve a setting from the DB-backed settings helper, then env."""
    try:
        from dropoutjeep_lib.utils.settings import get_setting  # type: ignore
        value = get_setting(name)
        if value:
            return value
    except Exception:
        # No Flask app context — fall through to env.
        pass
    return os.environ.get(name.upper())


def _session() -> requests.Session:
    """Build a requests.Session with browser-like headers."""
    s = requests.Session()
    s.headers.update({
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    return s


def _fetch(url: str, session: Optional[requests.Session] = None) -> Optional[str]:
    """GET a URL with retries/backoff. Returns HTML text or None on failure.

    Treats HTTP 999 (LinkedIn's challenge) and 429 as rate-limit signals and
    backs off rather than retrying aggressively.
    """
    sess = session or _session()
    last_exc: Optional[Exception] = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = sess.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if resp.status_code in (200,):
                return resp.text
            if resp.status_code in (429, 999):
                wait = BACKOFF_BASE * (2 ** attempt) + random.uniform(0, 1)
                logger.warning(
                    "LinkedIn rate-limit %s for %s; backing off %.1fs",
                    resp.status_code, url, wait,
                )
                time.sleep(wait)
                continue
            logger.warning("LinkedIn fetch %s returned HTTP %s", url, resp.status_code)
            return None
        except requests.RequestException as exc:
            last_exc = exc
            wait = BACKOFF_BASE * (2 ** attempt)
            logger.warning("LinkedIn fetch error for %s: %s (retry in %.1fs)",
                           url, exc, wait)
            time.sleep(wait)
    if last_exc:
        logger.error("LinkedIn fetch ultimately failed for %s: %s", url, last_exc)
    return None


# --- URL construction --------------------------------------------------------

def _build_search_url(name: str, company: str) -> str:
    """Construct a LinkedIn directory search URL for a person at a company.

    Uses LinkedIn's public people-search query shape. The operator is expected
    to point this at a logged-in browser session or a third-party mirror; the
    raw public page will typically redirect to an auth wall, which is why
    ``scrape_linkedin_profile`` also falls back to a Google ``site:`` lookup.
    """
    query = f'"{name}" "{company}"'
    return (
        f"{LINKEDIN_BASE}/search/results/people/?keywords={quote_plus(query)}"
    )


def _google_site_search_url(name: str, company: str) -> str:
    """A Google ``site:linkedin.com/in`` search URL as a resilient fallback."""
    query = f'site:linkedin.com/in "{name}" "{company}"'
    return f"https://www.google.com/search?q={quote_plus(query)}"


# --- Parsing ----------------------------------------------------------------

_PROFILE_URL_RE = re.compile(r"linkedin\.com/in/([A-Za-z0-9_\-%]+)", re.I)


def _extract_profile_url_from_serps(html: str) -> Optional[str]:
    """Find the first ``linkedin.com/in/<slug>`` URL in a SERP page."""
    if not html:
        return None
    match = _PROFILE_URL_RE.search(html)
    if not match:
        return None
    slug = match.group(1).rstrip("/").rstrip('",')
    return f"{LINKEDIN_BASE}/in/{slug}"


def _parse_profile_page(html: str) -> Dict:
    """Parse a LinkedIn profile page (or public-cache snapshot) into a dict.

    LinkedIn's public profile markup is unstable and varies by region/A-B
    tests, so this parser is deliberately tolerant: it falls back to JSON-LD
    blocks and ``<meta>`` tags where structured markup is unavailable. Missing
    fields come back as empty strings / empty lists rather than raising.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    data: Dict = {
        "job_title": "",
        "department": "",
        "manager_name": "",
        "recent_posts": [],
        "company_news": [],
        "profile_url": "",
    }

    # 1. JSON-LD blocks often carry Person schema with jobTitle / worksFor.
    for tag in soup.find_all("script", type="application/ld+json"):
        try:
            import json
            blob = json.loads(tag.string or "{}")
        except (ValueError, TypeError):
            continue
        person = blob if isinstance(blob, dict) else {}
        if person.get("@type", "").lower() != "person":
            # Some pages wrap the Person under @graph.
            for node in person.get("@graph", []) if isinstance(person.get("@graph"), list) else []:
                if isinstance(node, dict) and node.get("@type", "").lower() == "person":
                    person = node
                    break
        if person.get("@type", "").lower() == "person":
            data["job_title"] = data["job_title"] or str(person.get("jobTitle") or "")
            works_for = person.get("worksFor")
            if isinstance(works_for, dict):
                data.setdefault("_company", works_for.get("name", ""))

    # 2. <meta> tags for og:title / description as a robust fallback.
    og_title = soup.find("meta", property="og:title")
    if og_title and og_title.get("content") and not data["job_title"]:
        # og:title is commonly "First Last - Job Title | LinkedIn"
        content = og_title["content"].replace(" | LinkedIn", "").strip()
        if " - " in content:
            _, data["job_title"] = content.split(" - ", 1)
        else:
            data["job_title"] = content

    og_desc = soup.find("meta", property="og:description")
    desc_text = og_desc.get("content", "") if og_desc else ""
    if not data["job_title"]:
        # "Senior Engineer at Acme Corp" pattern.
        m = re.search(r"(.+?)\s+at\s+([^\.|]+)", desc_text)
        if m:
            data["job_title"] = m.group(1).strip()
            data.setdefault("_company", m.group(2).strip())

    # 3. Headline element (LinkedIn's h1/topcard-title variants).
    headline = soup.find(attrs={"class": re.compile(r"topcard|headline|pv-text")})
    if headline and not data["job_title"]:
        data["job_title"] = headline.get_text(" ", strip=True)

    # 4. Department inference from job-title text (heuristic).
    title_lower = data["job_title"].lower()
    dept_map = {
        "engineering": ["engineer", "developer", "sre", "devops", "architect"],
        "security": ["security", "infosec", "soc", "appsec"],
        "it": ["it ", "sysadmin", "infrastructure"],
        "finance": ["finance", "accountant", "controller", "cfo"],
        "hr": ["hr", "people", "talent", "recruiter"],
        "marketing": ["marketing", "brand", "content", "growth"],
        "sales": ["sales", "account executive", "ae "],
        "legal": ["legal", "counsel", "paralegal"],
        "product": ["product", "pm", "program manager"],
    }
    for dept, keywords in dept_map.items():
        if any(k in title_lower for k in keywords):
            data["department"] = dept
            break

    # 5. Recent posts — LinkedIn exposes these in activity/updates sections.
    for section in soup.find_all(attrs={"class": re.compile(r"core-rail|updates|activity")}):
        for post in section.find_all(["li", "div"], recursive=True):
            text = post.get_text(" ", strip=True)
            if 40 < len(text) < 600 and text not in data["recent_posts"]:
                data["recent_posts"].append(text)
            if len(data["recent_posts"]) >= 5:
                break
        if len(data["recent_posts"]) >= 5:
            break

    # 6. Company news — grab any news-module anchors/text near the experience
    # section as a best-effort signal.
    for a in soup.find_all("a", href=re.compile(r"linkedin\.com/(company|news)")):
        label = a.get_text(" ", strip=True)
        if label and label not in data["company_news"]:
            data["company_news"].append(label)
        if len(data["company_news"]) >= 5:
            break

    # 7. Manager name — not reliably exposed on public profile; attempt to
    # pull it from any "Reports to" / management pattern in the description.
    if desc_text:
        m = re.search(r"[Rr]eports?\s+to\s+([A-Z][a-z]+ [A-Z][a-z]+)", desc_text)
        if m:
            data["manager_name"] = m.group(1)

    return data


def _scrape_company_news(company: str, session: Optional[requests.Session] = None) -> List[str]:
    """Fetch a few recent public news headlines about ``company``.

    Uses DuckDuckGo's HTML endpoint (no API key required) as a resilient,
    low-friction source. Falls back to an empty list on any error.
    """
    if not company:
        return []
    sess = session or _session()
    url = f"https://html.duckduckgo.com/html/?q={quote_plus(company + ' news')}"
    try:
        resp = sess.get(url, timeout=DEFAULT_TIMEOUT)
        if resp.status_code != 200:
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        headlines: List[str] = []
        for a in soup.find_all("a", class_="result__a"):
            text = a.get_text(" ", strip=True)
            if text and text not in headlines:
                headlines.append(text)
            if len(headlines) >= 5:
                break
        return headlines
    except requests.RequestException as exc:
        logger.warning("company-news fetch failed for %s: %s", company, exc)
        return []


# --- Public API --------------------------------------------------------------

def scrape_linkedin_profile(
    name: str,
    company: str,
    email: Optional[str] = None,
) -> Dict:
    """Scrape public LinkedIn-style profile data for ``name`` at ``company``.

    Args:
        name: Full name of the target, e.g. ``"Jane Doe"``.
        company: Employer / company name, e.g. ``"Acme Corp"``.
        email: Optional target email; used only as a hint for slug inference
            (``first.last`` patterns) and logged for the operator's reference.

    Returns:
        Dict with keys ``job_title``, ``department``, ``manager_name``,
        ``recent_posts`` (list[str]), ``company_news`` (list[str]),
        ``profile_url``, plus a ``source`` note and any ``error``.
    """
    result: Dict = {
        "job_title": "",
        "department": "",
        "manager_name": "",
        "recent_posts": [],
        "company_news": [],
        "profile_url": "",
        "source": "",
        "error": None,
    }
    if not name or not company:
        result["error"] = "Both name and company are required."
        return result

    session = _session()

    # Step 1: discover the profile URL. Try LinkedIn directory first, then a
    # Google site: search as a resilient fallback.
    profile_url: Optional[str] = None
    direct_html = _fetch(_build_search_url(name, company), session)
    if direct_html:
        profile_url = _extract_profile_url_from_serps(direct_html)

    if not profile_url:
        serp_html = _fetch(_google_site_search_url(name, company), session)
        if serp_html:
            profile_url = _extract_profile_url_from_serps(serp_html)

    # Optional Playwright path for pages that need JS rendering.
    use_playwright = _api_key("linkedin_use_playwright") == "1" or os.environ.get("LINKEDIN_USE_PLAYWRIGHT") == "1"
    profile_html: Optional[str] = None
    if profile_url:
        if use_playwright:
            try:
                profile_html = _fetch_with_playwright(profile_url)
            except Exception as exc:
                logger.warning("Playwright fetch failed, falling back to requests: %s", exc)
                profile_html = None
        if profile_html is None:
            profile_html = _fetch(profile_url, session)
        result["profile_url"] = profile_url
        result["source"] = "linkedin_public"

    # Step 2: parse whatever profile HTML we obtained.
    if profile_html:
        parsed = _parse_profile_page(profile_html)
        for k in ("job_title", "department", "manager_name", "recent_posts"):
            if parsed.get(k):
                result[k] = parsed[k]
        if not result["profile_url"]:
            result["profile_url"] = parsed.get("profile_url", "")

    # Step 3: enrich with company news from a resilient source regardless of
    # whether the profile page yielded news.
    if not result["company_news"]:
        result["company_news"] = _scrape_company_news(company, session)

    # If we got nothing at all, surface a clear note so the operator can decide
    # whether to retry with a logged-in browser session.
    if not any([result["job_title"], result["recent_posts"], result["profile_url"]]):
        result["error"] = (
            "No public profile data recovered; LinkedIn may have served an "
            "auth wall. Retry with LINKEDIN_USE_PLAYWRIGHT=1 or a session cookie."
        )

    logger.info(
        "LinkedIn OSINT for %s @ %s: title=%r posts=%d news=%d url=%s",
        name, company, result["job_title"], len(result["recent_posts"]),
        len(result["company_news"]), result["profile_url"] or "(none)",
    )
    return result


def _fetch_with_playwright(url: str) -> Optional[str]:
    """Render a page with Playwright headless Chromium and return its HTML.

    Imported lazily so the module remains importable on hosts without
    Playwright installed. Returns None if Playwright is unavailable.
    """
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        logger.debug("Playwright not installed; skipping headless render.")
        return None

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(user_agent=random.choice(_USER_AGENTS))
        page = context.new_page()
        try:
            page.goto(url, timeout=DEFAULT_TIMEOUT * 1000, wait_until="domcontentloaded")
            # Give SPAs a moment to populate profile markup.
            page.wait_for_timeout(1500)
            return page.content()
        except Exception as exc:
            logger.warning("Playwright render failed for %s: %s", url, exc)
            return None
        finally:
            context.close()
            browser.close()


# --- Pretext generation ------------------------------------------------------

_PRETEXT_SUBJECT_TEMPLATES = [
    "Following up on the Q3 planning meeting with {manager}",
    "Reminder: {project} deadline approaching — action needed",
    "Re: {headline} — quick question from {name_first}",
    "{company} all-hands: slides for {project} review",
    "Action required: {project} status update due EOD",
]

_PRETEXT_BODY_TEMPLATES = [
    (
        "Hi {name_first},\n\n"
        "Following up on our discussion with {manager} regarding {project}. "
        "I noticed your recent post about {headline} and wanted to loop you in "
        "on a related item that needs sign-off before the {project} deadline.\n\n"
        "Could you review the attached brief and confirm by EOD? "
        "Happy to jump on a quick call if easier.\n\n"
        "Thanks,\n"
        "[Sender]"
    ),
    (
        "Hello {name_first},\n\n"
        "Per {manager}'s note in the {company} channel, we need to finalize "
        "the {project} deliverable. Given your role as {job_title}, your input "
        "on the attached document would be appreciated.\n\n"
        "Please open the document and add your comments today.\n\n"
        "Regards,\n"
        "[Sender]"
    ),
    (
        "Hi {name_first},\n\n"
        "Saw your update on {headline} — great context for the {project} "
        "workstream. {manager} asked me to share the latest revision for your "
        "review; the link below has the current draft.\n\n"
        "Open document: {link}\n\n"
        "Best,\n"
        "[Sender]"
    ),
]


def _first_name(name: str) -> str:
    """Return the first token of ``name``."""
    return name.split()[0] if name else "there"


# Common English stopwords to filter out of single-token project guesses.
_STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "for", "with", "we", "our", "i",
    "you", "they", "them", "their", "his", "her", "she", "he", "this", "that",
    "these", "those", "is", "are", "was", "were", "be", "been", "being",
    "to", "of", "in", "on", "at", "by", "from", "as", "it", "its",
    "just", "so", "very", "more", "most", "some", "any", "all", "new",
    "today", "now", "here", "there", "about", "into", "over", "up", "down",
    "looking", "excited", "happy", "thrilled", "proud", "great", "good",
    "join", "shipped", "launched", "released", "sharing", "shared",
    "acme", "corp", "llc", "inc",  # company suffix noise
}


def _infer_project_names(profile_data: Dict) -> List[str]:
    """Guess project / workstream names from posts and headlines.

    Pulls capitalized noun phrases (and standalone ``Q1``–``Q4`` tokens) out
    of recent post / news text. Falls back to a generic placeholder if nothing
    is recoverable.
    """
    projects: List[str] = []
    corpus = " ".join(profile_data.get("recent_posts") or []) + " " + \
        " ".join(profile_data.get("company_news") or [])

    # 1. Explicit "Project <Name>" or "Q<n> <Name>" patterns.
    for m in re.finditer(
        r"\b((?:Project|Q[1-4])\s+[A-Z][A-Za-z0-9\-]+)", corpus
    ):
        cand = m.group(1).strip()
        if cand not in projects and len(cand) <= 40:
            projects.append(cand)
        if len(projects) >= 4:
            break

    # 2. Multi-word capitalized phrases (2-4 words), e.g. "Atlas Migration".
    if len(projects) < 4:
        for m in re.finditer(
            r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b", corpus
        ):
            cand = m.group(1).strip()
            first = cand.split()[0].lower()
            if first in _STOPWORDS:
                continue
            if cand not in projects and len(cand) <= 40:
                projects.append(cand)
            if len(projects) >= 4:
                break

    # 3. Standalone capitalized tokens adjacent to project-y context words, or
    # bare "Q3"/"Q4" tokens. Catches "Phoenix" in "Phoenix project milestone".
    if len(projects) < 4:
        for m in re.finditer(
            r"\b([A-Z][a-z]{2,})\s+(?:project|workstream|migration|launch|"
            r"release|initiative|rollout|milestone|deadline)\b", corpus
        ):
            cand = m.group(1)
            if cand.lower() in _STOPWORDS:
                continue
            if cand not in projects:
                projects.append(cand)
            if len(projects) >= 4:
                break
        for m in re.finditer(r"\b(Q[1-4])\b", corpus):
            cand = m.group(1)
            if cand not in projects:
                projects.append(cand)
            if len(projects) >= 4:
                break

    if not projects:
        projects = ["the upcoming deliverable"]
    return projects


def generate_pretext_brief(profile_data: Dict) -> Dict:
    """Generate suggested subject lines and body templates from scraped data.

    Args:
        profile_data: Output of :func:`scrape_linkedin_profile`.

    Returns:
        Dict with ``subject_lines`` (list[str]), ``body_templates`` (list[str]),
        ``target_name``, ``project_names`` (list[str]), and ``notes``.
    """
    name = profile_data.get("target_name", "") or profile_data.get("name", "")
    manager = profile_data.get("manager_name") or "your manager"
    company = profile_data.get("company", "")
    job_title = profile_data.get("job_title") or "team member"
    news = profile_data.get("company_news") or []
    projects = _infer_project_names(profile_data)
    first = _first_name(name) if name else "there"

    fmt = {
        "name_first": first,
        "manager": manager,
        "company": company,
        "job_title": job_title,
        "project": projects[0],
        "headline": news[0] if news else "the latest company update",
        "link": "{PHISH_LINK}",
    }

    subject_lines: List[str] = []
    for tmpl in _PRETEXT_SUBJECT_TEMPLATES:
        try:
            subject_lines.append(tmpl.format(**fmt))
        except (KeyError, IndexError):
            subject_lines.append(tmpl)
    # Dedup while preserving order.
    seen = set()
    subject_lines = [s for s in subject_lines if not (s in seen or seen.add(s))]

    body_templates: List[str] = []
    for tmpl in _PRETEXT_BODY_TEMPLATES:
        try:
            body_templates.append(tmpl.format(**fmt))
        except (KeyError, IndexError):
            body_templates.append(tmpl)

    notes: List[str] = []
    if not manager or manager == "your manager":
        notes.append("Manager name not recovered; placeholder used.")
    if not profile_data.get("job_title"):
        notes.append("Job title not recovered; generic role used.")
    if not projects or projects[0] == "the upcoming deliverable":
        notes.append("No concrete project names extracted; generic placeholder used.")
    if profile_data.get("error"):
        notes.append(f"Scrape note: {profile_data['error']}")

    return {
        "target_name": name,
        "subject_lines": subject_lines,
        "body_templates": body_templates,
        "project_names": projects,
        "company_news": news,
        "notes": notes,
    }
