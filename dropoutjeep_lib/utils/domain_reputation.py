"""Domain reputation, warmup, and categorization scoring.

Uses VirusTotal (when VIRUSTOTAL_API_KEY is set) plus existing DNSBL, WHOIS,
SPF/DKIM/DMARC checks to produce a 0-100 reputation score and a daily send
warmup curve.
"""

import os
from datetime import datetime, date
from typing import Dict, List, Optional, Tuple

import requests
import whois

from dropoutjeep_lib import db
from dropoutjeep_lib.models import DomainReputation, Subsidiary
from dropoutjeep_lib.routes.urlcheck import check_blacklists, extract_domain
from dropoutjeep_lib.utils.validator import check_spf, check_dkim_selector
from dropoutjeep_lib.utils.dkim_utils import check_dmarc


VT_API_URL = "https://www.virustotal.com/api/v3/domains/{domain}"


def check_virus_total(domain: str) -> dict:
    """Query VirusTotal domain report. Returns score, categories, error."""
    from dropoutjeep_lib.utils.settings import get_setting
    key = get_setting('virustotal_api_key') or os.environ.get('VIRUSTOTAL_API_KEY')
    if not key:
        return {'score': None, 'categories': {}, 'error': 'No VIRUSTOTAL_API_KEY configured'}

    try:
        resp = requests.get(
            VT_API_URL.format(domain=domain),
            headers={'x-apikey': key},
            timeout=10,
        )
        if resp.status_code == 404:
            return {'score': None, 'categories': {}, 'error': 'Domain not found in VT'}
        if resp.status_code == 429:
            return {'score': None, 'categories': {}, 'error': 'VT rate limit hit'}
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        harmless = stats.get('harmless', 0)
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        timeout = stats.get('timeout', 0)
        total = harmless + malicious + suspicious + undetected + timeout
        score = None
        if total:
            bad = malicious + suspicious
            score = max(0, min(100, int(((total - bad) / total) * 100)))
        categories = attrs.get('categories', {})
        return {'score': score, 'categories': categories, 'error': None}
    except Exception as exc:
        return {'score': None, 'categories': {}, 'error': str(exc)}


def _domain_age_days(domain: str) -> Optional[int]:
    """Best-effort WHOIS domain age in days."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.now() - creation_date).days
            return age if age >= 0 else None
    except Exception:
        pass
    return None


def compute_overall_score(
    vt_result: dict,
    blacklist_flags: List[str],
    spf_ok: bool,
    dkim_ok: bool,
    dmarc_ok: bool,
    age_days: Optional[int],
) -> int:
    """Combine signals into a 0-100 reputation score."""
    score = 50

    # VirusTotal score contributes up to +/- 40 points
    vt_score = vt_result.get('score')
    if vt_score is not None:
        score += int((vt_score / 100.0) * 40) - 20

    # SPF/DKIM/DMARC contribute up to 30 points
    score += sum([spf_ok, dkim_ok, dmarc_ok]) * 10

    # DNSBL listings penalize heavily
    score -= len(blacklist_flags) * 20

    # Domain age signal
    if age_days is not None:
        if age_days >= 30:
            score += 10
        elif age_days < 7:
            score -= 10

    return max(0, min(100, score))


def _warmup_level_from_score_and_age(score: int, age_days: Optional[int]) -> int:
    """Map reputation to a 0-10 warmup level."""
    if score >= 90 and age_days is not None and age_days >= 90:
        return 10
    if score >= 80 and age_days is not None and age_days >= 60:
        return 8
    if score >= 70 and age_days is not None and age_days >= 30:
        return 6
    if score >= 60:
        return 4
    if score >= 40:
        return 2
    return 0


def _warmup_volume_limit(warmup_level: int) -> int:
    """Daily send limit for a given warmup level."""
    limits = {
        0: 0,
        1: 10,
        2: 50,
        3: 100,
        4: 250,
        5: 500,
        6: 1000,
        7: 2500,
        8: 5000,
        9: 10000,
        10: 50000,
    }
    return limits.get(warmup_level, 0)


def get_or_refresh_domain_reputation(
    domain: str,
    subsidiary_id: Optional[int] = None,
) -> DomainReputation:
    """Get cached reputation or refresh if older than 6 hours."""
    domain = extract_domain(domain).lower()
    rep = DomainReputation.query.filter_by(domain=domain).first()
    now = datetime.utcnow()
    if rep and rep.last_checked_at and (now - rep.last_checked_at).total_seconds() < 6 * 3600:
        return rep

    vt_result = check_virus_total(domain)
    blacklist = check_blacklists(domain)
    blacklist_ok = 'Clean' in blacklist or not blacklist
    flags: List[str] = [] if blacklist_ok else blacklist

    spf_ok, _ = check_spf(domain)
    dmarc_ok, _ = check_dmarc(domain)

    dkim_ok = False
    if subsidiary_id:
        sub = Subsidiary.query.get(subsidiary_id)
        if sub and sub.dkim_selector:
            dkim_ok, _ = check_dkim_selector(domain, sub.dkim_selector)

    age_days = _domain_age_days(domain)
    score = compute_overall_score(vt_result, flags, spf_ok, dkim_ok, dmarc_ok, age_days)
    warmup_level = _warmup_level_from_score_and_age(score, age_days)

    if not rep:
        rep = DomainReputation(domain=domain, subsidiary_id=subsidiary_id)

    rep.domain_age_days = age_days
    rep.virus_total_score = vt_result.get('score')
    rep.set_virus_total_categories(vt_result.get('categories') or {})
    rep.set_blacklist_flags(flags)
    rep.spf_ok = spf_ok
    rep.dkim_ok = dkim_ok
    rep.dmarc_ok = dmarc_ok
    rep.overall_score = score
    rep.warmup_level = warmup_level
    rep.last_checked_at = now
    db.session.add(rep)
    db.session.commit()
    return rep


def is_domain_ready_for_volume(
    subsidiary: Optional[Subsidiary],
    requested_count: int,
) -> Tuple[bool, str]:
    """Return (ok, message) for sending requested_count emails today."""
    if not subsidiary:
        return False, "No subsidiary configured"

    rep = get_or_refresh_domain_reputation(subsidiary.sending_domain, subsidiary.id)
    limit = _warmup_volume_limit(rep.warmup_level)
    today = date.today()

    if subsidiary.last_sent_date != today:
        subsidiary.daily_sent_count = 0
        subsidiary.last_sent_date = today
        db.session.add(subsidiary)
        db.session.commit()

    projected = subsidiary.daily_sent_count + requested_count
    if projected > limit:
        return False, f"Warmup limit exceeded: {projected}/{limit} for today"
    return True, f"Warmup OK ({projected}/{limit})"


def record_domain_send(subsidiary: Optional[Subsidiary], count: int = 1):
    """Increment today's send counter for a subsidiary."""
    if not subsidiary:
        return
    today = date.today()
    if subsidiary.last_sent_date != today:
        subsidiary.daily_sent_count = 0
        subsidiary.last_sent_date = today
    subsidiary.daily_sent_count += count
    db.session.add(subsidiary)
    db.session.commit()
