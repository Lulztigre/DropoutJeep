from flask import Blueprint, render_template, request

import dns.resolver
import dns.exception
import requests
import whois
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import re

from dropoutjeep_lib.models import SendingProfile
from dropoutjeep_lib.utils.auth import operator_required

urlcheck_bp = Blueprint('urlcheck', __name__, url_prefix='/admin/urlcheck')

# Optimized DNS resolver with short timeout.
resolver = dns.resolver.Resolver()
resolver.timeout = 2
resolver.lifetime = 2

BLACKLISTS = [
    "zen.spamhaus.org",
    "dbl.spamhaus.org",
    "multi.surbl.org"
]


def extract_domain(domain_or_url):
    """Extract clean domain from URL or domain string."""
    domain = re.sub(r'^https?://', '', domain_or_url)
    domain = domain.split('/')[0].split('?')[0]
    domain = domain.split(':')[0]
    return domain.strip().lower()


def check_blacklists(domain):
    """Check domain against DNS blacklists with parallel execution."""
    results = []

    def check_single_blacklist(bl):
        try:
            query = f"{domain}.{bl}"
            resolver.resolve(query, "A")
            return f"Listed on {bl}"
        except dns.resolver.NXDOMAIN:
            return None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=len(BLACKLISTS)) as executor:
        future_to_bl = {executor.submit(check_single_blacklist, bl): bl for bl in BLACKLISTS}

        for future in as_completed(future_to_bl, timeout=3):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception:
                pass

    return results if results else ["Clean"]


def check_domain_age(domain):
    """Check domain age using WHOIS with best-effort error handling."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age = (datetime.now() - creation_date).days
            return age if age >= 0 else "Unknown"
        return "Unknown"
    except Exception:
        return "Unknown"


def check_spf(domain):
    """Check SPF records with timeout handling."""
    try:
        spf_records = resolver.resolve(domain, 'TXT')
        spf_found = [r.to_text().strip('"') for r in spf_records if "v=spf1" in r.to_text()]
        return spf_found[0] if spf_found else "No SPF record found"
    except dns.resolver.NXDOMAIN:
        return "Domain does not exist"
    except dns.resolver.NoAnswer:
        return "No SPF record found"
    except dns.resolver.Timeout:
        return "DNS query timed out"
    except Exception:
        return "Unable to check SPF"


def check_http_status(domain):
    """Check HTTP status with HTTPS-first fallback to HTTP."""
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{domain}"
            r = requests.get(
                url,
                timeout=5,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            return r.status_code
        except requests.exceptions.SSLError:
            if protocol == 'https':
                continue
            return "SSL Certificate Error"
        except requests.exceptions.Timeout:
            return "Connection Timeout"
        except requests.exceptions.ConnectionError:
            return "Unable to Connect"
        except Exception:
            if protocol == 'http':
                return "Connection Failed"
    return "No Response"


def url_safety_check(domain_or_url):
    """Run parallel safety checks for a domain/URL."""
    domain = extract_domain(domain_or_url)

    result = {
        "domain": domain,
        "domain_age_days": "Checking...",
        "spf": "Checking...",
        "blacklists": "Checking...",
        "http_status": "Checking..."
    }

    with ThreadPoolExecutor(max_workers=4) as executor:
        future_age = executor.submit(check_domain_age, domain)
        future_spf = executor.submit(check_spf, domain)
        future_blacklist = executor.submit(check_blacklists, domain)
        future_http = executor.submit(check_http_status, domain)

        try:
            result["domain_age_days"] = future_age.result(timeout=5)
        except Exception:
            result["domain_age_days"] = "Check Failed"

        try:
            result["spf"] = future_spf.result(timeout=3)
        except Exception:
            result["spf"] = "Check Failed"

        try:
            blacklist_results = future_blacklist.result(timeout=4)
            result["blacklists"] = ", ".join(blacklist_results) if isinstance(blacklist_results, list) else blacklist_results
        except Exception:
            result["blacklists"] = "Check Failed"

        try:
            result["http_status"] = future_http.result(timeout=6)
        except Exception:
            result["http_status"] = "Check Failed"

    return result


@urlcheck_bp.route("/", methods=["GET", "POST"])
@operator_required
def url_check_page():
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()

        if not domain:
            return render_template("urlcheck.html", error="Please enter a domain or URL")

        if len(domain) > 253:
            return render_template("urlcheck.html", error="Domain name too long")

        try:
            data = url_safety_check(domain)
            return render_template("urlcheck.html", result=data)
        except Exception:
            return render_template("urlcheck.html", error="An error occurred while checking the domain. Please try again.")

    return render_template("urlcheck.html")
