"""Multi-domain campaign URL generation and provisioning.

When a campaign has an active wildcard ProxyDomain, per-recipient URLs use
``https://<recipient_token>.<base_domain>/`` instead of the default
``/proxy/<campaign_id>/t/<token>/`` path.
"""

import logging

from dropoutjeep_lib.models import ProxyDomain

logger = logging.getLogger(__name__)


def get_campaign_wildcard_domain(campaign_id: int) -> ProxyDomain | None:
    """Return the first active wildcard ProxyDomain for a campaign."""
    return ProxyDomain.query.filter_by(
        campaign_id=campaign_id,
        is_active=True,
        is_wildcard=True,
    ).first()


def get_recipient_proxy_url(
    campaign_id: int,
    token: str,
    base_url: str,
    scheme: str = "https",
) -> str:
    """Return the proxy URL for a recipient, using a clean domain if available."""
    pd = get_campaign_wildcard_domain(campaign_id)
    if pd and pd.base_domain:
        return f"{scheme}://{token}.{pd.base_domain}/"
    return f"{base_url}/proxy/{campaign_id}/t/{token}/"


def ensure_wildcard_domain_provisioned(campaign_id: int) -> tuple[bool, str]:
    """Provision DNS and TLS for a campaign's wildcard ProxyDomain."""
    pd = get_campaign_wildcard_domain(campaign_id)
    if not pd:
        return True, "no wildcard domain configured"

    if pd.is_fully_provisioned():
        return True, "already provisioned"

    from dropoutjeep_lib.dns import DNSManager
    dns_ok = DNSManager(pd).provision()
    if not dns_ok:
        return False, "DNS provisioning failed"

    if pd.auto_tls_enabled:
        from dropoutjeep_lib.utils.tls_provisioner import provision_tls
        tls_ok = provision_tls(pd)
        if not tls_ok:
            return False, f"TLS provisioning failed: {pd.provision_error or 'unknown error'}"

    return True, "provisioned"
