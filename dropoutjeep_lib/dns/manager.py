"""High-level DNS provisioning manager for ProxyDomain records."""

import logging

from .providers import get_dns_provider

logger = logging.getLogger(__name__)


class DNSManager:
    """Manage DNS records for a ProxyDomain."""

    def __init__(self, proxy_domain):
        self.proxy_domain = proxy_domain
        self.provider = get_dns_provider(
            proxy_domain.dns_provider,
            proxy_domain.get_dns_credentials(),
        )

    def _wildcard_name(self) -> str:
        """Return the wildcard record name, e.g. *.phish.example.com."""
        return f"*.{self.proxy_domain.base_domain}"

    def provision(self) -> bool:
        """Create the wildcard A record for this domain."""
        pd = self.proxy_domain
        if not pd.is_wildcard:
            return True
        if pd.dns_provider == "none":
            logger.info("DNS provider is none; skipping wildcard record creation")
            return True
        if not pd.server_ip:
            logger.error("Cannot provision DNS: server_ip is not set")
            return False
        name = self._wildcard_name()
        return self.provider.create_record(name, "A", pd.server_ip)

    def deprovision(self) -> bool:
        """Delete the wildcard A record for this domain."""
        pd = self.proxy_domain
        if not pd.is_wildcard or pd.dns_provider == "none":
            return True
        if not pd.server_ip:
            return True
        name = self._wildcard_name()
        return self.provider.delete_record(name, "A", pd.server_ip)

    def provision_subdomain(self, subdomain: str) -> bool:
        """Create an A record for a single recipient subdomain.

        Not needed when a wildcard record is used, but exposed for providers
        that do not support wildcards.
        """
        pd = self.proxy_domain
        if pd.dns_provider == "none":
            return True
        if not pd.server_ip:
            return False
        name = f"{subdomain}.{pd.base_domain}"
        return self.provider.create_record(name, "A", pd.server_ip)
