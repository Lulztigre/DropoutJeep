"""DNS provider integrations for automatic multi-domain phishing infrastructure."""

from .providers import (
    DNSProvider,
    CloudflareDNSProvider,
    Route53DNSProvider,
    DigitalOceanDNSProvider,
    ManualDNSProvider,
    NoopDNSProvider,
    get_dns_provider,
)
from .manager import DNSManager

__all__ = [
    "DNSProvider",
    "CloudflareDNSProvider",
    "Route53DNSProvider",
    "DigitalOceanDNSProvider",
    "ManualDNSProvider",
    "NoopDNSProvider",
    "get_dns_provider",
    "DNSManager",
]
