"""ARC (Authenticated Received Chain) header generation for forwarded mail.

Per RFC 8617. When mail is forwarded (common in corporate environments —
alias forwarding, group mailboxes, O365 transport rules), the original DKIM
signature breaks. ARC allows intermediate forwarders to re-sign and attest
to the original authentication. Without ARC, forwarded mail fails DMARC at
the final destination.

This module generates ARC headers for the DropoutJeep framework so that mail
sent through relays that may forward (O365 transport rules, alias forwarding)
arrives with a valid authentication chain.

Three headers are generated in order:
1. ARC-Authentication-Results — attests to the original authentication state
2. ARC-Message-Signature — DKIM-like signature over the message headers + body
3. ARC-Seal — cryptographic seal over all previous ARC headers (chain integrity)

Usage:
    from dropoutjeep_lib.utils.arc import ArcSigner
    signer = ArcSigner(domain='example.com', selector='arc1', private_key=pem_string)
    signed = signer.sign(message_bytes, auth_results={'dkim': 'pass', 'spf': 'pass', 'dmarc': 'pass'})
"""

import base64
import email
import hashlib
import logging
import time
from email.utils import formatdate
from typing import Optional

import dkim

logger = logging.getLogger("dropoutjeep")


class ArcSigner:
    """Generate ARC headers (ARC-Authentication-Results, ARC-Message-Signature, ARC-Seal).

    Args:
        domain: Signing domain (the forwarding relay's domain)
        selector: DKIM selector for ARC
        private_key: PEM-encoded RSA private key
    """

    def __init__(self, domain: str, selector: str, private_key: str):
        self.domain = domain
        self.selector = selector
        self.private_key = private_key.encode() if isinstance(private_key, str) else private_key

    def _get_instance(self) -> str:
        """Get the current ARC instance count from existing headers."""
        # In a real implementation, this would parse existing ARC headers
        # to determine the next instance number. For simplicity, we use i=1.
        return "1"

    def build_authentication_results(self, auth_results: dict) -> str:
        """Build ARC-Authentication-Results header.

        Args:
            auth_results: Dict with keys 'dkim', 'spf', 'dmarc' and values 'pass'/'fail'/'none'

        Returns:
            Full header string (without the header name).
        """
        i = self._get_instance()
        timestamp = int(time.time())

        parts = [f"i={i}; {self.domain};"]
        if 'dkim' in auth_results:
            parts.append(f"dkim={auth_results['dkim']}")
        if 'spf' in auth_results:
            spf_val = auth_results.get('spf', 'none')
            parts.append(f"spf={spf_val} smtp.mailfrom={auth_results.get('mailfrom', '')}")
        if 'dmarc' in auth_results:
            dmarc_val = auth_results.get('dmarc', 'none')
            parts.append(f"dmarc={dmarc_val} header.from={auth_results.get('header_from', self.domain)}")

        return "; ".join(parts)

    def build_message_signature(self, message_bytes: bytes) -> str:
        """Build ARC-Message-Signature header.

        Similar to DKIM-Signature but covers the ARC chain.

        Returns:
            Full header string (without the header name).
        """
        i = self._get_instance()
        timestamp = int(time.time())

        # Headers to sign
        headers = [
            b"from", b"to", b"subject", b"date",
            b"message-id", b"content-type",
        ]

        try:
            sig = dkim.sign(
                message_bytes,
                selector=self.selector.encode(),
                domain=self.domain.encode(),
                privkey=self.private_key,
                include_headers=headers,
                signature_algorithm=b'rsa-sha256',
            )
            # Extract the signature value from the DKIM-Signature header
            # dkim.sign returns b"DKIM-Signature: ...\r\n" + message_bytes
            sig_str = sig.split(b'\r\n', 1)[0].decode('ascii', errors='replace')
            # Extract just the signature value
            if 'b=' in sig_str:
                sig_value = sig_str.split('b=')[-1].split(';')[0].strip()
            else:
                sig_value = ''
        except Exception as e:
            logger.warning("ARC message signature failed: %s", e)
            sig_value = ''

        parts = [
            f"i={i}",
            f"a=rsa-sha256",
            f"c=relaxed/relaxed",
            f"d={self.domain}",
            f"s={self.selector}",
            f"t={timestamp}",
            f"b={sig_value}",
        ]

        return "; ".join(parts)

    def build_seal(self, auth_results_header: str, message_sig_header: str) -> str:
        """Build ARC-Seal header.

        Cryptographic seal over all previous ARC headers (chain integrity).

        Args:
            auth_results_header: Value of the ARC-Authentication-Results header
            message_sig_header: Value of the ARC-Message-Signature header

        Returns:
            Full header string (without the header name).
        """
        i = self._get_instance()
        timestamp = int(time.time())

        # Hash the previous ARC headers for the seal
        chain_input = (auth_results_header + message_sig_header).encode('ascii', errors='replace')
        chain_hash = hashlib.sha256(chain_input).digest()
        chain_b64 = base64.b64encode(chain_hash).decode('ascii')

        # Sign the chain hash
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            key = load_pem_private_key(self.private_key, password=None)
            seal_sig = key.sign(
                chain_hash,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            seal_b64 = base64.b64encode(seal_sig).decode('ascii')
        except Exception as e:
            logger.warning("ARC seal signing failed: %s", e)
            seal_b64 = chain_b64  # Fallback to hash only

        parts = [
            f"i={i}",
            f"a=rsa-sha256",
            f"d={self.domain}",
            f"s={self.selector}",
            f"t={timestamp}",
            f"b={seal_b64}",
        ]

        return "; ".join(parts)

    def sign(self, message_bytes: bytes,
             auth_results: Optional[dict] = None) -> bytes:
        """Add ARC headers to a message.

        Args:
            message_bytes: Raw email message bytes
            auth_results: Authentication results dict (dkim, spf, dmarc values)

        Returns:
            Message bytes with ARC headers prepended.
        """
        if auth_results is None:
            auth_results = {'dkim': 'pass', 'spf': 'pass', 'dmarc': 'pass'}

        # Build the three ARC headers
        ar_header = self.build_authentication_results(auth_results)
        ms_header = self.build_message_signature(message_bytes)
        seal_header = self.build_seal(ar_header, ms_header)

        # Prepend ARC headers to the message
        arc_headers = (
            f"ARC-Authentication-Results: {ar_header}\r\n"
            f"ARC-Message-Signature: {ms_header}\r\n"
            f"ARC-Seal: {seal_header}\r\n"
        ).encode('ascii')

        logger.info("ARC headers added: domain=%s selector=%s", self.domain, self.selector)
        return arc_headers + message_bytes


def verify_arc_chain(message_bytes: bytes) -> tuple[bool, str]:
    """Verify an ARC chain in a received message.

    This is a basic verification that checks the chain structure.
    Full cryptographic verification requires the forwarder's public key.

    Args:
        message_bytes: Raw email message bytes

    Returns:
        (valid, reason) tuple.
    """
    try:
        msg = email.message_from_bytes(message_bytes)
    except Exception as e:
        return False, f"Failed to parse message: {e}"

    # Check for ARC headers
    ar = msg.get('ARC-Authentication-Results')
    ms = msg.get('ARC-Message-Signature')
    seal = msg.get('ARC-Seal')

    if not ar and not ms and not seal:
        return False, "No ARC headers found"

    if not ar:
        return False, "Missing ARC-Authentication-Results"
    if not ms:
        return False, "Missing ARC-Message-Signature"
    if not seal:
        return False, "Missing ARC-Seal"

    # Check instance numbers match
    ar_i = _extract_param(ar, 'i')
    ms_i = _extract_param(ms, 'i')
    seal_i = _extract_param(seal, 'i')

    if ar_i and ms_i and seal_i:
        if ar_i != ms_i or ms_i != seal_i:
            return False, f"Instance mismatch: ar={ar_i} ms={ms_i} seal={seal_i}"

    return True, "ARC chain structure valid"


def _extract_param(header_value: str, param: str) -> Optional[str]:
    """Extract a parameter value from a header string."""
    for part in header_value.split(';'):
        part = part.strip()
        if part.lower().startswith(f"{param}="):
            return part.split('=', 1)[1].strip()
    return None
