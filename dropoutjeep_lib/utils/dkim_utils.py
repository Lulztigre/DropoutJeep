import base64
import dkim
import dns.resolver
import dns.exception
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_dkim_keypair(domain: str, selector: str):
    """
    Generate a DKIM RSA keypair for a domain and selector.
    Returns (private_key_pem, public_dns_txt)
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    pubkey = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    b64_pub = base64.b64encode(pubkey).decode().replace("\n", "")

    # DNS-friendly record format
    dns_txt = f"v=DKIM1; k=rsa; p={b64_pub}"

    return private_pem, dns_txt


def format_dkim_dns_record(domain: str, selector: str, public_txt: str):
    """
    Return the formatted DNS record for DKIM.
    Example output:
      selector._domainkey.example.com IN TXT "v=DKIM1; k=rsa; p=..."
    """
    return f'{selector}._domainkey.{domain} IN TXT "{public_txt}"'


def sign_email(message_bytes, selector, domain, private_key):
    """DKIM-sign a message. Returns signed bytes (signature + original message).

    Header coverage matches enterprise_mailer.py — includes Message-ID,
    Reply-To, List-Unsubscribe, and Content-Transfer-Encoding so Gmail's
    DKIM verifier sees a strong signature (a DKIM signature without Message-ID
    is a weak signal per the gap analysis).
    """
    headers = [
        b"from", b"to", b"subject", b"date",
        b"message-id", b"reply-to", b"list-unsubscribe",
        b"mime-version", b"content-type", b"content-transfer-encoding",
    ]
    sig = dkim.sign(
        message_bytes,
        selector=selector.encode(),
        domain=domain.encode(),
        privkey=private_key.encode(),
        include_headers=headers
    )
    return sig + message_bytes


def check_dkim(domain, selector):
    """Return (boolean, details string) for DKIM selector record presence and value."""
    if not selector:
        return None, "No selector provided"
    name = f"{selector}._domainkey.{domain}"
    try:
        answers = dns.resolver.resolve(name, 'TXT')
        txts = []
        for r in answers:
            for s in r.strings:
                txts.append(s.decode() if isinstance(s, bytes) else str(s))
        joined = ' '.join(txts)
        has_p = 'p=' in joined.lower()
        return has_p, joined
    except dns.exception.DNSException as e:
        return None, f"DNS error: {e}"


def check_dmarc(domain):
    """Check _dmarc TXT record."""
    name = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(name, 'TXT')
        txts = []
        for r in answers:
            for s in r.strings:
                txts.append(s.decode() if isinstance(s, bytes) else str(s))
        joined = ' '.join(txts)
        has_dmarc = 'v=dmarc1' in joined.lower()
        return has_dmarc, joined
    except dns.exception.DNSException as e:
        return None, f"DNS error: {e}"


def check_bimi(domain):
    """Check default._bimi.<domain> TXT record presence.

    BIMI (Brand Indicators for Message Identification) allows Gmail/Outlook
    to display sender logos in the inbox list view, dramatically increasing
    open rates and signalling legitimacy to the filter.
    """
    name = f"default._bimi.{domain}"
    try:
        answers = dns.resolver.resolve(name, 'TXT')
        txts = []
        for r in answers:
            for s in r.strings:
                txts.append(s.decode() if isinstance(s, bytes) else str(s))
        joined = ' '.join(txts)
        has_bimi = 'v=BIMI1' in joined.lower()
        return has_bimi, joined
    except dns.exception.DNSException as e:
        return None, f"DNS error: {e}"


def generate_bimi_record(domain: str, logo_url: str) -> str:
    """Generate a BIMI DNS TXT record.

    BIMI requires a VMC (Verified Mark Certificate) for Gmail display.
    The operator obtains the VMC separately; this generates the DNS record.

    Args:
        domain: Sending domain (e.g. example.com)
        logo_url: HTTPS URL to the SVG logo file

    Returns:
        Formatted DNS TXT record string.
    """
    return f'default._bimi.{domain} IN TXT "v=BIMI1; l={logo_url}"'


def dkim_spf_check(domain):
    results = {}

    # SPF
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        for record in spf_records:
            txt = record.to_text().strip('"')
            if txt.startswith("v=spf1"):
                results['spf'] = txt
                break
        else:
            results['spf'] = "No SPF record found"
    except Exception as e:
        results['spf'] = f"SPF check error: {e}"

    # DKIM (default selector)
    try:
        dkim_selector = "default"
        dkim_domain = f"{dkim_selector}._domainkey.{domain}"
        dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
        results['dkim'] = [r.to_text().strip('"') for r in dkim_records]
    except Exception as e:
        results['dkim'] = f"DKIM check error: {e}"

    return results
