import hmac
import hashlib
import os
import smtplib
import socket
from typing import Dict, Tuple

import dns.resolver
import dns.exception
import dns.reversename
from flask import has_app_context
from sqlalchemy import or_


def sign_token(token: str) -> str:
    """HMAC-sign a recipient token for tamper-resistant tracking URLs."""
    secret = os.environ.get('HMAC_SECRET', 'change-me-big-secret')
    return hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()


def verify_token_sig(token: str, sig: str) -> bool:
    """Verify an HMAC signature for a token."""
    if not token or not sig:
        return False
    expected = sign_token(token)
    return hmac.compare_digest(expected, sig)


def check_spf(domain: str) -> Tuple[bool, str]:
    """Return (has_spf, spf_text_or_error)."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for r in answers:
            txt = b"".join(r.strings).decode()
            if txt.lower().startswith('v=spf1'):
                return True, txt
        return False, "No SPF record found"
    except dns.exception.DNSException as e:
        return False, f"DNS error: {e}"


def check_dkim_selector(domain: str, selector: str) -> Tuple[bool, str]:
    """Return (has_dkim, value_or_error)."""
    if not selector:
        return False, 'No selector provided'
    name = f"{selector}._domainkey.{domain}"
    try:
        answers = dns.resolver.resolve(name, 'TXT')
        txts = [b"".join(r.strings).decode() for r in answers]
        joined = " ".join(txts)
        return ('p=' in joined.lower(), joined)
    except dns.exception.DNSException as e:
        return False, f"DNS error: {e}"


def check_ptr(ip: str) -> Tuple[bool, str]:
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, 'PTR')
        host = answers[0].to_text().rstrip('.')
        return True, host
    except Exception as e:
        return False, str(e)


def validate_smtp_relay(host: str, port: int = 587, user: str = None,
                        password: str = None, helo: str = None,
                        timeout: int = 10) -> Tuple[bool, str]:
    """Try a lightweight SMTP connection and optionally AUTH.

    Uses the same connection path as the mailer: implicit TLS on 465, STARTTLS
    elsewhere, with certificate verification. The previous version called
    smtplib.SMTP() and starttls() without a context, so it reported success on
    port 465 (where the server speaks TLS immediately) and on servers whose
    certificate would be rejected by a real send.
    """
    from dropoutjeep_lib.utils.mailer import _open_smtp
    smtp = None
    try:
        smtp = _open_smtp(host, port, timeout)
        if user and password:
            smtp.login(user, password)
        code = smtp.noop()[0]
        return (code == 250, f"NOOP response {code}")
    except Exception as e:
        return (False, str(e)[:300])
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                pass


def check_spoof_alignment(from_header: str, envelope_from: str) -> Dict:
    """Compare the visible From: domain with the envelope sender domain.
    Returns a dict with aligned flags and DNS auth results for the From domain.
    """
    import email.utils
    from dropoutjeep_lib.utils.dkim_utils import check_dmarc

    _, from_addr = email.utils.parseaddr(from_header)
    _, env_addr = email.utils.parseaddr(envelope_from)
    from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ''
    env_domain = env_addr.split('@')[-1].lower() if '@' in env_addr else ''

    spf_ok, spf_txt = check_spf(from_domain) if from_domain else (False, 'No From domain')
    dmarc_ok, dmarc_txt = check_dmarc(from_domain) if from_domain else (False, 'No From domain')

    return {
        'from_domain': from_domain,
        'envelope_domain': env_domain,
        'domains_aligned': from_domain == env_domain,
        'spf': {'ok': spf_ok, 'txt': spf_txt},
        'dmarc': {'ok': dmarc_ok, 'txt': dmarc_txt},
    }


def validate_campaign_before_launch(campaign_id: int) -> Dict:
    """Preflight checks before a campaign is allowed to launch."""
    from dropoutjeep_lib.models import Campaign, SendingProfile, Recipient, SuppressedEmail, ProxyDomain
    from dropoutjeep_lib.utils.domain_reputation import (
        get_or_refresh_domain_reputation,
        is_domain_ready_for_volume,
    )
    from dropoutjeep_lib.utils.redirectors import (
        get_campaign_redirector_templates,
        check_redirector_health,
    )

    result = {'ok': True, 'errors': [], 'checks': {}, 'warnings': []}
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        result['ok'] = False
        result['errors'].append('Campaign not found')
        return result

    sp = campaign.sending_profile
    if not sp:
        result['ok'] = False
        result['errors'].append('No sending profile selected')
        return result

    sub = sp.subsidiary
    domain = sub.sending_domain if sub else None
    selector = sub.dkim_selector if sub else None

    spf_ok, spf_txt = check_spf(domain) if domain else (False, 'No domain')
    dkim_ok, dkim_txt = check_dkim_selector(domain, selector) if domain and selector else (False, 'No domain/selector')
    smtp_ok, smtp_txt = validate_smtp_relay(sp.smtp_host or '', sp.smtp_port or 587,
                                            sp.smtp_user, sp.get_smtp_pass())

    result['checks'] = {
        'spf': {'ok': spf_ok, 'txt': spf_txt},
        'dkim': {'ok': dkim_ok, 'txt': dkim_txt},
        'smtp': {'ok': smtp_ok, 'txt': smtp_txt},
    }

    if not spf_ok:
        result['ok'] = False
        result['errors'].append(f'SPF validation failed: {spf_txt}')
    if not dkim_ok:
        result['ok'] = False
        result['errors'].append(f'DKIM validation failed: {dkim_txt}')
    if not smtp_ok:
        result['ok'] = False
        result['errors'].append(f'SMTP validation failed: {smtp_txt}')

    # Domain reputation + warmup check
    if campaign.domain_reputation_check_enabled and sub:
        try:
            rep = get_or_refresh_domain_reputation(domain, sub.id)
            unsent_count = Recipient.query.filter_by(
                campaign_id=campaign_id, sent_at=None
            ).count()
            warmup_ok, warmup_msg = is_domain_ready_for_volume(sub, unsent_count)
            result['checks']['domain_reputation'] = {
                'overall_score': rep.overall_score,
                'warmup_level': rep.warmup_level,
                'virus_total_score': rep.virus_total_score,
                'domain_age_days': rep.domain_age_days,
                'blacklist_flags': rep.get_blacklist_flags(),
                'spf_ok': rep.spf_ok,
                'dkim_ok': rep.dkim_ok,
                'dmarc_ok': rep.dmarc_ok,
                'warmup_message': warmup_msg,
                'warmup_ok': warmup_ok,
            }
            if rep.overall_score < 60:
                result['warnings'].append(
                    f"Domain reputation score is {rep.overall_score}/100. Consider warming the domain before launch."
                )
            if not warmup_ok:
                result['ok'] = False
                result['errors'].append(f"Warmup check failed: {warmup_msg}")
        except Exception as exc:
            result['warnings'].append(f"Could not complete domain reputation check: {exc}")

    # Redirector chain health check
    redirector_templates = get_campaign_redirector_templates(campaign)
    redirector_checks = []
    for template in redirector_templates:
        healthy, error = check_redirector_health(template)
        redirector_checks.append({
            'template': template,
            'healthy': healthy,
            'error': error,
        })
        if not healthy:
            result['warnings'].append(
                f"Redirector unhealthy (will be skipped): {template} — {error}"
            )
    if redirector_checks:
        result['checks']['redirectors'] = redirector_checks

    # Spoofing / alignment warning
    if sub:
        envelope = f"bounce@{sub.bounce_subdomain or sub.sending_domain}"
        from_header = f"{sub.display_name} <{sub.from_address}>"
        alignment = check_spoof_alignment(from_header, envelope)
        result['checks']['alignment'] = alignment
        if not alignment['domains_aligned']:
            result['warnings'].append(
                f"From domain ({alignment['from_domain']}) does not align with envelope domain ({alignment['envelope_domain']}). "
                "This may look spoofed to mail filters."
            )

    # DMARC check
    if sub:
        from dropoutjeep_lib.utils.dkim_utils import check_dmarc, check_bimi
        from dropoutjeep_lib.utils.fbl import get_spam_complaint_rate
        dmarc_ok, dmarc_txt = check_dmarc(domain)
        result['checks']['dmarc'] = {'ok': dmarc_ok, 'txt': dmarc_txt}
        if not dmarc_ok:
            result['ok'] = False
            result['errors'].append(f"DMARC validation failed: {dmarc_txt}")

        bimi_ok, bimi_txt = check_bimi(domain)
        result['checks']['bimi'] = {'ok': bool(bimi_ok), 'txt': bimi_txt}

        fbl_info = get_spam_complaint_rate(domain)
        result['checks']['fbl'] = {'domain': domain, 'info': fbl_info}

    # Recipients exist
    if has_app_context():
        recipient_count = Recipient.query.filter_by(campaign_id=campaign_id).count()
        unsent_count = Recipient.query.filter_by(campaign_id=campaign_id, sent_at=None).count()
        result['checks']['recipients'] = {'total': recipient_count, 'unsent': unsent_count}
        if recipient_count == 0:
            result['ok'] = False
            result['errors'].append('Campaign has no recipients')
        elif unsent_count == 0:
            result['warnings'].append('All recipients have already been sent to')

        # Suppression list hits
        suppressed = []
        if recipient_count > 0:
            recipients = Recipient.query.filter_by(campaign_id=campaign_id).all()
            for r in recipients:
                if SuppressedEmail.query.filter(
                    or_(SuppressedEmail.email == r.email.lower(),
                        SuppressedEmail.domain == r.email.lower().split('@')[-1])
                ).first():
                    suppressed.append(r.email)
        result['checks']['suppressions'] = {'count': len(suppressed), 'emails': suppressed}
        if suppressed:
            result['warnings'].append(
                f"{len(suppressed)} recipient(s) match the suppression list: {', '.join(suppressed[:5])}"
            )

        # Reverse-proxy domain + TLS readiness
        if campaign.flow_type == 'reverse_proxy':
            pd = ProxyDomain.query.filter_by(campaign_id=campaign_id).first()
            result['checks']['proxy_domain'] = {
                'present': pd is not None,
                'domain': pd.domain if pd else None,
                'tls_ready': pd.tls_ready if pd else False,
                'is_wildcard': pd.is_wildcard if pd else False,
            }
            if not pd:
                result['ok'] = False
                result['errors'].append('Reverse-proxy campaign has no provisioned proxy domain')
            elif not pd.tls_ready and pd.auto_tls_enabled:
                result['ok'] = False
                result['errors'].append(f'Proxy domain {pd.domain} TLS is not ready')
            elif not pd.tls_ready:
                result['warnings'].append(f'Proxy domain {pd.domain} exists but TLS is not ready')
    else:
        result['warnings'].append('Skipping recipient/suppression/proxy-domain checks outside of app context')

    return result
