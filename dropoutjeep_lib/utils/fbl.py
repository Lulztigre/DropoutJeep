"""Feedback Loop (FBL) registration helper for authorized phishing simulations.

Helps operators register sending domains with Gmail FBL, Microsoft SNDS/JMRP,
Comcast, and Yahoo FBL programs. Generates DNS records and confirmation emails
needed to register. Tracks spam complaint rates per sending domain.

Per gap analysis item 12: Without FBL registration, the framework has no
visibility into spam complaint rates — a critical deliverability signal.
"""

import json
import logging
from typing import Optional
from datetime import datetime

logger = logging.getLogger("dropoutjeep")

# FBL program registry
FBL_PROGRAMS = {
    "gmail": {
        "name": "Gmail FBL",
        "registration_url": "https://gmail.com/postmaster",
        "dns_record_type": "TXT",
        "dns_record_format": "google._domainkey.{domain}",
        "requires_confirmation": True,
        "notes": "Register via Google Postmaster Tools. Requires domain verification.",
    },
    "microsoft_snds": {
        "name": "Microsoft SNDS (Smart Network Data Services)",
        "registration_url": "https://sender.office.com",
        "dns_record_type": "TXT",
        "dns_record_format": "{domain}",
        "requires_confirmation": True,
        "notes": "Register at sender.office.com. Provides data on Outlook/O365 delivery.",
    },
    "microsoft_jmrp": {
        "name": "Microsoft JMRP (Junk Mail Reporting Program)",
        "registration_url": "https://postmaster.live.com/snds/JMRP.aspx",
        "dns_record_type": "TXT",
        "dns_record_format": "{domain}",
        "requires_confirmation": True,
        "notes": "Junk Mail Reporting Program — receive complaint feedback from Hotmail/Outlook.",
    },
    "comcast": {
        "name": "Comcast FBL",
        "registration_url": "https://postmaster.comcast.net",
        "dns_record_type": "TXT",
        "dns_record_format": "comcast._domainkey.{domain}",
        "requires_confirmation": True,
        "notes": "Register at Comcast Postmaster for complaint feedback.",
    },
    "yahoo": {
        "name": "Yahoo CFL (Complaint Feedback Loop)",
        "registration_url": "https://help.yahoo.com/kb/postmaster",
        "dns_record_type": "TXT",
        "dns_record_format": "yahoo._domainkey.{domain}",
        "requires_confirmation": True,
        "notes": "Register via Yahoo Postmaster help pages.",
    },
    "verizon": {
        "name": "Verizon Media CFL",
        "registration_url": "https://postmaster.verizonmedia.com",
        "dns_record_type": "TXT",
        "dns_record_format": "verizon._domainkey.{domain}",
        "requires_confirmation": True,
        "notes": "Covers AOL and Yahoo after merger.",
    },
}


def list_fbl_programs() -> list[dict]:
    """List all supported FBL programs with registration details."""
    return [
        {
            "key": key,
            "name": info["name"],
            "registration_url": info["registration_url"],
            "dns_record_type": info["dns_record_type"],
            "notes": info["notes"],
        }
        for key, info in FBL_PROGRAMS.items()
    ]


def get_fbl_program(key: str) -> Optional[dict]:
    """Get details for a specific FBL program."""
    return FBL_PROGRAMS.get(key)


def generate_fbl_confirmation(domain: str, fbl_key: str) -> dict:
    """Generate DNS records and confirmation email content for FBL registration.

    Args:
        domain: The sending domain to register
        fbl_key: FBL program key (e.g. 'gmail', 'microsoft_snds')

    Returns:
        Dict with 'dns_records' (list of str), 'confirmation_email' (dict with subject, body),
        'registration_url' (str), 'notes' (str)
    """
    program = FBL_PROGRAMS.get(fbl_key)
    if not program:
        raise ValueError(f"Unknown FBL program: {fbl_key}. Available: {list(FBL_PROGRAMS.keys())}")

    # Generate DNS record
    dns_record_name = program["dns_record_format"].format(domain=domain)
    dns_record = f"{dns_record_name} IN TXT \"v=FBL1; r={domain}; o=postmaster@{domain}\""

    # Generate confirmation email content
    confirmation = {
        "subject": f"FBL Registration Request — {domain}",
        "body": f"""Dear {program['name']} Team,

We would like to register the domain {domain} for your Feedback Loop program.

Domain: {domain}
Sending IP range: (to be provided)
Postmaster contact: postmaster@{domain}
DNS verification record: {dns_record_name}
Record value: v=FBL1; r={domain}; o=postmaster@{domain}

Please confirm registration and let us know if additional information is required.

Best regards,
Postmaster Team — {domain}
""",
    }

    return {
        "dns_records": [dns_record],
        "confirmation_email": confirmation,
        "registration_url": program["registration_url"],
        "notes": program["notes"],
    }


def generate_all_fbl_registrations(domain: str) -> dict:
    """Generate registration materials for all supported FBL programs.

    Args:
        domain: The sending domain to register

    Returns:
        Dict keyed by FBL program key, each with registration materials.
    """
    results = {}
    for key in FBL_PROGRAMS:
        try:
            results[key] = generate_fbl_confirmation(domain, key)
        except Exception as e:
            logger.warning("FBL registration generation failed for %s: %s", key, e)
            results[key] = {"error": str(e)}
    return results


# Spam complaint tracking — uses the framework's Event model if available
def record_spam_complaint(domain: str, recipient: str, source: str = "fbl",
                           complaint_data: dict = None) -> bool:
    """Record a spam complaint from an FBL notification.

    Args:
        domain: Sending domain that received the complaint
        recipient: Email address that complained
        source: FBL source (gmail, microsoft_snds, etc.)
        complaint_data: Additional complaint data from the FBL notification

    Returns:
        True if recorded successfully.
    """
    try:
        from dropoutjeep_lib import db
        from dropoutjeep_lib.models import Event
        from dropoutjeep_lib.models import SendingProfile

        # Find the sending profile for this domain
        profile = SendingProfile.query.filter_by(envelope_from_domain=domain).first()
        profile_id = profile.id if profile else None

        e = Event(
            event_type='spam_complaint',
            campaign_id=None,
            recipient_id=None,
            meta=json.dumps({
                'domain': domain,
                'recipient': recipient,
                'source': source,
                'profile_id': profile_id,
                'complaint_data': complaint_data or {},
                'timestamp': datetime.utcnow().isoformat(),
            }),
        )
        db.session.add(e)
        db.session.commit()
        logger.info("Spam complaint recorded: domain=%s recipient=%s source=%s",
                    domain, recipient, source)
        return True
    except Exception as e:
        logger.error("Failed to record spam complaint: %s", e)
        return False


def get_spam_complaint_rate(domain: str, days: int = 7) -> dict:
    """Calculate spam complaint rate for a domain.

    Args:
        domain: Sending domain
        days: Look-back window in days

    Returns:
        Dict with 'total_sent', 'total_complaints', 'complaint_rate'
    """
    try:
        from dropoutjeep_lib import db
        from dropoutjeep_lib.models import Event, SendingProfile
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(days=days)

        # Count complaints
        complaints = Event.query.filter(
            Event.event_type == 'spam_complaint',
            Event.created_at >= cutoff,
        ).all()

        domain_complaints = [
            e for e in complaints
            if json.loads(e.meta or '{}').get('domain') == domain
        ]

        # Count total sent (from send events)
        sends = Event.query.filter(
            Event.event_type == 'email_sent',
            Event.created_at >= cutoff,
        ).all()

        domain_sends = [
            e for e in sends
            if json.loads(e.meta or '{}').get('domain') == domain
        ]

        total_sent = len(domain_sends)
        total_complaints = len(domain_complaints)
        rate = (total_complaints / total_sent * 100) if total_sent > 0 else 0.0

        return {
            'total_sent': total_sent,
            'total_complaints': total_complaints,
            'complaint_rate': round(rate, 4),
            'days': days,
            'domain': domain,
        }
    except Exception as e:
        logger.error("Failed to get spam complaint rate: %s", e)
        return {
            'total_sent': 0,
            'total_complaints': 0,
            'complaint_rate': 0.0,
            'days': days,
            'domain': domain,
            'error': str(e),
        }
