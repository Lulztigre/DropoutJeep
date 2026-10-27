"""Sender identity rotation for campaigns.

A SenderRotationPool contains ordered entries. Each recipient in a campaign
send gets the next entry in round-robin order; the CampaignJob.rotation_index
persists progress across batches and restarts.
"""

from typing import Optional, Tuple

from dropoutjeep_lib.models import SenderRotationPool, SenderRotationEntry


def get_next_identity(
    pool_id: int,
    current_index: int,
) -> Tuple[Optional[SenderRotationEntry], int]:
    """Return the next entry and the incremented rotation index."""
    pool = SenderRotationPool.query.get(pool_id)
    if not pool:
        return None, current_index
    entries = sorted(pool.entries, key=lambda e: e.sort_order)
    if not entries:
        return None, current_index
    entry = entries[current_index % len(entries)]
    return entry, current_index + 1


def build_identity_for_entry(entry: SenderRotationEntry) -> Tuple[str, str, Optional[str], dict]:
    """Build envelope/from/reply-to and mailer kwargs from a rotation entry.

    Returns (envelope_from, from_header, reply_to, mailer_kwargs).
    """
    sp = entry.sending_profile
    sub = entry.subsidiary or (sp.subsidiary if sp else None)

    from_addr = entry.from_address_override or (sub.from_address if sub else sp.smtp_user)
    display_name = entry.display_name_override or (sub.display_name if sub else sp.name)
    if sub:
        if sub.bounce_subdomain and '.' in sub.bounce_subdomain:
            envelope_domain = sub.bounce_subdomain
        elif sub.bounce_subdomain:
            envelope_domain = f"{sub.bounce_subdomain}.{sub.sending_domain}"
        else:
            envelope_domain = sub.sending_domain
    else:
        envelope_domain = from_addr.split('@')[-1]

    envelope_from = f"bounce@{envelope_domain}"
    from_header = f"{display_name} <{from_addr}>"
    reply_to = f"security@{sub.sending_domain}" if sub else None

    mailer_kwargs = {
        'smtp_host': sp.smtp_host,
        'smtp_port': sp.smtp_port or 25,
        'smtp_user': sp.smtp_user,
        'smtp_pass': sp.get_smtp_pass(),
        'use_tls': sp.use_tls,
        'dkim_selector': sub.dkim_selector if sub else None,
        'dkim_domain': sub.sending_domain if sub else None,
        'dkim_private_key': sub.get_dkim_private_key() if sub else None,
    }

    return envelope_from, from_header, reply_to, mailer_kwargs
