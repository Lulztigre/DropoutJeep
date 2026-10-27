"""Campaign clone and versioning helpers."""

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, Recipient


def clone_campaign(campaign_id: int, new_name: str | None = None, copy_recipients: bool = True) -> Campaign:
    """Duplicate a campaign and optionally its recipient list."""
    source = Campaign.query.get_or_404(campaign_id)
    name = new_name or f'{source.name} (Copy)'

    # Ensure name uniqueness by appending a counter if needed.
    base_name = name
    counter = 1
    while Campaign.query.filter_by(name=name).first():
        name = f'{base_name} ({counter})'
        counter += 1

    campaign = Campaign(
        name=name,
        subject=source.subject,
        body_html=source.body_html,
        template_html=source.template_html,
        landing_html=source.landing_html,
        sending_profile_id=source.sending_profile_id,
        parent_campaign_id=source.id,
        flow_type=source.flow_type,
        flow_config=source.flow_config,
        calendar_invite=source.calendar_invite,
        calendar_event_title=source.calendar_event_title,
        calendar_event_location=source.calendar_event_location,
        calendar_event_start=source.calendar_event_start,
        calendar_event_end=source.calendar_event_end,
    )
    db.session.add(campaign)
    db.session.flush()

    if copy_recipients:
        for r in Recipient.query.filter_by(campaign_id=source.id).all():
            db.session.add(Recipient(
                email=r.email,
                name=r.name,
                external_id=r.external_id,
                campaign_id=campaign.id,
            ))

    db.session.commit()
    return campaign


def restore_campaign_version(campaign_id: int, version_id: int, user_id: int | None = None) -> dict:
    """Restore a campaign to a previous version, snapshotting current state first."""
    campaign = Campaign.query.get_or_404(campaign_id)
    version = CampaignVersion.query.filter_by(id=version_id, campaign_id=campaign_id).first_or_404()
    pre = campaign.snapshot_version(
        user_id=user_id,
        notes=f'Pre-restore snapshot before version {version.version_number}'
    )
    db.session.add(pre)
    campaign.name = version.name
    campaign.subject = version.subject
    campaign.body_html = version.body_html
    campaign.template_html = version.body_html
    campaign.landing_html = version.landing_html
    campaign.flow_config = version.flow_config
    db.session.commit()
    return {'status': 'restored', 'campaign_id': campaign.id, 'version_id': version.id}
