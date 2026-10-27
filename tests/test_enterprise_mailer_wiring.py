"""Tests for enterprise mailer selection in the dialer."""

import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, SendingProfile, Subsidiary, Recipient
from dropoutjeep_lib.utils.dialer import create_mailer
from dropoutjeep_lib.utils.mailer import Mailer
from dropoutjeep_lib.utils.enterprise_mailer import EnterpriseMailer


@pytest.fixture
def ctx():
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        sub = Subsidiary(
            name='Test', sending_domain='example.com',
            display_name='Test', from_address='test@example.com'
        )
        db.session.add(sub)
        db.session.commit()
        sp = SendingProfile(name='Test SMTP', smtp_host='smtp.example.com',
                            smtp_port=587, smtp_user='user', subsidiary_id=sub.id)
        sp.set_smtp_pass('secret')
        db.session.add(sp)
        db.session.commit()
        campaign = Campaign(name='Test', subject='s', body_html='b',
                            landing_html='l', sending_profile_id=sp.id)
        db.session.add(campaign)
        db.session.commit()
        Recipient(campaign_id=campaign.id, email='victim@example.com')
        db.session.commit()
        yield {'campaign': campaign, 'sp': sp, 'sub': sub}
        db.session.remove()
        db.drop_all()


def test_create_mailer_standard(ctx):
    sp = ctx['sp']
    sub = ctx['sub']
    kwargs = {
        'smtp_host': sp.smtp_host,
        'smtp_port': sp.smtp_port,
        'smtp_user': sp.smtp_user,
        'smtp_pass': sp.get_smtp_pass(),
        'use_tls': sp.use_tls,
        'dkim_selector': sub.dkim_selector,
        'dkim_domain': sub.sending_domain,
        'dkim_private_key': sub.get_dkim_private_key(),
    }
    mailer = create_mailer(kwargs, pool_size=2, use_enterprise=False)
    assert isinstance(mailer, Mailer)
    mailer.close()


def test_create_mailer_enterprise(ctx):
    sp = ctx['sp']
    sub = ctx['sub']
    kwargs = {
        'smtp_host': sp.smtp_host,
        'smtp_port': sp.smtp_port,
        'smtp_user': sp.smtp_user,
        'smtp_pass': sp.get_smtp_pass(),
        'use_tls': sp.use_tls,
        'dkim_selector': sub.dkim_selector,
        'dkim_domain': sub.sending_domain,
        'dkim_private_key': sub.get_dkim_private_key(),
    }
    mailer = create_mailer(kwargs, pool_size=2, use_enterprise=True)
    assert isinstance(mailer, EnterpriseMailer)
    mailer.close()
