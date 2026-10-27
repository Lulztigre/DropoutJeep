"""Unit tests for sender rotation logic."""

from types import SimpleNamespace

from dropoutjeep_lib.utils.sender_rotation import build_identity_for_entry


def _make_mock_sub(name='Test Sub', domain='example.com', from_addr='no-reply@example.com',
                   display='Example', bounce='mail', dkim_selector='dkim', dkim_key='key'):
    return SimpleNamespace(
        name=name,
        sending_domain=domain,
        from_address=from_addr,
        display_name=display,
        bounce_subdomain=bounce,
        dkim_selector=dkim_selector,
        get_dkim_private_key=lambda: dkim_key,
    )


def _make_mock_profile(name='Profile', host='smtp.example.com', port=587,
                       user='user', pwd='pass', use_tls=True, sub=None):
    return SimpleNamespace(
        name=name,
        smtp_host=host,
        smtp_port=port,
        smtp_user=user,
        get_smtp_pass=lambda: pwd,
        use_tls=use_tls,
        subsidiary=sub,
    )


def test_build_identity_for_entry_uses_defaults():
    sub = _make_mock_sub()
    sp = _make_mock_profile(sub=sub)
    entry = SimpleNamespace(
        sending_profile=sp,
        subsidiary=None,
        display_name_override=None,
        from_address_override=None,
    )
    envelope, from_header, reply_to, kwargs = build_identity_for_entry(entry)
    assert envelope == 'bounce@mail.example.com'
    assert from_header == 'Example <no-reply@example.com>'
    assert reply_to == 'security@example.com'
    assert kwargs['smtp_host'] == 'smtp.example.com'
    assert kwargs['dkim_selector'] == 'dkim'


def test_build_identity_for_entry_uses_overrides():
    sub = _make_mock_sub()
    sp = _make_mock_profile(sub=sub)
    entry = SimpleNamespace(
        sending_profile=sp,
        subsidiary=None,
        display_name_override='Override Name',
        from_address_override='override@example.com',
    )
    envelope, from_header, reply_to, kwargs = build_identity_for_entry(entry)
    assert from_header == 'Override Name <override@example.com>'
    assert envelope == 'bounce@mail.example.com'
