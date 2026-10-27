"""Tests for rate limiting on auth and admin endpoints."""

import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app, _default_rate_limits
from dropoutjeep_lib import db


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def test_default_rate_limits_bypass_in_testing(client):
    # Rate limits are disabled while TESTING is true so the suite can log in repeatedly.
    with app.test_request_context('/admin/login', method='POST'):
        assert _default_rate_limits() == ''


def test_default_rate_limits_for_login():
    with app.test_request_context('/admin/login', method='POST'):
        app.config['TESTING'] = False
        assert _default_rate_limits() == '5 per minute'


def test_default_rate_limits_for_api_write():
    with app.test_request_context('/api/v1/campaigns/', method='POST'):
        app.config['TESTING'] = False
        assert _default_rate_limits() == '30 per minute'


def test_default_rate_limits_for_admin_write():
    with app.test_request_context('/admin/campaign/new', method='POST'):
        app.config['TESTING'] = False
        assert _default_rate_limits() == '60 per minute'


def test_default_rate_limits_get_exempt():
    with app.test_request_context('/admin/login', method='GET'):
        app.config['TESTING'] = False
        assert _default_rate_limits() == ''
