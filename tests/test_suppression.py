"""Tests for the persistent suppression list."""

import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import SuppressedEmail
from dropoutjeep_lib.utils.suppression import (
    is_suppressed, suppress, remove_suppression,
    import_suppressions, export_suppressions, list_suppressions,
)


@pytest.fixture
def ctx():
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()


def test_is_suppressed_by_email(ctx):
    suppress('victim@cyberdome.net')
    assert is_suppressed('victim@cyberdome.net')
    assert not is_suppressed('other@example.com')


def test_is_suppressed_by_domain(ctx):
    suppress('cyberdome.net')
    assert is_suppressed('any@cyberdome.net')
    assert not is_suppressed('any@example.com')


def test_suppress_is_idempotent(ctx):
    suppress('victim@cyberdome.net')
    suppress('victim@cyberdome.net')
    assert SuppressedEmail.query.count() == 1


def test_remove_suppression(ctx):
    suppress('victim@cyberdome.net')
    assert is_suppressed('victim@cyberdome.net')
    assert remove_suppression('victim@cyberdome.net')
    assert not is_suppressed('victim@cyberdome.net')
    assert not remove_suppression('victim@cyberdome.net')


def test_import_plain_text(ctx):
    lines = ['# comment', 'victim@cyberdome.net', 'example.com', 'not_an_email']
    result = import_suppressions(lines)
    assert result['added'] == 2
    assert result['duplicates'] == 0
    assert len(result['errors']) == 1
    assert is_suppressed('victim@cyberdome.net')
    assert is_suppressed('any@example.com')


def test_import_csv(ctx):
    lines = ['email', 'victim@cyberdome.net', 'example.com']
    result = import_suppressions(lines)
    assert result['added'] == 2
    assert is_suppressed('victim@cyberdome.net')


def test_import_skips_duplicates(ctx):
    suppress('victim@cyberdome.net')
    result = import_suppressions(['victim@cyberdome.net', 'new@example.com'])
    assert result['added'] == 1
    assert result['duplicates'] == 1


def test_export_suppressions(ctx):
    suppress('a@example.com', source='manual')
    suppress('b@example.com', source='import')
    csv_data = export_suppressions()
    assert 'a@example.com' in csv_data
    assert 'b@example.com' in csv_data
    assert 'manual' in csv_data


def test_list_suppressions_pagination(ctx):
    suppress('a@example.com')
    suppress('b@example.com')
    rows = list_suppressions(limit=1)
    assert len(rows) == 1
