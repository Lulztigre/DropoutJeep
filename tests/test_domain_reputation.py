"""Unit tests for domain reputation scoring."""

import pytest

from dropoutjeep_lib.utils.domain_reputation import (
    compute_overall_score,
    _warmup_level_from_score_and_age,
    _warmup_volume_limit,
)


def test_compute_overall_score_perfect_domain():
    vt = {'score': 100, 'categories': {}}
    score = compute_overall_score(vt, [], True, True, True, 90)
    assert score == 100


def test_compute_overall_score_blacklisted():
    vt = {'score': 100, 'categories': {}}
    score = compute_overall_score(vt, ['zen.spamhaus.org'], True, True, True, 90)
    # Base 50 + VT net 20 + auth 30 + age 10 - blacklist 20 = 90
    assert score == 90


def test_compute_overall_score_no_auth():
    vt = {'score': 50, 'categories': {}}
    score = compute_overall_score(vt, [], False, False, False, 5)
    assert score < 50


def test_compute_overall_score_very_young_domain():
    vt = {'score': 100, 'categories': {}}
    score = compute_overall_score(vt, [], True, True, True, 1)
    assert score == 90


def test_warmup_level_mapping():
    assert _warmup_level_from_score_and_age(95, 120) == 10
    assert _warmup_level_from_score_and_age(85, 70) == 8
    assert _warmup_level_from_score_and_age(75, 40) == 6
    assert _warmup_level_from_score_and_age(65, 10) == 4
    assert _warmup_level_from_score_and_age(45, 1) == 2
    assert _warmup_level_from_score_and_age(20, 1) == 0


def test_warmup_volume_limits():
    assert _warmup_volume_limit(0) == 0
    assert _warmup_volume_limit(5) == 500
    assert _warmup_volume_limit(10) == 50000
    assert _warmup_volume_limit(99) == 0
