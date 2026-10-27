"""Tests for redirector chain builder and health checks."""

import pytest

from dropoutjeep_lib.utils.redirectors import (
    _apply_redirector,
    build_redirect_chain,
    check_redirector_health,
    filter_healthy_redirector_templates,
    get_campaign_redirector_templates,
    obfuscate_with_open_redirect,
    wrap_campaign_link,
)


def test_apply_redirector_with_placeholder():
    result = _apply_redirector("https://r1.example.com/out?to={url}", "https://target.example.com")
    assert result == "https://r1.example.com/out?to=https%3A%2F%2Ftarget.example.com"


def test_apply_redirector_without_placeholder():
    result = _apply_redirector("https://r1.example.com/redirect", "https://target.example.com")
    assert result == "https://r1.example.com/redirect?dj_next=https%3A%2F%2Ftarget.example.com"


def test_apply_redirector_without_placeholder_preserves_existing_query():
    result = _apply_redirector("https://r1.example.com/redirect?x=1", "https://target.example.com")
    assert result == "https://r1.example.com/redirect?x=1&dj_next=https%3A%2F%2Ftarget.example.com"


def test_build_redirect_chain_orders_inside_out():
    chain = build_redirect_chain(
        "https://final.example.com/proxy/1/t/abc/",
        [
            "https://r1.example.com/out?to={url}",
            "https://r2.example.com/go?u={url}",
        ],
    )
    # r1 wraps r2 wraps final
    assert chain.startswith("https://r1.example.com/out?to=")
    assert "r2.example.com" in chain
    assert "final.example.com" in chain


def test_build_redirect_chain_ignores_empty_templates():
    chain = build_redirect_chain(
        "https://final.example.com/",
        ["", "https://r1.example.com/{url}", "  "],
    )
    assert chain == "https://r1.example.com/https%3A%2F%2Ffinal.example.com%2F"


def test_get_campaign_redirector_templates_reads_flow_config():
    class FakeCampaign:
        def get_flow_config(self):
            return {
                "redirector_chains_enabled": True,
                "redirectors": [
                    "https://r1.example.com/{url}",
                    "https://r2.example.com/{url}",
                ],
            }

    assert get_campaign_redirector_templates(FakeCampaign()) == [
        "https://r1.example.com/{url}",
        "https://r2.example.com/{url}",
    ]


def test_get_campaign_redirector_templates_disabled_when_flag_false():
    class FakeCampaign:
        def get_flow_config(self):
            return {
                "redirector_chains_enabled": False,
                "redirectors": ["https://r1.example.com/{url}"],
            }

    assert get_campaign_redirector_templates(FakeCampaign()) == []


def test_wrap_campaign_link_returns_final_when_no_redirectors():
    class FakeCampaign:
        def get_flow_config(self):
            return {}

    final = "https://final.example.com/proxy/1/t/abc/"
    assert wrap_campaign_link(final, FakeCampaign(), fallback_to_db=False) == final


def test_wrap_campaign_link_uses_campaign_templates():
    class FakeCampaign:
        def get_flow_config(self):
            return {
                "redirector_chains_enabled": True,
                "redirectors": ["https://r1.example.com/{url}"],
            }

    result = wrap_campaign_link("https://final.example.com/", FakeCampaign(), fallback_to_db=False)
    assert result == "https://r1.example.com/https%3A%2F%2Ffinal.example.com%2F"


def test_check_redirector_health_detects_healthy_redirect(monkeypatch):
    class FakeResponse:
        status_code = 302

    class FakeClient:
        def head(self, url, follow_redirects=False):
            assert "example.com" in url
            return FakeResponse()

        def close(self):
            pass

    healthy, error = check_redirector_health(
        "https://r1.example.com/out?to={url}", client=FakeClient()
    )
    assert healthy is True
    assert error is None


def test_check_redirector_health_detects_unhealthy_redirect(monkeypatch):
    class FakeResponse:
        status_code = 500

    class FakeClient:
        def head(self, url, follow_redirects=False):
            return FakeResponse()

        def close(self):
            pass

    healthy, error = check_redirector_health(
        "https://r1.example.com/out?to={url}", client=FakeClient()
    )
    assert healthy is False
    assert "status 500" in error


def test_check_redirector_health_detects_network_error(monkeypatch):
    import httpx

    class FakeClient:
        def head(self, url, follow_redirects=False):
            raise httpx.ConnectError("connection failed")

        def close(self):
            pass

    healthy, error = check_redirector_health(
        "https://r1.example.com/out?to={url}", client=FakeClient()
    )
    assert healthy is False
    assert "connection failed" in error


def test_filter_healthy_redirector_templates(monkeypatch):
    def fake_check(template, timeout=10.0, client=None):
        return template.startswith("https://healthy"), None if template.startswith("https://healthy") else "dead"

    monkeypatch.setattr(
        "dropoutjeep_lib.utils.redirectors.check_redirector_health", fake_check
    )
    templates = [
        "https://dead.example/{url}",
        "https://healthy.example/{url}",
        "https://healthy2.example/{url}",
    ]
    healthy = filter_healthy_redirector_templates(templates)
    assert healthy == [
        "https://healthy.example/{url}",
        "https://healthy2.example/{url}",
    ]


def test_obfuscate_with_open_redirect_uses_known_endpoint():
    url = "https://final.example.com/proxy/1/t/abc/"
    obfuscated = obfuscate_with_open_redirect(url)
    assert obfuscated != url
    assert "https%3A%2F%2Ffinal.example.com%2Fproxy%2F1%2Ft%2Fabc%2F" in obfuscated


def test_obfuscate_with_open_redirect_custom_endpoint():
    url = "https://final.example.com/"
    endpoint = "https://example.com/redirect?next={url}"
    obfuscated = obfuscate_with_open_redirect(url, endpoint=endpoint)
    assert obfuscated.startswith("https://example.com/redirect?next=")
    assert "final.example.com" in obfuscated


def test_wrap_campaign_link_applies_obfuscation():
    class FakeCampaign:
        def get_flow_config(self):
            return {
                "redirector_chains_enabled": True,
                "redirectors": ["https://r1.example.com/{url}"],
            }

    result = wrap_campaign_link(
        "https://final.example.com/",
        FakeCampaign(),
        fallback_to_db=False,
        obfuscate_final=True,
    )
    assert "r1.example.com" in result
    assert "final.example.com" in result
    # outermost hop should be a known open-redirect domain
    assert any(domain in result for domain in ("google.com", "facebook.com", "youtube.com", "linkedin.com", "reddit.com", "steamcommunity.com"))


def test_wrap_campaign_link_uses_pre_filtered_templates():
    class FakeCampaign:
        def get_flow_config(self):
            return {
                "redirector_chains_enabled": True,
                "redirectors": ["https://r1.example.com/{url}", "https://r2.example.com/{url}"],
            }

    result = wrap_campaign_link(
        "https://final.example.com/",
        FakeCampaign(),
        fallback_to_db=False,
        templates=["https://r2.example.com/{url}"],
    )
    assert "r2.example.com" in result
    assert "r1.example.com" not in result


def test_validate_campaign_includes_redirector_checks(monkeypatch):
    from unittest.mock import patch
    from dropoutjeep_lib.utils.validator import validate_campaign_before_launch

    class FakeSub:
        sending_domain = "example.com"
        dkim_selector = "default"
        bounce_subdomain = "example.com"
        display_name = "Test"
        from_address = "test@example.com"

    class FakeSP:
        smtp_host = "smtp.example.com"
        smtp_port = 587
        smtp_user = "user"

        def get_smtp_pass(self):
            return "pass"

        subsidiary = FakeSub()

        def resolve_rate_profile(self):
            return None

    class FakeCampaign:
        id = 1
        sending_profile = FakeSP()
        domain_reputation_check_enabled = False

        def get_flow_config(self):
            return {
                "redirector_chains_enabled": True,
                "redirectors": [
                    "https://dead.example/{url}",
                    "https://healthy.example/{url}",
                ],
            }

    def fake_health(template, timeout=10.0, client=None):
        if template.startswith("https://healthy"):
            return True, None
        return False, "dead"

    monkeypatch.setattr(
        "dropoutjeep_lib.utils.redirectors.check_redirector_health", fake_health
    )

    with patch("dropoutjeep_lib.models.Campaign") as MockCampaign, \
         patch("dropoutjeep_lib.utils.validator.check_spf", return_value=(True, "ok")), \
         patch("dropoutjeep_lib.utils.validator.check_dkim_selector", return_value=(True, "ok")), \
         patch("dropoutjeep_lib.utils.validator.validate_smtp_relay", return_value=(True, "ok")):
        MockCampaign.query.get.return_value = FakeCampaign()
        result = validate_campaign_before_launch(1)

    assert result["ok"] is True
    redirector_checks = result["checks"]["redirectors"]
    assert len(redirector_checks) == 2
    assert redirector_checks[0] == {
        "template": "https://dead.example/{url}",
        "healthy": False,
        "error": "dead",
    }
    assert redirector_checks[1] == {
        "template": "https://healthy.example/{url}",
        "healthy": True,
        "error": None,
    }
    assert any("Redirector unhealthy" in w for w in result["warnings"])
