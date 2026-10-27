"""Unit tests for risk-based conditional rule application."""

from dropoutjeep_lib.proxy.engine import Rule
from dropoutjeep_lib.proxy.types import Request, Response


def test_rule_applies_when_risk_above_threshold():
    rule = Rule({
        "url": "/login",
        "match": "prefix",
        "if_risk_gt": 50,
        "replace": {"response": {"status": 403}},
    })
    resp = Response(200, {"content-type": "text/html"}, "<html></html>")
    ctx = {"method": "GET", "risk_score": 75}
    result = rule.apply_response(resp, ctx)
    assert result.status_code == 403


def test_rule_skipped_when_risk_below_threshold():
    rule = Rule({
        "url": "/login",
        "match": "prefix",
        "if_risk_gt": 50,
        "replace": {"response": {"status": 403}},
    })
    resp = Response(200, {"content-type": "text/html"}, "<html></html>")
    ctx = {"method": "GET", "risk_score": 30}
    result = rule.apply_response(resp, ctx)
    assert result.status_code == 200


def test_rule_applies_when_click_count_above_threshold():
    rule = Rule({
        "url": "/",
        "match": "word",
        "if_click_count_gt": 2,
        "replace": {"response": {"body": {"append": "<div>disclosure</div>"}}},
    })
    resp = Response(200, {"content-type": "text/html"}, "<html><body></body></html>")
    ctx = {"method": "GET", "click_count": 5}
    result = rule.apply_response(resp, ctx)
    assert "disclosure" in result.body


def test_rule_skipped_when_click_count_below_threshold():
    rule = Rule({
        "url": "/",
        "match": "word",
        "if_click_count_gt": 2,
        "replace": {"response": {"body": {"append": "<div>disclosure</div>"}}},
    })
    resp = Response(200, {"content-type": "text/html"}, "<html><body></body></html>")
    ctx = {"method": "GET", "click_count": 1}
    result = rule.apply_response(resp, ctx)
    assert "disclosure" not in result.body


def test_rule_without_conditions_always_applies():
    rule = Rule({
        "url": "/",
        "match": "word",
        "replace": {"response": {"status": 418}},
    })
    resp = Response(200, {"content-type": "text/html"}, "<html></html>")
    ctx = {"method": "GET"}
    result = rule.apply_response(resp, ctx)
    assert result.status_code == 418


def test_status_override_ignored_for_invalid_value():
    rule = Rule({
        "url": "/",
        "match": "word",
        "replace": {"response": {"status": "not-a-number"}},
    })
    resp = Response(200, {"content-type": "text/html"}, "<html></html>")
    ctx = {"method": "GET"}
    result = rule.apply_response(resp, ctx)
    assert result.status_code == 200


def test_conditions_apply_to_request_rules_too():
    rule = Rule({
        "url": "/api",
        "match": "prefix",
        "if_risk_gt": 60,
        "replace": {"request": {"header": {"X-Risk": "high"}}},
    })
    req = Request("GET", "/api/x", {"X-Orig": "1"}, {}, b"")
    ctx_low = {"risk_score": 30}
    result_low = rule.apply_request(req, ctx_low)
    assert "X-Risk" not in result_low.headers

    ctx_high = {"risk_score": 80}
    result_high = rule.apply_request(req, ctx_high)
    assert result_high.headers["X-Risk"] == "high"
