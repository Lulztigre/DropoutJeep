import sys
from dropoutjeep import app, db
from dropoutjeep_lib.models import User

def main():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    client = app.test_client()

    with app.app_context():
        db.create_all()
        user = User.query.filter_by(username='admin_test_run').first()
        if not user:
            user = User(username='admin_test_run', role='admin', is_active=True)
            user.set_password('pass1234')
            db.session.add(user)
            db.session.commit()
        user_id = user.id

    # Login via session
    with client.session_transaction() as sess:
        sess['user_id'] = user_id

    routes_to_test = [
        ("/admin/osint", "[ OSINT_RECON_DASHBOARD ]"),
        ("/admin/pretext-gen", "[ PRETEXT_GENERATOR ]"),
        ("/admin/branding-clone", "[ BRANDING_CLONE_ENGINE ]"),
        ("/admin/payloads", "[ PAYLOAD_GENERATOR_SUITE ]"),
        ("/admin/exfil-channels", "[ EXFILTRATION_CHANNELS ]"),
        ("/admin/c2", "[ C2_ADVANCED_CONFIGURATION ]"),
        ("/admin/evasion", "[ EVASION_&_DEFENSE_BYPASS_SETTINGS ]"),
        ("/admin/persistence", "[ PERSISTENCE_MODULES ]"),
        ("/admin/warmup", "[ DOMAIN_WARMUP_MANAGER ]"),
        ("/admin/fbl", "[ FEEDBACK_LOOP_(FBL)_REGISTRATION ]"),
        ("/admin/proxy-payload", "[ PROXY_PAYLOAD_DELIVERY_ENGINE ]"),
        ("/admin/proxy-chain", "[ MULTI-HOP_PROXY_CHAIN_BUILDER ]"),
        ("/admin/templates", "TEMPLATE MARKETPLACE"),
        ("/events", "[ EVENTS_MONITOR ]"),
        ("/spoof-check", "[ SPOOF_CHECK ]"),
    ]

    passed = 0
    failed = 0

    print("==================================================")
    print(" VERIFYING NEW & UPDATED UI PAGES")
    print("==================================================")
    for path, expected_header in routes_to_test:
        r = client.get(path)
        text = r.data.decode('utf-8', errors='ignore')
        if r.status_code == 200 and expected_header.lower() in text.lower():
            print(f"PASS: {path:<25} (HTTP 200) - Header found")
            passed += 1
        else:
            print(f"FAIL: {path:<25} (HTTP {r.status_code}) - Expected '{expected_header}'")
            failed += 1

    print("\n==================================================")
    print(" VERIFYING NEW API ENDPOINTS")
    print("==================================================")
    api_endpoints = [
        ("/admin/evasion/edr/processes", "GET", None, "processes"),
        ("/admin/evasion/profiles", "GET", None, "profiles"),
        ("/admin/c2/fronting/providers", "GET", None, "providers"),
        ("/admin/warmup/schedule", "GET", None, "schedule"),
        ("/admin/fbl/programs", "GET", None, "programs"),
        ("/admin/proxy-chain/health", "GET", None, "health"),
        ("/admin/osint/linkedin", "POST", {"name": "Jane Doe", "company": "Acme Corp"}, "profile"),
        ("/admin/pretext/gen", "POST", {"company": "Acme Corp"}, "pretext_suggestions"),
        ("/admin/persistence/generate", "POST", {"module": "com_hijack"}, "command"),
        ("/admin/c2/fronting/test", "POST", {"provider": "azure", "backend_host": "c2.test.com"}, "blocked"),
        ("/admin/c2/saas/teams", "POST", {"data": "ping", "token": "test"}, "url"),
        ("/admin/c2/saas/slack", "POST", {"data": "ping", "bot_token": "test"}, "url"),
        ("/admin/c2/dead-drop/resolve", "POST", {"source": "gist:1234567890abcdef1234567890abcdef"}, "instructions"),
        ("/admin/fbl/register", "POST", {"program": "gmail", "domain": "example.com"}, "confirmation_email"),
        ("/admin/proxy-payload/rule", "POST", {"pattern": "/login", "payload_url": "http://test.com/hook.js"}, "rule"),
    ]

    for path, method, payload, expected_key in api_endpoints:
        if method == "GET":
            r = client.get(path)
        else:
            r = client.post(path, json=payload)

        text = r.data.decode('utf-8', errors='ignore')
        if r.status_code == 200 and expected_key in text:
            print(f"PASS API: {path:<30} (HTTP 200) - Key '{expected_key}' returned")
            passed += 1
        else:
            print(f"FAIL API: {path:<30} (HTTP {r.status_code}) - Response: {text[:100]}")
            failed += 1

    total = len(routes_to_test) + len(api_endpoints)
    print("==================================================")
    print(f"TOTAL VERIFIED RESULTS: {passed}/{total} PASSED")
    print("==================================================")

    if failed > 0:
        sys.exit(1)

if __name__ == '__main__':
    main()
