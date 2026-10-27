import requests
import sys

BASE_URL = "http://127.0.0.1:5005"

session = requests.Session()

# 1. Login
print("Logging in to admin console at http://127.0.0.1:5005...")
login_resp = session.post(f"{BASE_URL}/admin/login", data={
    'username': 'admin',
    'password': 'password123'
}, allow_redirects=True)

print(f"Login status: {login_resp.status_code}")

routes_to_test = [
    ("/admin/osint", "[ OSINT_RECON_DASHBOARD ]"),
    ("/admin/pretext-gen", "[ PRETEXT_GENERATOR ]"),
    ("/admin/branding-clone", "[ BRANDING_CLONE_ENGINE ]"),
    ("/admin/payloads", "[ PAYLOAD_GENERATOR_SUITE ]"),
    ("/admin/exfil", "[ EXFILTRATION_CHANNELS ]"),
    ("/admin/c2", "[ C2_ADVANCED_CONFIGURATION ]"),
    ("/admin/evasion", "[ EVASION_&_DEFENSE_BYPASS_SETTINGS ]"),
    ("/admin/persistence", "[ PERSISTENCE_MODULES ]"),
    ("/admin/warmup", "[ DOMAIN_WARMUP_MANAGER ]"),
    ("/admin/fbl", "[ FEEDBACK_LOOP_(FBL)_REGISTRATION ]"),
    ("/admin/proxy-payload", "[ PROXY_PAYLOAD_DELIVERY_ENGINE ]"),
    ("/admin/proxy-chain", "[ MULTI-HOP_PROXY_CHAIN_BUILDER ]"),
    ("/admin/templates", "TEMPLATE MARKETPLACE"),
    ("/events", "[ EVENTS_MONITOR ]"),
    ("/spoof-check", "Spoofing & Sender Authentication Alignment Check"),
]

passed = 0
failed = 0

print("\n--- VERIFYING UI ROUTES ---")
for path, expected_header in routes_to_test:
    r = session.get(f"{BASE_URL}{path}")
    if r.status_code == 200 and expected_header.lower() in r.text.lower():
        print(f"✓ PASS: {path:<25} (HTTP 200) - Header found")
        passed += 1
    else:
        print(f"✗ FAIL: {path:<25} (HTTP {r.status_code}) - Expected '{expected_header}'")
        failed += 1

print("\n--- VERIFYING API ENDPOINTS ---")
api_endpoints = [
    ("/admin/evasion/edr/processes", "GET", None, "processes"),
    ("/admin/evasion/profiles", "GET", None, "profiles"),
    ("/admin/c2/fronting/providers", "GET", None, "providers"),
    ("/admin/warmup/schedule", "GET", None, "schedule"),
    ("/admin/fbl/programs", "GET", None, "programs"),
    ("/admin/proxy-chain/health", "GET", None, "health"),
    ("/admin/osint/linkedin", "POST", {"name": "Test User", "company": "Test Corp"}, "profile"),
    ("/admin/pretext/gen", "POST", {"company": "Acme Corp"}, "pretext_suggestions"),
    ("/admin/persistence/generate", "POST", {"module": "com_hijack"}, "install_cmd"),
]

for path, method, payload, expected_key in api_endpoints:
    if method == "GET":
        r = session.get(f"{BASE_URL}{path}")
    else:
        r = session.post(f"{BASE_URL}{path}", json=payload)

    if r.status_code == 200 and expected_key in r.text:
        print(f"✓ PASS API: {path:<30} (HTTP 200) - Key '{expected_key}' returned")
        passed += 1
    else:
        print(f"✗ FAIL API: {path:<30} (HTTP {r.status_code})")
        failed += 1

print(f"\n==========================================")
print(f"TOTAL VERIFIED: {passed}/{len(routes_to_test) + len(api_endpoints)} PASSED.")
if failed > 0:
    sys.exit(1)
