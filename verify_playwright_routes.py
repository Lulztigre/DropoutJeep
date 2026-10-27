import asyncio
import threading
import time
from playwright.async_api import async_playwright
from dropoutjeep import app, db
from dropoutjeep_lib.models import User

# Ensure admin user exists for test login
with app.app_context():
    db.create_all()
    user = User.query.filter_by(username='admin_pw_test').first()
    if not user:
        user = User(username='admin_pw_test', role='admin', is_active=True)
        user.set_password('pass1234')
        db.session.add(user)
        db.session.commit()

def run_server():
    app.run(host='127.0.0.1', port=5005, debug=False, use_reloader=False)

async def main():
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(2)

    routes = [
        ('/admin/osint', '[ OSINT_RECON_DASHBOARD ]'),
        ('/admin/pretext-gen', '[ PRETEXT_GENERATOR ]'),
        ('/admin/branding-clone', '[ BRANDING_CLONE_ENGINE ]'),
        ('/admin/payloads', '[ PAYLOAD_GENERATOR_SUITE ]'),
        ('/admin/exfil', '[ EXFILTRATION_CHANNELS ]'),
        ('/admin/c2', '[ C2_ADVANCED_CONFIGURATION ]'),
        ('/admin/evasion', '[ EVASION_&_DEFENSE_BYPASS_SETTINGS ]'),
        ('/admin/persistence', '[ PERSISTENCE_MODULES ]'),
        ('/admin/warmup', '[ DOMAIN_WARMUP_MANAGER ]'),
        ('/admin/fbl', '[ FEEDBACK_LOOP_(FBL)_REGISTRATION ]'),
        ('/admin/proxy-payload', '[ PROXY_PAYLOAD_DELIVERY_ENGINE ]'),
        ('/admin/proxy-chain', '[ MULTI-HOP_PROXY_CHAIN_BUILDER ]'),
        ('/admin/templates', 'TEMPLATE MARKETPLACE'),
        ('/events', '[ EVENTS_MONITOR ]'),
        ('/spoof-check', 'Spoofing & Sender Authentication Alignment Check'),
    ]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        # Login
        print("Logging in to admin console...")
        await page.goto("http://127.0.0.1:5005/admin/login")
        await page.fill("input[name='username']", "admin_pw_test")
        await page.fill("input[name='password']", "pass1234")
        await page.click("button[type='submit']")
        await page.wait_for_load_state("networkidle")

        print("Verifying all 15 new and updated UI routes with Playwright...\n")
        passed = 0
        failed = 0

        for path, expected_text in routes:
            url = f"http://127.0.0.1:5005{path}"
            resp = await page.goto(url)
            content = await page.content()
            status = resp.status
            
            if status == 200 and expected_text.lower() in content.lower():
                print(f"✓ PASS: {path} (HTTP {status}) - Verified header text")
                passed += 1
            else:
                print(f"✗ FAIL: {path} (HTTP {status}) - Could not find '{expected_text}'")
                failed += 1

        await browser.close()
        print(f"\nPlaywright UI Verification Complete: {passed}/{len(routes)} routes PASSED.")
        if failed == 0:
            print("ALL UI ROUTES VERIFIED SUCCESSFULLY WITH PLAYWRIGHT!")

if __name__ == '__main__':
    asyncio.run(main())
