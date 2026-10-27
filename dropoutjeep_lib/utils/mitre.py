"""MITRE ATT&CK technique mapping for campaign events.

Maps internal event types to ATT&CK techniques so reporting can reference the
framework used in the authorization letter and engagement deliverables.
"""

from typing import List

TECHNIQUES = {
    'T1566.001': {
        'name': 'Phishing: Spearphishing Attachment',
        'tactic': 'Initial Access',
    },
    'T1566.002': {
        'name': 'Phishing: Spearphishing Link',
        'tactic': 'Initial Access',
    },
    'T1003': {
        'name': 'OS Credential Dumping',
        'tactic': 'Credential Access',
    },
    'T1556.006': {
        'name': 'Multi-Factor Authentication Interception',
        'tactic': 'Credential Access',
    },
    'T1539': {
        'name': 'Steal Web Session Cookie',
        'tactic': 'Credential Access',
    },
    'T1027.006': {
        'name': 'HTML Smuggling',
        'tactic': 'Defense Evasion',
    },
    'T1204.001': {
        'name': 'User Execution: Malicious Link',
        'tactic': 'Execution',
    },
    'T1204.002': {
        'name': 'User Execution: Malicious File',
        'tactic': 'Execution',
    },
    'T1598': {
        'name': 'Phishing for Information',
        'tactic': 'Reconnaissance',
    },
}


EVENT_TYPE_MAP: dict[str, List[str]] = {
    'sent': ['T1566.001', 'T1566.002'],
    'open': ['T1566.001', 'T1566.002'],
    'click': ['T1566.002', 'T1204.001'],
    'visit': ['T1566.002', 'T1204.001'],
    'credential_attempt': ['T1566.002', 'T1003'],
    'mfa_prompt': ['T1556.006'],
    'mfa_attempt': ['T1556.006'],
    'proxy_credential_capture': ['T1003'],
    'proxy_mfa_capture': ['T1556.006'],
    'proxy_session_cookie_capture': ['T1539'],
    'html_smuggle_download': ['T1027.006', 'T1204.002'],
    'canary_triggered': ['T1598'],
    'fingerprint': ['T1598'],
    'flow_complete': ['T1566.002'],
    'training_started': ['T1566.002'],
    'training_completed': ['T1566.002'],
}


def map_event_type(event_type: str | None) -> List[str]:
    """Return MITRE technique IDs for a given internal event type."""
    return list(EVENT_TYPE_MAP.get(event_type or '', []))


def technique_details(technique_id: str) -> dict:
    """Return name and tactic for a technique ID."""
    info = TECHNIQUES.get(technique_id, {})
    return {
        'id': technique_id,
        'name': info.get('name', 'Unknown'),
        'tactic': info.get('tactic', 'Unknown'),
    }


def summarize_campaign(events) -> dict:
    """Return a MITRE technique summary for an iterable of Event objects."""
    counts = {}
    for event in events:
        for tid in event.mitre_techniques_list():
            counts[tid] = counts.get(tid, 0) + 1
    return {
        'techniques': [
            {**technique_details(tid), 'count': count}
            for tid, count in sorted(counts.items(), key=lambda x: -x[1])
        ],
        'total_mapped_events': sum(counts.values()),
    }


def coverage_report(events) -> dict:
    """Return observed vs possible MITRE technique coverage.

    ``all_possible`` is derived from every technique referenced in
    ``EVENT_TYPE_MAP`` so operators can see gaps in their simulation.
    """
    observed = set()
    for event in events:
        observed.update(event.mitre_techniques_list())

    all_possible = set()
    for tids in EVENT_TYPE_MAP.values():
        all_possible.update(tids)

    missing = sorted(all_possible - observed)
    return {
        'observed_count': len(observed),
        'possible_count': len(all_possible),
        'coverage_percent': round(100 * len(observed) / len(all_possible), 1) if all_possible else 0,
        'observed': sorted(observed),
        'missing': [{**technique_details(tid)} for tid in missing],
    }
