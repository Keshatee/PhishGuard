"""Analyze sender identity."""

import difflib
from ..utils import registered_domain

BRANDS = ['paypal.com', 'microsoft.com', 'apple.com', 'google.com', 'amazon.com', 'netflix.com', 'bankofamerica.com', 'chase.com', 'usps.com', 'fedex.com']

def _domain(address):
    return registered_domain(address.split('@', 1)[1]) if '@' in address else ''

def analyze_sender(parsed_email):
    findings = []
    from_address = parsed_email.get('from_address', '')
    from_domain = _domain(from_address)
    auth = parsed_email.get('auth_results', {})
    for method, weight in {'spf': 30, 'dkim': 25, 'dmarc': 25}.items():
        result = auth.get(method)
        if result == 'fail':
            findings.append({'signal': f'{method}_fail', 'weight': weight, 'detail': f'{method.upper()} check failed.'})
        elif method == 'spf' and result is None:
            findings.append({'signal': 'spf_missing', 'weight': 10, 'detail': 'No SPF result found.'})
    display_name = (parsed_email.get('from_display_name') or '').lower()
    for brand in BRANDS:
        short = brand.split('.')[0]
        if short in display_name and from_domain != brand:
            findings.append({'signal': 'display_name_mismatch', 'weight': 35, 'detail': f"Display name references '{short}' but sending domain is '{from_domain or 'unknown'}'."})
            break
    for brand in BRANDS:
        if from_domain != brand and difflib.SequenceMatcher(None, from_domain, brand).ratio() >= 0.82:
            findings.append({'signal': 'typosquat_domain', 'weight': 40, 'detail': f"Sending domain '{from_domain}' closely resembles '{brand}'."})
            break
    reply_to = parsed_email.get('reply_to_address')
    if reply_to and _domain(reply_to) != from_domain:
        findings.append({'signal': 'reply_to_mismatch', 'weight': 20, 'detail': 'Reply-To domain differs from the From domain.'})
    return findings
