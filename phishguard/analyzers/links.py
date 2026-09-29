"""Extract and analyze email links."""

import re
from urllib.parse import urlparse
from ..utils import extract

URL_REGEX = re.compile(r"https?://[^\s\"'<>\)\]]+", re.I)
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'}
SUSPICIOUS_TLDS = {'xyz', 'top', 'club', 'click', 'loan', 'win', 'tk', 'icu'}
BRANDS = ('paypal', 'microsoft', 'apple', 'google', 'amazon', 'netflix', 'bank')

def extract_urls(parsed_email):
    text = f"{parsed_email.get('body_text', '')} {parsed_email.get('body_html', '')}"
    found = URL_REGEX.findall(text)
    found.extend(re.findall(r'''(?:href|src)=["'](https?://[^"']+)''', text, re.I))
    result = []
    for url in found:
        url = url.rstrip(".,);]'\"")
        if url not in result:
            result.append(url)
    return result

def analyze_links(urls):
    findings = []
    for url in urls:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        parts = extract(hostname)
        if re.match(r'^https?://(\d{1,3}\.){3}\d{1,3}', url):
            findings.append({'signal': 'ip_based_url', 'weight': 45, 'detail': f'Link uses a raw IP address: {url}'})
        if hostname in SHORTENERS:
            findings.append({'signal': 'url_shortener', 'weight': 25, 'detail': f'Link uses a URL shortener ({hostname}): {url}'})
        if parts.suffix.lstrip('.') in SUSPICIOUS_TLDS:
            findings.append({'signal': 'suspicious_tld', 'weight': 20, 'detail': f'Link uses a commonly abused TLD ({parts.suffix}): {url}'})
        if len(parts.subdomain.split('.')) >= 3:
            findings.append({'signal': 'excessive_subdomains', 'weight': 20, 'detail': f'Link has excessive subdomain nesting: {hostname}'})
        if '@' in url.split('//', 1)[-1]:
            findings.append({'signal': 'userinfo_obfuscation', 'weight': 35, 'detail': f"Link uses '@' to disguise its destination: {url}"})
        for brand in BRANDS:
            if brand in hostname and hostname != f'{brand}.com' and not hostname.endswith(f'.{brand}.com'):
                findings.append({'signal': 'brand_lookalike_hostname', 'weight': 40, 'detail': f"Hostname contains '{brand}' but is not the official domain: {hostname}"})
                break
    return findings

def check_url_reputation(url):
    return None

def follow_redirects(url):
    return None
