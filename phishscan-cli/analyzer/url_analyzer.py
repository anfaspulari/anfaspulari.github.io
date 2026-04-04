"""
URL intelligence layer.

Extracts URLs from all email body parts and classifies each one:
  - IP-based URLs (no hostname)
  - Lookalike / brand-impersonation domains
  - Homoglyph attacks (digit/letter substitutions)
  - Suspicious TLDs (.xyz, .top, .tk, etc.)
  - URL shorteners (destination hidden)
  - General suspicious domain patterns
"""

import re
from utils.helpers import (
    defang, extract_domain, get_tld, get_sld,
    is_url_shortener, is_suspicious_domain, is_suspicious_tld,
    lookalike_brand, has_homoglyph_attack, is_ip_address,
)

_URL_RE     = re.compile(r'https?://[^\s\'"<>()\[\]]+', re.IGNORECASE)
_TRAILING   = '.,:;)>]"\''


def extract_urls(body_parts):
    seen = set()
    urls = []
    for part in body_parts:
        text = part.get('content', '')
        if part.get('type') == 'text/html':
            text = re.sub(r'<[^>]+>', ' ', text)
        for url in _URL_RE.findall(text):
            url = url.rstrip(_TRAILING)
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def analyze_urls(urls):
    raw        = []
    defanged   = []
    domains    = []
    ip_urls    = []
    shorteners = []
    lookalikes = []
    homoglyphs = []
    bad_tld    = []
    suspicious = []
    seen_domains = set()

    for url in urls:
        domain       = extract_domain(url)
        defanged_url = defang(url)
        raw.append(url)
        defanged.append(defanged_url)

        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            domains.append(domain)

        if is_ip_address(domain):
            ip_urls.append(defanged_url)
            continue

        if is_url_shortener(domain):
            shorteners.append(defanged_url)

        brand = lookalike_brand(domain)
        if brand:
            lookalikes.append({'url': defanged_url, 'brand': brand, 'domain': domain})

        is_homo, homo_brand = has_homoglyph_attack(domain)
        if is_homo:
            homoglyphs.append({'url': defanged_url, 'brand': homo_brand, 'domain': domain})

        if is_suspicious_tld(domain):
            bad_tld.append(defanged_url)

        if is_suspicious_domain(domain) and not brand and not is_homo:
            suspicious.append(defanged_url)

    return {
        'raw':        raw,
        'defanged':   defanged,
        'count':      len(raw),
        'domains':    domains,
        'ip_urls':    ip_urls,
        'shorteners': shorteners,
        'lookalikes': lookalikes,
        'homoglyphs': homoglyphs,
        'bad_tld':    bad_tld,
        'suspicious': suspicious,
    }
