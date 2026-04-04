"""
Shared utility functions for PhishScan.

Includes defanging, domain extraction, URL shortener lookup,
and advanced domain-intelligence helpers (lookalike detection,
suspicious TLDs, homoglyph patterns).
"""

import re
import unicodedata

# ── Known URL shortener domains ───────────────────────────────────────────────
URL_SHORTENERS = frozenset({
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly',
    'short.link', 'rb.gy', 'cutt.ly', 'is.gd', 'v.gd', 'tiny.cc',
    'bl.ink', 'snip.ly', 'shorturl.at', 'clck.ru', 'x.co', 'lnkd.in',
    'youtu.be', 'ift.tt', 'dlvr.it', 'wp.me', 'ow.ly',
    # Email tracking services — hide real destination, reveal open/click tracking
    'l.mailtrack.com', 'mailtrack.com', 'mailtrack.io',
    'click.mailchimp.com', 'list-manage.com', 'mandrillapp.com',
    'sendgrid.net', 'mailgun.org', 'mg.mail', 'em.mail',
    'track.customer.io', 'links.iterable.com', 'click.pstmrk.it',
})

# ── Brands commonly impersonated in phishing (expanded) ──────────────────────
# Includes software/SaaS brands often used in BEC and lookalike campaigns
BRAND_NAMES = frozenset({
    # Finance / payment
    'paypal', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
    'barclays', 'santander', 'natwest', 'lloyds', 'zelle', 'venmo',
    'cashapp', 'stripe', 'wise', 'revolut', 'coinbase', 'binance', 'kraken',
    # Big tech
    'google', 'microsoft', 'apple', 'amazon', 'meta', 'facebook',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'adobe', 'salesforce',
    'oracle', 'sap', 'ibm', 'cisco',
    # Cloud / SaaS
    'outlook', 'office365', 'sharepoint', 'onedrive', 'teams',
    'gmail', 'googledrive', 'googlecloud', 'aws', 'azure',
    'slack', 'zoom', 'webex', 'docusign', 'hellosign',
    'zendesk', 'freshdesk', 'servicenow', 'jira', 'confluence',
    'github', 'gitlab', 'bitbucket',
    # Delivery / retail
    'fedex', 'dhl', 'ups', 'usps', 'royalmail', 'netflix',
    'spotify', 'uber', 'airbnb',
    # European fintech / investment (commonly targeted in BEC / investment scams)
    'raisin', 'n26', 'transferwise', 'monzo', 'starling',
    'klarna', 'traderepublic', 'etoro', 'degiro', 'scalable',
    'comdirect', 'consorsbank', 'dkb', 'ing', 'bunq',
})

# ── Suspicious TLDs — high-abuse, low-cost registrations ─────────────────────
# Source: abuse statistics from threat-intel feeds; not exhaustive
SUSPICIOUS_TLDS = frozenset({
    'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq',   # free/abused TLDs
    'click', 'download', 'loan', 'review', 'party',
    'gdn', 'bid', 'win', 'racing', 'date', 'trade',
    'science', 'work', 'link', 'live', 'stream',
    'support', 'help', 'service', 'secure', 'online',
    'site', 'website', 'space', 'tech', 'store',
    'shop', 'club', 'fun', 'host', 'icu',
})

# ── Suspicious SLD keywords ──────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = frozenset({
    'secure', 'verify', 'update', 'login', 'signin', 'account',
    'banking', 'confirm', 'validation', 'password', 'credential',
    'recovery', 'suspended', 'unlock', 'alert', 'support', 'helpdesk',
    'portal', 'authenticate', 'access', 'service', 'notification',
    'billing', 'invoice', 'payment', 'refund',
})

_DOMAIN_RE = re.compile(r'(?:https?://)?([^/?\s#:@\[\]]+)')


# ── Core helpers ──────────────────────────────────────────────────────────────

def defang(text):
    """Defang a URL or domain so it is safe to paste into reports/tickets."""
    if not text:
        return text
    return text.replace('http', 'hxxp').replace('.', '[.]')


def extract_domain(url):
    """Extract the hostname/netloc from a URL or bare domain string."""
    if not url:
        return ''
    url = url.strip()
    match = _DOMAIN_RE.match(url)
    if match:
        host = match.group(1).lower()
        return host.split(':')[0]   # strip port
    return ''


def get_tld(domain):
    """Return the TLD (last label) of a domain, e.g. 'com' from 'paypal.com'."""
    if not domain:
        return ''
    return domain.rstrip('.').rsplit('.', 1)[-1].lower()


def get_sld(domain):
    """Return the SLD (second-to-last label), e.g. 'paypal' from 'paypal.com'."""
    parts = domain.rstrip('.').split('.')
    return parts[-2].lower() if len(parts) >= 2 else domain.lower()


def is_url_shortener(domain):
    return (domain or '').lower().strip() in URL_SHORTENERS


def is_suspicious_tld(domain):
    """Return True if the domain uses a high-abuse TLD."""
    return get_tld(domain) in SUSPICIOUS_TLDS


# ── Lookalike / impersonation detection ──────────────────────────────────────

def levenshtein(a, b):
    """
    Compute the Levenshtein edit distance between two strings.
    Used to detect brand lookalike domains (e.g. 'zendesks' vs 'zendesk').
    """
    if len(a) < len(b):
        return levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            ins  = prev[j + 1] + 1
            dele = curr[j]     + 1
            sub  = prev[j] + (0 if ca == cb else 1)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]


def lookalike_brand(domain):
    """
    If the domain SLD closely resembles a known brand name (edit distance ≤ 2
    AND the SLD is not the brand itself), return the matched brand name.
    Also catches prefix/suffix obfuscation where brand appears inside the SLD.

    Examples:
        zendesks.ca   → 'zendesk'  (edit distance 1)
        paypa1.com    → 'paypal'   (edit distance 1)
        micosoft.com  → 'microsoft'(edit distance 1)
        paypal-login.com → 'paypal' (substring)
        github.com    → None       (exact brand — legitimate)
    """
    if not domain:
        return None
    sld = get_sld(domain)

    # Exact brand match → legitimate domain, not a lookalike
    # Check this FIRST before any pairwise comparison to avoid cross-brand false positives
    # (e.g. 'github' vs 'gitlab' have edit distance 2 — github is a real brand)
    if sld in BRAND_NAMES:
        return None

    for brand in BRAND_NAMES:
        # Edit-distance lookalike (catches extra/missing/swapped chars)
        if abs(len(sld) - len(brand)) <= 2 and levenshtein(sld, brand) <= 2:
            return brand
        # Substring: brand inside SLD but SLD ≠ brand  (e.g. paypal-secure)
        if brand in sld and sld != brand:
            return brand

    return None


def is_suspicious_domain(domain):
    """
    Return True if the domain matches known phishing patterns:
    - Lookalike of a known brand
    - Contains brand in domain but SLD differs
    - SLD contains a suspicious keyword
    """
    if not domain:
        return False
    domain = domain.lower().strip('.')
    if lookalike_brand(domain):
        return True
    sld = get_sld(domain)
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in sld:
            return True
    return False


# ── Homoglyph detection ───────────────────────────────────────────────────────

# Common confusable substitutions used in homoglyph attacks
_HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', 'rn': 'm', 'vv': 'w',
    'cl': 'd', 'cj': 'g',
}

def has_homoglyph_attack(domain):
    """
    Return (True, brand_matched) if domain uses digit/letter substitutions
    to impersonate a brand (e.g. paypa1.com → paypal, mlcrosoft.com → microsoft).
    """
    if not domain:
        return False, None
    sld = get_sld(domain)
    # Normalize: replace common substitutions and recheck
    normalized = sld
    for glyph, real in _HOMOGLYPH_MAP.items():
        normalized = normalized.replace(glyph, real)
    if normalized != sld:
        for brand in BRAND_NAMES:
            if normalized == brand or levenshtein(normalized, brand) <= 1:
                return True, brand
    # Also check for unicode confusables (Cyrillic a, e, o look like Latin)
    try:
        ascii_sld = unicodedata.normalize('NFKD', sld).encode('ascii', 'ignore').decode()
        if ascii_sld != sld:
            for brand in BRAND_NAMES:
                if ascii_sld == brand or levenshtein(ascii_sld, brand) <= 1:
                    return True, brand
    except Exception:
        pass
    return False, None


# ── IP address helpers ─────────────────────────────────────────────────────────

_PRIVATE_IP_RE = re.compile(
    r'^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)'
)
_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def is_ip_address(host):
    """Return True if host is an IPv4 address (not a hostname)."""
    return bool(_IP_RE.match(host or ''))


def is_private_ip(ip):
    return bool(_PRIVATE_IP_RE.match(ip or ''))
