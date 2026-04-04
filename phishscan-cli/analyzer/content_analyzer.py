"""
Content / social-engineering analysis layer.

Analyzes the plain-text (and HTML-stripped) body for patterns that indicate
social engineering tactics:

  1. Urgency / fear triggers — pressure language forcing rash action
  2. Credential harvesting cues — login prompts, password requests
  3. Business Email Compromise (BEC) patterns — RFQ lures, wire transfers,
     gift-card requests, CEO fraud
  4. Brand impersonation in body text — sender claims a brand identity that
     doesn't match the From domain
  5. Attachment lure language — "see attached", "open the file below"

SOC context: content signals alone are weak, but combined with header and
URL anomalies they substantially raise confidence.
"""

import re

# ── Pattern tables ────────────────────────────────────────────────────────────

# Urgency / fear language that creates pressure to act without thinking
_URGENCY_PATTERNS = [
    r'\burgent\b', r'\bimmediately\b', r'\baction required\b',
    r'\baccount.*suspend', r'\bsuspend.*account', r'\bunusual activity\b',
    r'\bverify.*account', r'\bconfirm.*identity', r'\bclick here\b',
    r'\baccount.*locked', r'\bpassword.*expir', r'\blimited time\b',
    r'\bact now\b', r'\bwarn.*you\b', r'\bsecurity.*alert\b',
    r'\byour account has been', r'\bunauthorized.*access',
]

# Credential harvesting — requests for login details or personal information
_CRED_PATTERNS = [
    r'\benter.*password\b', r'\bprovide.*credential', r'\bsign.*in below\b',
    r'\bverify.*email', r'\bupdate.*payment', r'\bconfirm.*billing',
    r'\bsubmit.*information\b', r'\bfill.*form\b',
    r'\bsocial security\b', r'\bcredit card\b', r'\bbank account\b',
    r'\bpin\b.*\benter\b', r'\benter.*pin\b',
]

# BEC (Business Email Compromise) — invoice fraud, RFQ lures, wire transfers
_BEC_PATTERNS = [
    r'\brequest.*quote\b', r'\brfq\b', r'\bquote.*request\b',
    r'\bwire.*transfer\b', r'\btransfer.*fund', r'\bgift card\b',
    r'\binvoice.*attach', r'\battach.*invoice', r'\bpurchase order\b',
    r'\bpo.*attach', r'\bpayment.*instruction', r'\bnew.*vendor\b',
    r'\bchange.*bank.*detail', r'\bupdate.*account.*detail',
    r'\basset.*purchase', r'\bconfidential.*transaction',
]

# Brand impersonation claims — (regex_pattern, canonical_brand_name)
# Fires when body text claims the email is from that brand but the From
# domain's SLD does not exactly equal the canonical brand name.
_IMPERSONATION_CLAIMS = [
    (r'\bzendesk\b',    'zendesk'),
    (r'\bpaypal\b',     'paypal'),
    (r'\bmicrosoft\b',  'microsoft'),
    (r'\bgoogle\b',     'google'),
    (r'\bapple\b',      'apple'),
    (r'\bamazon\b',     'amazon'),
    (r'\bnetflix\b',    'netflix'),
    (r'\bfacebook\b',   'facebook'),
    (r'\blinkedin\b',   'linkedin'),
    (r'\bchase bank\b', 'chase'),
    (r'\bwells fargo\b','wellsfargo'),
    (r'\bdocusign\b',   'docusign'),
    (r'\bdropbox\b',    'dropbox'),
    (r'\bslack\b',      'slack'),
    (r'\bzoom\b',       'zoom'),
    (r'\bgithub\b',     'github'),
    (r'\bgitlab\b',     'gitlab'),
    (r'\bsalesforce\b', 'salesforce'),
    (r'\bservicenow\b', 'servicenow'),
    (r'\bstripe\b',     'stripe'),
    # European fintech / investment brands
    (r'\braisin\b',        'raisin'),
    (r'\bn26\b',           'n26'),
    (r'\btraderepublic\b', 'traderepublic'),
    (r'\betoro\b',         'etoro'),
    (r'\bdegiro\b',        'degiro'),
    (r'\bklarna\b',        'klarna'),
    (r'\bcomdirect\b',     'comdirect'),
    (r'\bconsorsbank\b',   'consorsbank'),
]

# Attachment lure language
_ATTACHMENT_PATTERNS = [
    r'\bsee attach', r'\bopen.*attach', r'\battach.*file',
    r'\bdownload.*attach', r'\bview.*document', r'\breview.*attach',
    r'\bplease find attach', r'\bkindly.*open\b',
]


def analyze_content(body_parts, headers):
    """
    Scan email body text and subject for social-engineering indicators.

    Args:
        body_parts: list of dicts from utils.parser.get_body_parts()
        headers:    dict from analyzer.header_analyzer.analyze_headers()

    Returns a dict of content intelligence signals.
    """
    # Combine subject + plain + HTML-stripped text for pattern matching
    plain_parts = [p['content'] for p in body_parts if p['type'] == 'text/plain']
    html_parts  = [
        re.sub(r'<[^>]+>', ' ', p['content'])
        for p in body_parts if p['type'] == 'text/html'
    ]
    subject  = headers.get('subject', '')
    all_text = '\n'.join([subject] + plain_parts + html_parts).lower()

    urgency_hits    = _match(all_text, _URGENCY_PATTERNS)
    cred_hits       = _match(all_text, _CRED_PATTERNS)
    bec_hits        = _match(all_text, _BEC_PATTERNS)
    attachment_hits = _match(all_text, _ATTACHMENT_PATTERNS)

    # Impersonation: body claims to be from a known brand, but the From
    # domain doesn't match that brand's canonical SLD (mismatch = deception)
    impersonation_brand = _find_impersonation(
        all_text, headers.get('from_domain', ''), headers.get('subject', '')
    )

    return {
        'urgency_hits':       urgency_hits,
        'cred_hits':          cred_hits,
        'bec_hits':           bec_hits,
        'attachment_hits':    attachment_hits,
        'impersonation_brand': impersonation_brand,
        # Convenience booleans for scoring engine
        'has_urgency':       bool(urgency_hits),
        'has_cred_harvest':  bool(cred_hits),
        'has_bec':           bool(bec_hits),
        'has_attachment_lure': bool(attachment_hits),
        'has_impersonation': bool(impersonation_brand),
    }


# ── Private helpers ────────────────────────────────────────────────────────────

def _match(text, patterns):
    """Return list of matched pattern strings found in text."""
    hits = []
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(pat.replace(r'\b', '').replace('.*', ' '))
    return hits


def _find_impersonation(text, from_domain, subject=''):
    """
    Return the brand name if the body (or subject) claims to be from a known
    brand but the From domain's SLD doesn't exactly equal that brand name.
    E.g. body says 'Zendesk Ltd.' but From domain is zendesks.ca (not zendesk.com).
    """
    from utils.helpers import get_sld
    sld = get_sld(from_domain) if from_domain else ''
    combined = text + ' ' + subject.lower()
    for pattern, brand_name in _IMPERSONATION_CLAIMS:
        if re.search(pattern, combined, re.IGNORECASE):
            # Legitimate only when SLD exactly equals the brand canonical name
            if sld != brand_name:
                return brand_name
    return ''
