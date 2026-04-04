"""
Content / social-engineering analysis layer.

Analyzes the plain-text (and HTML-stripped) body for patterns that indicate
social engineering tactics.
"""

import re

_URGENCY_PATTERNS = [
    r'\burgent\b', r'\bimmediately\b', r'\baction required\b',
    r'\baccount.*suspend', r'\bsuspend.*account', r'\bunusual activity\b',
    r'\bverify.*account', r'\bconfirm.*identity', r'\bclick here\b',
    r'\baccount.*locked', r'\bpassword.*expir', r'\blimited time\b',
    r'\bact now\b', r'\bwarn.*you\b', r'\bsecurity.*alert\b',
    r'\byour account has been', r'\bunauthorized.*access',
]

_CRED_PATTERNS = [
    r'\benter.*password\b', r'\bprovide.*credential', r'\bsign.*in below\b',
    r'\bverify.*email', r'\bupdate.*payment', r'\bconfirm.*billing',
    r'\bsubmit.*information\b', r'\bfill.*form\b',
    r'\bsocial security\b', r'\bcredit card\b', r'\bbank account\b',
    r'\bpin\b.*\benter\b', r'\benter.*pin\b',
]

_BEC_PATTERNS = [
    r'\brequest.*quote\b', r'\brfq\b', r'\bquote.*request\b',
    r'\bwire.*transfer\b', r'\btransfer.*fund', r'\bgift card\b',
    r'\binvoice.*attach', r'\battach.*invoice', r'\bpurchase order\b',
    r'\bpo.*attach', r'\bpayment.*instruction', r'\bnew.*vendor\b',
    r'\bchange.*bank.*detail', r'\bupdate.*account.*detail',
    r'\basset.*purchase', r'\bconfidential.*transaction',
]

# Brand impersonation claims: (regex_pattern, canonical_brand_name)
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
]

_ATTACHMENT_PATTERNS = [
    r'\bsee attach', r'\bopen.*attach', r'\battach.*file',
    r'\bdownload.*attach', r'\bview.*document', r'\breview.*attach',
    r'\bplease find attach', r'\bkindly.*open\b',
]


def analyze_content(body_parts, headers):
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

    impersonation_brand = _find_impersonation(
        all_text, headers.get('from_domain', ''), headers.get('subject', '')
    )

    return {
        'urgency_hits':       urgency_hits,
        'cred_hits':          cred_hits,
        'bec_hits':           bec_hits,
        'attachment_hits':    attachment_hits,
        'impersonation_brand': impersonation_brand,
        'has_urgency':       bool(urgency_hits),
        'has_cred_harvest':  bool(cred_hits),
        'has_bec':           bool(bec_hits),
        'has_attachment_lure': bool(attachment_hits),
        'has_impersonation': bool(impersonation_brand),
    }


def _match(text, patterns):
    hits = []
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(pat.replace(r'\b', '').replace('.*', ' '))
    return hits


def _find_impersonation(text, from_domain, subject=''):
    from utils.helpers import get_sld
    sld = get_sld(from_domain) if from_domain else ''
    combined = text + ' ' + subject.lower()
    for pattern, brand_name in _IMPERSONATION_CLAIMS:
        if re.search(pattern, combined, re.IGNORECASE):
            if sld != brand_name:
                return brand_name
    return ''
