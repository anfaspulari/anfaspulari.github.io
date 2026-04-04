"""
Header intelligence layer.

Extracts and evaluates all trust-chain signals present in email headers:
  - SPF / DKIM / DMARC authentication results
  - Microsoft Exchange spam-classification headers (SCL, SFV, CAT)
  - Received chain: Gmail API relay, bare-IP relay, repeated sends
  - Return-Path / From mismatch
  - Reply-To mismatch
  - Free-mail provider used for business-impersonation
"""

import re
from email.utils import parseaddr
from utils.helpers import is_private_ip, lookalike_brand

_SPF_RE   = re.compile(r'\bspf=(\w+)',   re.IGNORECASE)
_DKIM_RE  = re.compile(r'\bdkim=(\w+)',  re.IGNORECASE)
_DMARC_RE = re.compile(r'\bdmarc=(\w+)', re.IGNORECASE)
_MS_FIELD_RE = re.compile(r'([A-Z]+):([^;]+)')
_GMAIL_API_RE = re.compile(r'gmailapi\.google\.com', re.IGNORECASE)
_BARE_IP_RE = re.compile(r'\(\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\)')

_FREE_MAIL = frozenset({
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'live.com', 'aol.com', 'protonmail.com', 'icloud.com',
    'mail.com', 'yandex.com', 'zoho.com',
})


def analyze_headers(msg):
    from_raw  = msg.get('From', '')
    rto_raw   = msg.get('Reply-To', '')
    rpath_raw = msg.get('Return-Path', '')

    _, from_addr  = parseaddr(from_raw)
    _, rto_addr   = parseaddr(rto_raw)
    _, rpath_addr = parseaddr(rpath_raw)

    from_addr  = from_addr.lower().strip()
    rto_addr   = rto_addr.lower().strip()
    rpath_addr = rpath_addr.lower().strip()

    from_domain  = _addr_domain(from_addr)
    rto_domain   = _addr_domain(rto_addr)
    rpath_domain = _addr_domain(rpath_addr)

    auth = (
        msg.get('Authentication-Results', '')
        or msg.get('ARC-Authentication-Results', '')
        or ''
    )
    spf  = _extract(auth, _SPF_RE)   or _spf_fallback(msg)
    dkim = _extract(auth, _DKIM_RE)  or 'none'
    dmarc_result = _extract(auth, _DMARC_RE) or 'none'

    dmarc_action = ''
    if 'action=' in auth.lower():
        m = re.search(r'action=(\w+)', auth, re.IGNORECASE)
        if m:
            dmarc_action = m.group(1).lower()

    dmarc_weak = dmarc_result.lower() in ('none', 'bestguesspass', '')

    ms_report = msg.get('X-Forefront-Antispam-Report', '')
    ms_fields = dict(_MS_FIELD_RE.findall(ms_report))
    scl = int(ms_fields.get('SCL', '0') or '0')
    sfv = ms_fields.get('SFV', '').strip()
    cat = ms_fields.get('CAT', '').strip()

    ms_spam_high = scl >= 5 or sfv in ('SPM', 'PHSH') or cat in ('SPM', 'PHSH', 'MALW')

    ms_antispam = msg.get('X-Microsoft-Antispam', '')
    bcl_m = re.search(r'BCL:(\d+)', ms_antispam, re.IGNORECASE)
    bcl = int(bcl_m.group(1)) if bcl_m else 0

    received = msg.get_all('Received') or []

    gmail_api_hops = [r for r in received if _GMAIL_API_RE.search(r)]
    gmail_api_relay = len(gmail_api_hops) > 0
    repeated_sends = len(gmail_api_hops) > 1

    bare_ip_relay = False
    bare_ip_value = ''
    for rcv in received:
        m = _BARE_IP_RE.search(rcv)
        if m:
            ip = m.group(1)
            if not is_private_ip(ip):
                bare_ip_relay = True
                bare_ip_value = ip
                break

    reply_to_mismatch = bool(
        rto_addr and from_domain and rto_domain and rto_domain != from_domain
    )
    return_path_mismatch = bool(
        rpath_addr and from_domain and rpath_domain and rpath_domain != from_domain
    )

    free_mail_sender = from_domain in _FREE_MAIL
    sender_lookalike_brand = lookalike_brand(from_domain) or ''

    return {
        'from_raw':             from_raw,
        'from_addr':            from_addr,
        'from_domain':          from_domain,
        'reply_to':             rto_addr,
        'reply_to_domain':      rto_domain,
        'return_path':          rpath_addr,
        'return_path_domain':   rpath_domain,
        'spf':                  spf,
        'dkim':                 dkim,
        'dmarc':                dmarc_result,
        'dmarc_action':         dmarc_action,
        'dmarc_weak':           dmarc_weak,
        'ms_scl':               scl,
        'ms_sfv':               sfv,
        'ms_cat':               cat,
        'ms_bcl':               bcl,
        'ms_spam_high':         ms_spam_high,
        'received':             received,
        'gmail_api_relay':      gmail_api_relay,
        'gmail_api_hops':       len(gmail_api_hops),
        'repeated_sends':       repeated_sends,
        'bare_ip_relay':        bare_ip_relay,
        'bare_ip_value':        bare_ip_value,
        'reply_to_mismatch':    reply_to_mismatch,
        'return_path_mismatch': return_path_mismatch,
        'free_mail_sender':          free_mail_sender,
        'sender_lookalike_brand':    sender_lookalike_brand,
        'subject':    msg.get('Subject', '(no subject)'),
        'date':       msg.get('Date', ''),
        'message_id': msg.get('Message-ID', ''),
    }


def _addr_domain(addr):
    if '@' in addr:
        return addr.split('@', 1)[-1].strip('<>').strip()
    return ''


def _extract(text, pattern):
    m = pattern.search(text)
    return m.group(1).lower() if m else ''


def _spf_fallback(msg):
    rcv_spf = msg.get('Received-SPF', '')
    if rcv_spf:
        m = re.match(r'(\w+)', rcv_spf.strip())
        if m:
            return m.group(1).lower()
    return 'none'
