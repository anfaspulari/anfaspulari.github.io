"""
IOC extraction — domains, IP addresses, and file hashes from email content.
"""

import re
from utils.helpers import extract_domain

_IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

_SHA256_RE = re.compile(r'\b[0-9a-fA-F]{64}\b')
_SHA1_RE   = re.compile(r'\b[0-9a-fA-F]{40}\b')
_MD5_RE    = re.compile(r'\b[0-9a-fA-F]{32}\b')

_PRIVATE_IP_RE = re.compile(
    r'^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)'
)


def extract_iocs(msg, urls, headers):
    body = _get_body(msg)
    return {
        'domains': _extract_domains(urls, headers),
        'ips':     _extract_ips(body, headers),
        'hashes':  _extract_hashes(body),
    }


def _get_body(msg):
    parts = []
    for part in msg.walk():
        if part.get_content_type() not in ('text/plain', 'text/html'):
            continue
        try:
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or 'utf-8'
                parts.append(payload.decode(charset, errors='replace'))
        except Exception:
            pass
    return ' '.join(parts)


def _extract_domains(urls, headers):
    seen = set()
    domains = []
    for url in urls:
        d = extract_domain(url)
        if d and d not in seen:
            seen.add(d)
            domains.append(d)
    for field in ('from_domain', 'reply_to_domain'):
        d = headers.get(field, '')
        if d and d not in seen:
            seen.add(d)
            domains.append(d)
    return domains


def _extract_ips(body, headers):
    seen = set()
    ips  = []

    def add(ip):
        if ip not in seen and not _PRIVATE_IP_RE.match(ip):
            seen.add(ip)
            ips.append(ip)

    for ip in _IP_RE.findall(body):
        add(ip)
    for received in headers.get('received', []):
        for ip in _IP_RE.findall(received):
            add(ip)
    return ips


def _extract_hashes(body):
    seen   = set()
    hashes = []
    for pattern, hash_type in (
        (_SHA256_RE, 'sha256'),
        (_SHA1_RE,   'sha1'),
        (_MD5_RE,    'md5'),
    ):
        for match in pattern.findall(body):
            val = match.lower()
            if val not in seen:
                seen.add(val)
                hashes.append({'type': hash_type, 'value': val})
    return hashes
