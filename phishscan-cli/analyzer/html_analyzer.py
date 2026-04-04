"""
HTML structure analysis layer.

Inspects the rendered HTML structure for:
  1. URL mismatch — anchor display text differs from actual href
  2. Hidden elements — content made invisible via CSS
  3. Credential forms — password inputs in email
  4. Inline scripts — obfuscation / payload attempts
  5. Data URIs — embedded payloads
"""

import re
from urllib.parse import urlparse

_HREF_RE   = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                        re.IGNORECASE | re.DOTALL)
_STYLE_HIDDEN_RE = re.compile(
    r'style=["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|'
    r'font-size\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?)\b)[^"\']*["\']',
    re.IGNORECASE,
)
_FORM_RE      = re.compile(r'<form\b', re.IGNORECASE)
_INPUT_PW_RE  = re.compile(r'<input\b[^>]*type=["\']?password["\']?', re.IGNORECASE)
_SCRIPT_RE    = re.compile(r'<script\b', re.IGNORECASE)
_DATA_URI_RE  = re.compile(r'href=["\']data:', re.IGNORECASE)


def analyze_html(html):
    if not html:
        return _empty_result()

    url_mismatches    = _find_url_mismatches(html)
    hidden_count      = len(_STYLE_HIDDEN_RE.findall(html))
    has_form          = bool(_FORM_RE.search(html))
    has_password_form = bool(_INPUT_PW_RE.search(html))
    has_script        = bool(_SCRIPT_RE.search(html))
    has_data_uri      = bool(_DATA_URI_RE.search(html))

    return {
        'url_mismatches':     url_mismatches,
        'has_url_mismatch':   bool(url_mismatches),
        'hidden_element_count': hidden_count,
        'has_hidden_content': hidden_count > 0,
        'has_credential_form': has_password_form,
        'has_form':            has_form,
        'has_inline_script':  has_script,
        'has_data_uri':       has_data_uri,
    }


def _find_url_mismatches(html):
    mismatches = []
    for m in _HREF_RE.finditer(html):
        href    = m.group(1).strip()
        display = re.sub(r'<[^>]+>', '', m.group(2)).strip()

        if not (display.startswith('http') or display.startswith('www.')):
            continue

        try:
            href_host    = urlparse(href).netloc.lower().lstrip('www.')
            display_host = urlparse(display if display.startswith('http') else 'http://' + display).netloc.lower().lstrip('www.')
        except Exception:
            continue

        if href_host and display_host and href_host != display_host:
            mismatches.append({
                'display': display,
                'href':    href,
                'detail':  '{} -> {}'.format(display_host, href_host),
            })
    return mismatches


def _empty_result():
    return {
        'url_mismatches':     [],
        'has_url_mismatch':   False,
        'hidden_element_count': 0,
        'has_hidden_content': False,
        'has_credential_form': False,
        'has_form':            False,
        'has_inline_script':  False,
        'has_data_uri':       False,
    }
