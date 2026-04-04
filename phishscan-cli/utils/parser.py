"""
Email loading and body-extraction utilities.

Centralises all email.message.Message access so the analyzers
only need to call clean, typed functions rather than dealing with
MIME internals everywhere.
"""

import email
import sys
from pathlib import Path


def load_email(path):
    """
    Load a .eml file from disk and return a parsed email.message.Message.
    Exits with a clear error if the file cannot be read or parsed.
    """
    try:
        with open(path, 'rb') as fh:
            return email.message_from_bytes(fh.read())
    except FileNotFoundError:
        print(f'[ERROR] File not found: {path}', file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f'[ERROR] Failed to parse email: {exc}', file=sys.stderr)
        sys.exit(1)


def get_body_parts(msg):
    """
    Walk the MIME tree and return a list of decoded body parts.
    Each entry is a dict:
        { 'type': 'text/plain' | 'text/html', 'content': str }
    """
    parts = []
    for part in msg.walk():
        ct = part.get_content_type()
        if ct not in ('text/plain', 'text/html'):
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        charset = part.get_content_charset() or 'utf-8'
        try:
            content = payload.decode(charset, errors='replace')
        except (LookupError, Exception):
            content = payload.decode('utf-8', errors='replace')
        parts.append({'type': ct, 'content': content})
    return parts


def get_plain_text(msg):
    """Return concatenated plain-text body, or empty string."""
    return '\n'.join(
        p['content'] for p in get_body_parts(msg) if p['type'] == 'text/plain'
    )


def get_html_body(msg):
    """Return concatenated HTML body, or empty string."""
    return '\n'.join(
        p['content'] for p in get_body_parts(msg) if p['type'] == 'text/html'
    )
