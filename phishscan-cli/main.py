#!/usr/bin/env python3
"""
PhishScan v2 — Multi-Layer Phishing Detection Engine
=====================================================
CLI tool for SOC analysts to triage suspicious emails.

Analyzes email headers, URLs, content behaviour, and HTML structure
through four independent intelligence layers, then aggregates findings
into a weighted risk score with a human-readable verdict.

Usage:
    python main.py <email.eml>
    python main.py <email.eml> --verbose
    python main.py <email.eml> --json
    python main.py <email.eml> --no-color
"""

import sys
import json
import argparse
from pathlib import Path

# ── Pipeline imports ──────────────────────────────────────────────────────────
from utils.parser import load_email, get_body_parts, get_html_body
from analyzer.header_analyzer        import analyze_headers
from analyzer.url_analyzer           import extract_urls, analyze_urls
from analyzer.content_analyzer       import analyze_content
from analyzer.html_analyzer          import analyze_html
from analyzer.impersonation_detector import analyze_impersonation
from analyzer.threat_intel           import (query_all as ti_query_all, empty_result as ti_empty,
                                              query_virustotal_domain, query_ismalicious,
                                              query_abuseipdb)
from analyzer.scoring_engine         import run_rules, calculate_score
from analyzers.iocs                  import extract_iocs   # existing IOC module
from utils.helpers import defang

# ── Colour support (graceful degradation) ────────────────────────────────────
try:
    from colorama import init as _cinit, Fore, Style
    _cinit(autoreset=True)
    _COLOR = True
except ImportError:
    class _Stub:
        def __getattr__(self, _): return ''
    Fore = Style = _Stub()
    _COLOR = False

_NO_COLOR = False   # overridden by --no-color flag


def _c(code, text):
    if _NO_COLOR or not _COLOR:
        return text
    return code + text + Style.RESET_ALL


# ── Pipeline ──────────────────────────────────────────────────────────────────

def run_analysis(eml_path, verbose=False, quiet=False, no_api=False):
    """
    Execute the full four-layer analysis pipeline.
    Returns a result dict consumed by the report renderer or JSON exporter.
    """
    def step(msg):
        if not quiet:
            print(_c(Fore.CYAN, '[+]') + ' ' + msg)

    msg = load_email(eml_path)

    step('Parsing email headers…')
    headers = analyze_headers(msg)

    step('Extracting and classifying URLs…')
    body_parts   = get_body_parts(msg)
    raw_urls     = extract_urls(body_parts)
    url_analysis = analyze_urls(raw_urls)

    step('Analysing body content…')
    content = analyze_content(body_parts, headers)

    step('Inspecting HTML structure…')
    html_body = get_html_body(msg)
    html      = analyze_html(html_body)

    step('Running impersonation analysis…')
    impersonation = analyze_impersonation(headers, url_analysis)

    if not no_api:
        step('Querying threat intelligence APIs…')
        iocs        = extract_iocs(msg, raw_urls, headers)
        threat_intel = ti_query_all(headers, url_analysis, iocs)
    else:
        iocs         = {'domains': [], 'ips': [], 'hashes': []}
        threat_intel = ti_empty()

    step('Running multi-layer detection rules…')
    hits = run_rules(headers, url_analysis, content, html,
                     impersonation=impersonation, threat_intel=threat_intel)

    step('Calculating weighted risk score…')
    score, verdict = calculate_score(hits)

    return {
        'file':         str(eml_path),
        'headers':      headers,
        'url_analysis': url_analysis,
        'content':      content,
        'html':         html,
        'impersonation': impersonation,
        'threat_intel': threat_intel,
        'iocs':         iocs,
        'hits':         hits,
        'score':        score,
        'verdict':      verdict,
        'verbose':      verbose,
        'no_api_flag':  no_api,
    }


# ── Report renderer ───────────────────────────────────────────────────────────

def print_report(r):
    h   = r['headers']
    u   = r['url_analysis']
    c   = r['content']
    htm = r['html']

    def bar(char='═', w=56):
        print(_c(Fore.CYAN, '  ' + char * w))

    def section(title):
        print()
        print('  ' + _c(Fore.CYAN + Style.BRIGHT, title))
        print('  ' + _c(Fore.CYAN, '─' * len(title)))

    def kv(key, val, width=14):
        print('  {:{w}}  {}'.format(key, val, w=width))

    def auth_kv(key, val):
        val = (val or 'none').upper()
        if val == 'PASS':
            colored = _c(Fore.GREEN + Style.BRIGHT, val)
        elif val in ('FAIL', 'NONE'):
            colored = _c(Fore.RED + Style.BRIGHT, val)
        else:
            colored = _c(Fore.YELLOW + Style.BRIGHT, val)
        kv(key, colored)

    print()
    bar('═')
    print('  ' + _c(Fore.CYAN + Style.BRIGHT, 'PHISHSCAN REPORT  v2'))
    bar('═')

    # ── Metadata ──────────────────────────────────────────────────────────────
    section('EMAIL METADATA')
    kv('File',    r['file'])
    kv('Subject', h['subject'] or '(no subject)')
    kv('Date',    h['date']    or '(unknown)')
    sender_str = defang(h['from_addr']) if h['from_addr'] else _c(Style.DIM, '(none)')
    kv('Sender',  sender_str)
    if h['reply_to']:
        rt_str = defang(h['reply_to'])
        if h['reply_to_mismatch']:
            rt_str += '  ' + _c(Fore.RED + Style.BRIGHT, '[MISMATCH]')
        kv('Reply-To', rt_str)
    if h['return_path'] and h['return_path_mismatch']:
        kv('Return-Path', defang(h['return_path']) + '  ' + _c(Fore.RED, '[MISMATCH]'))

    # ── Authentication ────────────────────────────────────────────────────────
    section('AUTHENTICATION')
    auth_kv('SPF',   h['spf'])
    auth_kv('DKIM',  h['dkim'])
    dmarc_str = h['dmarc'].upper() or 'NONE'
    if h['dmarc_weak']:
        dmarc_str += '  ' + _c(Fore.YELLOW, '[WEAK — no enforcement]')
    kv('DMARC', dmarc_str)

    # Microsoft spam verdict if present
    if h['ms_spam_high']:
        ms_str = 'SCL:{ms_scl}  SFV:{ms_sfv}  CAT:{ms_cat}'.format(**h)
        kv('MS Spam', _c(Fore.RED, ms_str))

    # Relay chain notes
    if h['gmail_api_relay']:
        relay_str = _c(Fore.YELLOW, 'Gmail API ({} hop{})'.format(
            h['gmail_api_hops'], 's' if h['gmail_api_hops'] != 1 else ''))
        kv('Relay', relay_str)
    if h['bare_ip_relay']:
        kv('Bare IP', _c(Fore.RED, h['bare_ip_value']))

    # ── URL analysis ──────────────────────────────────────────────────────────
    section('URL ANALYSIS  ({} URL{})'.format(u['count'], 's' if u['count'] != 1 else ''))

    if not u['raw']:
        print('    ' + _c(Style.DIM, 'None found'))
    else:
        shortener_set  = set(u['shorteners'])
        lookalike_urls = {e['url'] for e in u['lookalikes']}
        homoglyph_urls = {e['url'] for e in u['homoglyphs']}
        bad_tld_set    = set(u['bad_tld'])
        susp_set       = set(u['suspicious'])
        ip_set         = set(u['ip_urls'])

        for url in u['defanged']:
            tags = []
            if url in ip_set:         tags.append(_c(Fore.RED,    '[IP-URL]'))
            if url in lookalike_urls: tags.append(_c(Fore.RED,    '[LOOKALIKE]'))
            if url in homoglyph_urls: tags.append(_c(Fore.RED,    '[HOMOGLYPH]'))
            if url in susp_set:       tags.append(_c(Fore.RED,    '[SUSPICIOUS]'))
            if url in bad_tld_set:    tags.append(_c(Fore.YELLOW, '[BAD-TLD]'))
            if url in shortener_set:  tags.append(_c(Fore.YELLOW, '[SHORTENER]'))
            flag_str = '  '.join(tags)
            print('    ' + _c(Fore.WHITE, url) + ('  ' + flag_str if tags else ''))

    # ── Content ───────────────────────────────────────────────────────────────
    section('CONTENT ANALYSIS')
    _yn(c['has_urgency'],        'Urgency / fear language')
    _yn(c['has_cred_harvest'],   'Credential harvesting cues')
    _yn(c['has_bec'],            'BEC pattern (invoice / RFQ / wire transfer)')
    _yn(c['has_impersonation'],  'Brand impersonation claim in body')
    _yn(c['has_attachment_lure'],'Attachment lure language')

    # ── HTML ──────────────────────────────────────────────────────────────────
    section('HTML STRUCTURE')
    _yn(htm['has_url_mismatch'],   'Link display/destination mismatch')
    _yn(htm['has_hidden_content'], 'Hidden HTML elements')
    _yn(htm['has_credential_form'],'Credential form (password input)')
    _yn(htm['has_inline_script'],  'Inline script block')

    # ── Impersonation Analysis ────────────────────────────────────────────────
    imp = r.get('impersonation', {})
    section('IMPERSONATION ANALYSIS')
    kv('Sender domain', defang(imp.get('sender_domain', '')) or _c(Style.DIM, '(unknown)'))

    primary = imp.get('primary')
    if primary:
        dist    = primary.get('distance', '?')
        tactic  = primary.get('tactic', 'Typosquatting')
        risk    = primary.get('risk', 'HIGH')
        risk_c  = Fore.RED if risk == 'HIGH' else Fore.YELLOW
        matched = primary.get('matched_domain') or primary.get('matched_sld', '?')
        kv('Similar to',    defang(matched))
        kv('Distance',      str(dist) + ' edit{}'.format('' if dist == 1 else 's'))
        kv('Tactic',        tactic)
        kv('Verdict',       _c(risk_c + Style.BRIGHT, risk + ' RISK (' + tactic + ')'))
    else:
        print('    ' + _c(Style.DIM, 'No domain spoofing detected'))

    if imp.get('redirect_hits'):
        for rh in imp['redirect_hits']:
            orig = rh.get('original_url', '')
            orig_str = '  → ' + defang(orig[:60]) if orig else ''
            print('    ' + _c(Fore.YELLOW, '[!]') + '  Redirect: ' +
                  _c(Fore.YELLOW, rh['service']) + orig_str)

    # ── Threat Intelligence ───────────────────────────────────────────────────
    ti = r.get('threat_intel', {})
    section('THREAT INTELLIGENCE')
    any_key = ti.get('vt_enabled') or ti.get('ismal_enabled') or ti.get('abipdb_enabled')
    if not any_key:
        print('    ' + _c(Style.DIM, 'No API keys configured — skipped'))
        print('    ' + _c(Style.DIM,
              'Copy .env.example to .env and add your keys, then re-run without --no-api'))
    elif r.get('no_api_flag'):
        print('    ' + _c(Style.DIM, 'Skipped (--no-api flag)'))
    else:
        # VirusTotal
        if ti.get('vt_enabled'):
            vt_results = ti.get('vt_results', [])
            if vt_results:
                max_mal = ti.get('vt_max_malicious', 0)
                total_e = max(rv.get('harmless', 0) + rv.get('malicious', 0) + rv.get('suspicious', 0)
                              for rv in vt_results)
                vt_conf = 'HIGH' if max_mal >= 10 else ('MEDIUM' if max_mal >= 3 else 'LOW')
                vt_c    = Fore.RED if max_mal >= 10 else (Fore.YELLOW if max_mal >= 3 else Fore.GREEN)
                kv('VirusTotal', _c(vt_c, '{}/{} detections — {}'.format(max_mal, total_e, vt_conf)))
            else:
                kv('VirusTotal', _c(Fore.GREEN, 'CLEAN  (0 engines flagged)'))

        # isMalicious
        if ti.get('ismal_enabled'):
            ismal = ti.get('ismal_results', [])
            if ismal:
                flag   = any(rv.get('malicious', 0) > 0 for rv in ismal)
                isml_c = Fore.RED if flag else Fore.GREEN
                kv('isMalicious', _c(isml_c, 'MALICIOUS' if flag else 'CLEAN'))
            else:
                kv('isMalicious', _c(Fore.GREEN, 'CLEAN'))

        # AbuseIPDB
        if ti.get('abipdb_enabled'):
            ab = ti.get('abipdb_results', [])
            if ab:
                high   = any(rv.get('confidence') in ('high', 'medium') for rv in ab)
                ab_c   = Fore.RED if high else Fore.GREEN
                kv('AbuseIPDB',  _c(ab_c, 'HIGH ABUSE' if high else 'CLEAN'))
            else:
                kv('AbuseIPDB', _c(Fore.GREEN, 'CLEAN  (no IPs to check)'))

    # ── Score & verdict ───────────────────────────────────────────────────────
    print()
    bar('─')
    score   = r['score']
    verdict = r['verdict']
    if verdict == 'HIGH RISK PHISHING':
        vc = Fore.RED + Style.BRIGHT
    elif verdict == 'SUSPICIOUS':
        vc = Fore.YELLOW + Style.BRIGHT
    else:
        vc = Fore.GREEN + Style.BRIGHT

    filled  = score // 5
    bar_str = _c(vc, '[' + '█' * filled + '░' * (20 - filled) + ']')
    print('  Score   : ' + _c(vc, '{}/100'.format(score)) + '  ' + bar_str)
    print('  Verdict : ' + _c(vc, verdict))
    bar('─')

    # ── Detection reasons ─────────────────────────────────────────────────────
    if r['hits']:
        section('DETECTION REASONS')
        by_cat = {}
        for hit in r['hits']:
            by_cat.setdefault(hit['category'], []).append(hit)
        for cat in ('header', 'url', 'content', 'html', 'impersonation', 'external'):
            if cat not in by_cat:
                continue
            print('    ' + _c(Fore.CYAN, '[{}]'.format(cat.upper())))
            for hit in by_cat[cat]:
                pts = '+{:>2}'.format(hit['score'])
                print('    ' + _c(Fore.YELLOW, pts) + '  ' + hit['reason'])

    # ── Verbose rule breakdown ─────────────────────────────────────────────────
    if r.get('verbose'):
        section('ALL RULES (--verbose)')
        from analyzer.scoring_engine import RULES
        hit_ids = {h['id'] for h in r['hits']}
        for rule in RULES:
            if rule.id in hit_ids:
                print('  ' + _c(Fore.RED,   '  HIT') + '  +{:>2}  [{}]  {}'.format(
                    rule.score, rule.category, rule.id))
            else:
                print('  ' + _c(Fore.GREEN, ' PASS') + '   +0  [{}]  {}'.format(
                    rule.category, rule.id))

    print()


def _yn(flag, label):
    if flag:
        print('    ' + _c(Fore.RED,   '[!]') + '  ' + label)
    else:
        print('    ' + _c(Fore.GREEN, '[ ]') + '  ' + label)


# ── JSON export ───────────────────────────────────────────────────────────────

def to_json(r):
    h   = r['headers']
    imp = r.get('impersonation', {})
    ti  = r.get('threat_intel', {})
    return {
        'file':    r['file'],
        'subject': h['subject'],
        'sender':  h['from_addr'],
        'spf':     h['spf'],
        'dkim':    h['dkim'],
        'dmarc':   h['dmarc'],
        'ms_spam': {'scl': h['ms_scl'], 'sfv': h['ms_sfv'], 'cat': h['ms_cat']},
        'urls':    r['url_analysis']['defanged'],
        'impersonation': {
            'sender_domain': imp.get('sender_domain'),
            'primary_match': imp.get('primary'),
            'redirect_hits': imp.get('redirect_hits', []),
        },
        'threat_intel': {
            'vt_max_malicious': ti.get('vt_max_malicious', 0),
            'ismal_flagged':    ti.get('ismal_flagged', False),
            'abipdb_high':      ti.get('abipdb_high', False),
        },
        'score':   r['score'],
        'verdict': r['verdict'],
        'reasons': [hit['reason'] for hit in r['hits']],
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def test_apis():
    """
    Connectivity check for all configured threat intelligence APIs.
    Uses 'google.com' as a known-clean test target.
    Prints OK / FAIL / NOT CONFIGURED for each source.
    """
    import os
    _TEST_HOST = 'google.com'

    print()
    print(_c(Fore.CYAN, '  Checking threat intelligence API connectivity...'))
    print()

    # VirusTotal
    vt_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not vt_key:
        print('  VirusTotal    : ' + _c(Fore.YELLOW, 'NOT CONFIGURED') +
              '  (set VIRUSTOTAL_API_KEY in .env)')
    else:
        r = query_virustotal_domain(_TEST_HOST)
        if r is not None:
            print('  VirusTotal    : ' + _c(Fore.GREEN, 'OK') +
                  '  (key: {}...)'.format(vt_key[:8]))
        else:
            print('  VirusTotal    : ' + _c(Fore.RED, 'FAIL') +
                  '  (key configured but request failed)')

    # isMalicious
    ismal_key = os.environ.get('ISMALICIOUS_API_KEY', '')
    if not ismal_key:
        print('  isMalicious   : ' + _c(Fore.YELLOW, 'NOT CONFIGURED') +
              '  (set ISMALICIOUS_API_KEY + ISMALICIOUS_API_SECRET in .env)')
    else:
        r = query_ismalicious(_TEST_HOST)
        if r is not None:
            print('  isMalicious   : ' + _c(Fore.GREEN, 'OK') +
                  '  (key: {}...)'.format(ismal_key[:8]))
        else:
            print('  isMalicious   : ' + _c(Fore.RED, 'FAIL') +
                  '  (key configured but request failed)')

    # AbuseIPDB — test with a known public IP (Google DNS)
    ab_key = os.environ.get('ABUSEIPDB_API_KEY', '')
    if not ab_key:
        print('  AbuseIPDB     : ' + _c(Fore.YELLOW, 'NOT CONFIGURED') +
              '  (set ABUSEIPDB_API_KEY in .env)')
    else:
        r = query_abuseipdb('8.8.8.8')
        if r is not None:
            print('  AbuseIPDB     : ' + _c(Fore.GREEN, 'OK') +
                  '  (key: {}...)'.format(ab_key[:8]))
        else:
            print('  AbuseIPDB     : ' + _c(Fore.RED, 'FAIL') +
                  '  (key configured but request failed)')

    print()


def build_parser():
    p = argparse.ArgumentParser(
        prog='phishscan',
        description='PhishScan v2 — Multi-Layer Phishing Detection Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python main.py suspicious.eml\n'
            '  python main.py suspicious.eml --verbose\n'
            '  python main.py suspicious.eml --json\n'
            '  python main.py suspicious.eml --no-color\n'
            '  python main.py --test-apis'
        ),
    )
    p.add_argument('eml_file',    nargs='?', help='Path to the .eml file to analyse')
    p.add_argument('--json',      action='store_true', help='Output results as JSON')
    p.add_argument('--verbose',   action='store_true', help='Show all rules, not just hits')
    p.add_argument('--no-color',  action='store_true', help='Disable ANSI colour output')
    p.add_argument('--no-api',    action='store_true',
                   help='Skip external threat-intelligence API lookups')
    p.add_argument('--test-apis', action='store_true',
                   help='Test connectivity for all configured threat-intel API keys and exit')
    return p


def main():
    global _NO_COLOR
    parser = build_parser()
    args   = parser.parse_args()

    if args.no_color:
        _NO_COLOR = True

    if args.test_apis:
        test_apis()
        sys.exit(0)

    if not args.eml_file:
        parser.print_help()
        sys.exit(1)

    eml_path = Path(args.eml_file)
    if not eml_path.exists():
        print('[ERROR] File not found: {}'.format(args.eml_file), file=sys.stderr)
        sys.exit(1)

    result = run_analysis(eml_path, verbose=args.verbose,
                          quiet=args.json, no_api=args.no_api)

    if args.json:
        print(json.dumps(to_json(result), indent=2))
    else:
        print_report(result)


if __name__ == '__main__':
    main()
