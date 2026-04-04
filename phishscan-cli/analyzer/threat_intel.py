"""
External Threat Intelligence Enrichment Layer.

Supported sources:
  - VirusTotal v3    (VIRUSTOTAL_API_KEY)
  - isMalicious      (ISMALICIOUS_API_KEY + ISMALICIOUS_API_SECRET)
  - AbuseIPDB        (ABUSEIPDB_API_KEY)

API keys are read from environment variables (auto-loaded from .env).
All lookups fail gracefully — missing keys or errors return empty results.

Copy .env.example to .env and fill in your keys to enable threat intel.
"""

import os
import time
import urllib.request
from pathlib import Path
import urllib.error
import urllib.parse
import json
import base64


def _load_dotenv():
    env_path = Path(__file__).resolve().parent.parent / '.env'
    if not env_path.exists():
        return
    with open(env_path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, val = line.partition('=')
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val


_load_dotenv()

_VT_BASE      = 'https://www.virustotal.com/api/v3'
_ISMAL_BASE   = 'https://ismalicious.com/api/v1/check'
_ABIPDB_BASE  = 'https://api.abuseipdb.com/api/v2/check'
_TIMEOUT      = 8
_SLEEP        = 1.1


def _result(source, target, target_type, malicious, suspicious, harmless, confidence, raw=None):
    return {
        'source':      source,
        'target':      target,
        'target_type': target_type,
        'malicious':   malicious,
        'suspicious':  suspicious,
        'harmless':    harmless,
        'confidence':  confidence,
        'raw':         raw or {},
    }


def _vt_confidence(malicious):
    if malicious >= 10: return 'high'
    if malicious >= 3:  return 'medium'
    if malicious >= 1:  return 'low'
    return 'unknown'


def _vt_headers():
    key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not key:
        return None
    return {'x-apikey': key, 'Accept': 'application/json'}


def _vt_get(path):
    headers = _vt_headers()
    if not headers:
        return None
    req = urllib.request.Request(_VT_BASE + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return None
    except Exception:
        return None


def query_virustotal_domain(domain):
    data = _vt_get('/domains/{}'.format(domain))
    if not data:
        return None
    try:
        stats = data['data']['attributes']['last_analysis_stats']
        mal  = stats.get('malicious',  0)
        susp = stats.get('suspicious', 0)
        hrm  = stats.get('harmless',   0)
        return _result('virustotal', domain, 'domain', mal, susp, hrm,
                        _vt_confidence(mal), raw=stats)
    except (KeyError, TypeError):
        return None


def query_virustotal_url(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    data   = _vt_get('/urls/{}'.format(url_id))
    if not data:
        return None
    try:
        stats = data['data']['attributes']['last_analysis_stats']
        mal  = stats.get('malicious',  0)
        susp = stats.get('suspicious', 0)
        hrm  = stats.get('harmless',   0)
        return _result('virustotal', url, 'url', mal, susp, hrm,
                        _vt_confidence(mal), raw=stats)
    except (KeyError, TypeError):
        return None


def _ismal_header():
    key    = os.environ.get('ISMALICIOUS_API_KEY', '')
    secret = os.environ.get('ISMALICIOUS_API_SECRET', '')
    if not key or not secret:
        return None
    token = base64.b64encode('{}:{}'.format(key, secret).encode()).decode()
    return token


def query_ismalicious(host):
    token = _ismal_header()
    if not token:
        return None

    url = '{}?host={}'.format(_ISMAL_BASE, urllib.parse.quote(host, safe=''))
    req = urllib.request.Request(url, headers={
        'Accept':    'application/json',
        'X-API-KEY': token,
    })
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return None
    except Exception:
        return None

    try:
        is_mal  = data.get('malicious', False)
        verdict = data.get('verdict', 'unknown').lower()
        mal  = 1 if is_mal or verdict == 'malicious'  else 0
        susp = 1 if verdict == 'suspicious'            else 0
        hrm  = 1 if not is_mal and verdict not in ('suspicious',) else 0
        conf = 'high'   if mal  else (
               'medium' if susp else 'unknown')
        return _result('ismalicious', host, 'domain', mal, susp, hrm, conf, raw=data)
    except Exception:
        return None


def query_abuseipdb(ip):
    key = os.environ.get('ABUSEIPDB_API_KEY', '')
    if not key:
        return None

    params = urllib.parse.urlencode({'ipAddress': ip, 'maxAgeInDays': 90})
    url    = '{}?{}'.format(_ABIPDB_BASE, params)
    req    = urllib.request.Request(url, headers={
        'Key': key, 'Accept': 'application/json'
    })
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return None

    try:
        abuse_score = int(data['data'].get('abuseConfidenceScore', 0))
        if abuse_score >= 75:
            mal, conf = 10, 'high'
        elif abuse_score >= 25:
            mal, conf = 4,  'medium'
        else:
            mal, conf = 0,  'unknown'
        return _result('abuseipdb', ip, 'ip', mal, 0, 0, conf,
                        raw={'abuseConfidenceScore': abuse_score})
    except Exception:
        return None


def query_all(headers, url_analysis, iocs):
    results = []
    skipped = []

    def _add(fn, *args):
        r = fn(*args)
        if r:
            results.append(r)
            time.sleep(_SLEEP)
        else:
            skipped.append(fn.__name__)

    sender_domain = headers.get('from_domain', '')
    if sender_domain:
        _add(query_virustotal_domain, sender_domain)
        _add(query_ismalicious, sender_domain)

    url_domains   = url_analysis.get('domains', [])
    shortener_set = set(url_analysis.get('shorteners', []))
    checked = 0
    for dom in url_domains:
        if dom == sender_domain or dom in shortener_set:
            continue
        _add(query_virustotal_domain, dom)
        checked += 1
        if checked >= 3:
            break

    for ip in (iocs.get('ips') or [])[:3]:
        _add(query_abuseipdb, ip)

    vt_results    = [r for r in results if r['source'] == 'virustotal']
    ismal_results = [r for r in results if r['source'] == 'ismalicious']
    abipdb_results = [r for r in results if r['source'] == 'abuseipdb']

    max_vt_mal    = max((r['malicious'] for r in vt_results),   default=0)
    ismal_flagged = any(r['malicious'] > 0 for r in ismal_results)
    abipdb_high   = any(r['confidence'] in ('high', 'medium') for r in abipdb_results)

    return {
        'results':       results,
        'skipped':       list(set(skipped)),
        'vt_results':    vt_results,
        'ismal_results': ismal_results,
        'abipdb_results': abipdb_results,
        'vt_max_malicious': max_vt_mal,
        'vt_high':          max_vt_mal >= 10,
        'vt_medium':        3 <= max_vt_mal < 10,
        'ismal_flagged':    ismal_flagged,
        'abipdb_high':      abipdb_high,
        'vt_enabled':    bool(os.environ.get('VIRUSTOTAL_API_KEY')),
        'ismal_enabled': bool(os.environ.get('ISMALICIOUS_API_KEY')),
        'abipdb_enabled': bool(os.environ.get('ABUSEIPDB_API_KEY')),
    }


def empty_result():
    return {
        'results': [], 'skipped': [], 'vt_results': [],
        'ismal_results': [], 'abipdb_results': [],
        'vt_max_malicious': 0, 'vt_high': False, 'vt_medium': False,
        'ismal_flagged': False, 'abipdb_high': False,
        'vt_enabled': False, 'ismal_enabled': False, 'abipdb_enabled': False,
    }
