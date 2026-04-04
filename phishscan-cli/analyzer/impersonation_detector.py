"""
Impersonation and Domain Spoofing Detection Layer.

Detects typosquatting, domain lookalikes, homoglyph attacks, and
redirect-service masking by cross-referencing the sender domain
against:
  1. Domains found in the email body (primary signal)
  2. A curated list of commonly-targeted business domains
  3. Mimecast / SafeLinks redirect wrapping

SOC Context:
  A lookalike domain registered 1 edit from the target (grosvernor.com
  vs grosvenor.com) passes SPF, DKIM, and all authentication checks
  because it IS a legitimate domain — just not the one it claims to be.
  Edit-distance comparison is the primary defence against this tactic.
"""

import re
import urllib.parse
from utils.helpers import levenshtein, get_sld, get_tld, BRAND_NAMES

KNOWN_BUSINESS_SLDS = frozenset({
    # Real-estate / property
    'grosvenor', 'cushmanwakefield', 'jll', 'cbre', 'savills', 'knightfrank',
    'colliers', 'brookfield',
    # Law / professional services
    'linklaters', 'freshfields', 'cliffordchance', 'slaughteranda', 'allenovery',
    'pwc', 'deloitte', 'kpmg', 'ey', 'accenture', 'mckinsey', 'bain',
    # Finance / banking
    'goldmansachs', 'morganstanley', 'jpmorgan', 'blackrock', 'vanguard',
    'fidelity', 'schwab', 'nomura', 'ubs', 'deutschebank', 'barclays',
    'lloydsbank', 'santander', 'natwest', 'tsb', 'nationwide',
    # Healthcare
    'nhs', 'bupa', 'axa', 'vitality',
    # Insurance
    'allianz', 'aviva', 'zurich', 'aig', 'lloydsoflon',
    # Shipping / logistics
    'maersk', 'cargill', 'expeditors', 'dsv',
    # Telecoms / ISP
    'bt', 'vodafone', 'ericsson', 'nokia',
})

_CHAR_SUBS = [
    ('0', 'o'), ('1', 'l'), ('3', 'e'), ('4', 'a'), ('5', 's'),
    ('6', 'g'), ('7', 't'), ('8', 'b'),
    ('rn', 'm'), ('vv', 'w'), ('cl', 'd'), ('cj', 'g'),
]

_REDIRECT_SERVICES = [
    ('mimecastprotect.com',              'Mimecast'),
    ('safelinks.protection.outlook.com', 'Microsoft Safe Links'),
    ('urldefense.com',                   'Proofpoint URL Defense'),
    ('urldefense.proofpoint.com',        'Proofpoint URL Defense'),
    ('linkprotect.cudasvc.com',          'Barracuda Link Protection'),
    ('secure.mimecast.com',              'Mimecast Secure URL'),
    ('click.email',                      'Generic click-tracker'),
]

_SAFELINKS_URL_RE = re.compile(r'[?&]url=([^&]+)', re.IGNORECASE)


def analyze_impersonation(headers, url_analysis):
    sender_domain = headers.get('from_domain', '')
    sender_sld    = get_sld(sender_domain)
    body_domains  = url_analysis.get('domains', [])

    similarity_hits = _cross_compare(sender_domain, sender_sld, body_domains)
    business_hit    = _compare_against_known(sender_sld, body_domains)
    homoglyph_hit   = _homoglyph_check(sender_sld, body_domains)
    redirect_hits   = _detect_redirects(url_analysis.get('raw', []))

    primary = similarity_hits[0] if similarity_hits else (
        business_hit if business_hit else (
            homoglyph_hit if homoglyph_hit else None
        )
    )

    return {
        'sender_domain':      sender_domain,
        'sender_sld':         sender_sld,
        'similarity_hits':    similarity_hits,
        'business_hit':       business_hit,
        'homoglyph_hit':      homoglyph_hit,
        'redirect_hits':      redirect_hits,
        'primary':            primary,
        'has_high_similarity':   any(h['risk'] == 'HIGH'   for h in similarity_hits),
        'has_medium_similarity': any(h['risk'] == 'MEDIUM' for h in similarity_hits),
        'has_business_match':    business_hit is not None,
        'has_homoglyph':         homoglyph_hit is not None,
        'has_redirect':          bool(redirect_hits),
    }


def _normalize_homoglyphs(sld):
    result = sld
    for glyph, real in sorted(_CHAR_SUBS, key=lambda x: -len(x[0])):
        result = result.replace(glyph, real)
    return result


def _compare_slds(a, b):
    if a == b:
        return 0, 0, False
    raw  = levenshtein(a, b)
    norm = levenshtein(_normalize_homoglyphs(a), _normalize_homoglyphs(b))
    is_homo = (norm < raw)
    return raw, norm, is_homo


def _risk_level(distance):
    if distance <= 2: return 'HIGH'
    if distance <= 3: return 'MEDIUM'
    return None


def _cross_compare(sender_domain, sender_sld, body_domains):
    if sender_sld in BRAND_NAMES or sender_sld in KNOWN_BUSINESS_SLDS:
        return []

    hits = []
    seen = set()
    for dom in body_domains:
        dom_sld = get_sld(dom)
        if dom_sld == sender_sld or dom_sld in seen:
            continue
        seen.add(dom_sld)

        raw, norm, is_homo = _compare_slds(sender_sld, dom_sld)
        best = min(raw, norm)
        risk = _risk_level(best)
        if not risk:
            continue

        hits.append({
            'matched_domain':  dom,
            'matched_sld':     dom_sld,
            'sender_domain':   sender_domain,
            'distance':        best,
            'raw_distance':    raw,
            'norm_distance':   norm,
            'is_homoglyph':    is_homo,
            'risk':            risk,
            'tactic': 'Homoglyph' if is_homo else 'Typosquatting',
        })

    hits.sort(key=lambda h: h['distance'])
    return hits


def _compare_against_known(sender_sld, body_domains):
    if sender_sld in BRAND_NAMES or sender_sld in KNOWN_BUSINESS_SLDS:
        return None

    body_slds = {get_sld(d) for d in body_domains}

    for known in KNOWN_BUSINESS_SLDS | BRAND_NAMES:
        if known in body_slds:
            continue
        raw, norm, is_homo = _compare_slds(sender_sld, known)
        best = min(raw, norm)
        risk = _risk_level(best)
        if risk and sender_sld != known:
            return {
                'matched_sld':  known,
                'distance':     best,
                'is_homoglyph': is_homo,
                'risk':         risk,
                'tactic':       'Homoglyph' if is_homo else 'Typosquatting',
            }
    return None


def _homoglyph_check(sender_sld, body_domains):
    normalised = _normalize_homoglyphs(sender_sld)
    if normalised == sender_sld:
        return None

    for dom in body_domains:
        dom_sld = get_sld(dom)
        if normalised == dom_sld:
            return {
                'matched_sld':  dom_sld,
                'normalised':   normalised,
                'distance':     0,
                'is_homoglyph': True,
                'risk':         'HIGH',
                'tactic':       'Homoglyph',
            }

    all_known = BRAND_NAMES | KNOWN_BUSINESS_SLDS
    if normalised in all_known:
        return {
            'matched_sld':  normalised,
            'normalised':   normalised,
            'distance':     0,
            'is_homoglyph': True,
            'risk':         'HIGH',
            'tactic':       'Homoglyph',
        }
    return None


def _detect_redirects(raw_urls):
    hits = []
    for url in raw_urls:
        url_lower = url.lower()
        for service_domain, service_name in _REDIRECT_SERVICES:
            if service_domain in url_lower:
                original = _unwrap_url(url)
                hits.append({
                    'url':          url,
                    'service':      service_name,
                    'original_url': original,
                })
                break
    return hits


def _unwrap_url(url):
    try:
        m = _SAFELINKS_URL_RE.search(url)
        if m:
            return urllib.parse.unquote(m.group(1))
        if 'urldefense.com' in url.lower():
            return ''
    except Exception:
        pass
    return ''
