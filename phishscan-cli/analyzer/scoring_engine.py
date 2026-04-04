"""
Scoring engine — weighted multi-layer risk model.

Each detection rule contributes points if it fires.
Internal rules are uncapped; external (API) rules are capped at 40 pts total.
Final score is capped at 100.

Verdicts: 0–30 LOW RISK, 31–70 SUSPICIOUS, 71–100 HIGH RISK PHISHING
"""

from collections import namedtuple

Rule = namedtuple('Rule', ['id', 'score', 'category', 'reason'])

RULES = [
    # ── Header — Authentication ─────────────────────────────────────────────────
    Rule('spf_fail',     20, 'header', 'SPF validation FAILED — sender domain not authorised'),
    Rule('spf_softfail', 10, 'header', 'SPF soft-fail (~all) — weak sender domain policy'),
    Rule('spf_none',     10, 'header', 'No SPF record published for sender domain'),
    Rule('dkim_fail',    10, 'header', 'DKIM signature absent or invalid ({dkim})'),
    Rule('dmarc_weak',   10, 'header', 'DMARC not enforced (result: {dmarc}) — spoofing risk'),
    # ── Header — Infrastructure ──────────────────────────────────────────────
    Rule('ms_spam_high', 25, 'header',
         'Microsoft Exchange flagged as spam (SCL:{ms_scl}, SFV:{ms_sfv}, CAT:{ms_cat})'),
    Rule('gmail_api_relay', 20, 'header',
         'Email sent via Gmail API (gmailapi.google.com) — unusual for business email'),
    Rule('repeated_sends', 10, 'header',
         'Email re-sent {gmail_api_hops}x via Gmail API — automated campaign behaviour'),
    Rule('bare_ip_relay',  10, 'header',
         'Email relayed through bare public IP (no reverse DNS): {bare_ip_value}'),
    Rule('sender_lookalike', 30, 'header',
         'Sender domain "{from_domain}" is a lookalike of brand "{sender_lookalike_brand}"'),
    Rule('reply_to_mismatch', 25, 'header',
         'Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain})'),
    Rule('return_path_mismatch', 15, 'header',
         'Return-Path domain ({return_path_domain}) differs from From domain ({from_domain})'),
    # ── URL ───────────────────────────────────────────────────────────────────
    Rule('lookalike_domain', 30, 'url',
         'Sender domain is a lookalike of brand "{lookalike_brand}" — likely impersonation'),
    Rule('ip_url',           25, 'url',
         'URL uses bare IP address (no hostname): {ip_url_sample}'),
    Rule('homoglyph_url',    20, 'url',
         'Homoglyph attack detected in URL — "{homoglyph_domain}" impersonates "{homoglyph_brand}"'),
    Rule('url_shortener',    15, 'url',
         'URL shortener hides final destination: {shortener_sample}'),
    Rule('suspicious_tld',   15, 'url',
         'URL uses high-abuse TLD: {bad_tld_sample}'),
    Rule('suspicious_url',   25, 'url',
         'Suspicious URL pattern (brand + keyword): {susp_url_sample}'),
    Rule('many_urls',        10, 'url',
         'High URL count ({url_count}) — unusual for a plain business email'),
    # ── Content ─────────────────────────────────────────────────────────────
    Rule('urgency_language', 10, 'content',
         'Urgency / fear language detected in body — pressure tactic'),
    Rule('credential_harvest', 15, 'content',
         'Credential harvesting language detected — requests sensitive information'),
    Rule('bec_pattern',      15, 'content',
         'Business Email Compromise pattern detected ({bec_hint})'),
    Rule('impersonation_body', 20, 'content',
         'Body claims to be from "{impersonation_brand}" but From domain does not match'),
    Rule('attachment_lure',  10, 'content',
         'Attachment lure language found — attempts to get recipient to open a file'),
    # ── HTML ────────────────────────────────────────────────────────────────
    Rule('url_mismatch_html', 20, 'html',
         'Visible URL in email differs from actual href link destination'),
    Rule('hidden_content',   15, 'html',
         'Hidden HTML elements detected — may conceal payload or bypass filters'),
    Rule('credential_form',  20, 'html',
         'HTML form with password input — credential phishing page embedded'),
    Rule('inline_script',    10, 'html',
         'Inline <script> block in email body — obfuscation / payload attempt'),
    # ── Impersonation (cross-email domain comparison) ──────────────────────────
    Rule('sender_url_spoof_high',   40, 'impersonation',
         'Sender domain "{sender_domain}" is {distance} edit(s) from '
         '"{matched_domain}" found in email — Levenshtein typosquatting ({tactic})'),
    Rule('sender_url_spoof_medium', 20, 'impersonation',
         'Sender domain "{sender_domain}" is moderately similar to '
         '"{matched_domain}" (distance {distance}) — possible typosquatting'),
    Rule('sender_known_spoof',      35, 'impersonation',
         'Sender domain is a lookalike of known organisation "{matched_sld}" '
         '(distance {distance}, {tactic})'),
    Rule('sender_homoglyph',        40, 'impersonation',
         'Homoglyph attack on sender domain — "{sender_sld}" normalises to '
         '"{normalised}" (impersonates "{matched_sld}")'),
    Rule('redirect_service',        10, 'impersonation',
         'URL wrapped by redirect service ({service}) — true destination hidden'),
    # ── Threat intelligence (external — capped at 40 pts total) ─────────────────
    Rule('vt_high_risk',      30, 'external',
         'VirusTotal: {vt_max_malicious} engines flagged sender/URL as malicious'),
    Rule('vt_medium_risk',    15, 'external',
         'VirusTotal: {vt_max_malicious} engines flagged as suspicious/malicious'),
    Rule('ismal_flagged',     40, 'external',
         'isMalicious: domain/IP flagged as malicious'),
    Rule('abipdb_high',       20, 'external',
         'AbuseIPDB: relay IP has high abuse confidence score'),
]


def run_rules(headers, url_analysis, content, html,
              impersonation=None, threat_intel=None):
    ctx = _build_context(headers, url_analysis, content, html,
                         impersonation or {}, threat_intel or {})
    hits = []
    for rule in RULES:
        fired, reason = _evaluate(rule, ctx)
        if fired:
            hits.append({
                'id':       rule.id,
                'score':    rule.score,
                'category': rule.category,
                'reason':   reason,
            })
    return hits


def calculate_score(hits):
    internal = sum(h['score'] for h in hits if h.get('category') != 'external')
    external = sum(h['score'] for h in hits if h.get('category') == 'external')
    external = min(external, 40)
    total    = min(internal + external, 100)

    if total >= 71:
        verdict = 'HIGH RISK PHISHING'
    elif total >= 31:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'LOW RISK'

    return total, verdict


def _evaluate(rule, ctx):
    rid = rule.id

    if rid == 'spf_fail'     and ctx['spf'] == 'fail':      return True, rule.reason
    if rid == 'spf_softfail' and ctx['spf'] == 'softfail':  return True, rule.reason
    if rid == 'spf_none'     and ctx['spf'] in ('none', ''): return True, rule.reason
    if rid == 'dkim_fail'    and ctx['dkim'] in ('none', 'fail', 'neutral'):
        return True, rule.reason.format(**ctx)
    if rid == 'dmarc_weak'   and ctx['dmarc_weak']:
        return True, rule.reason.format(**ctx)
    if rid == 'ms_spam_high' and ctx['ms_spam_high']:
        return True, rule.reason.format(**ctx)
    if rid == 'gmail_api_relay' and ctx['gmail_api_relay']:
        return True, rule.reason
    if rid == 'repeated_sends'  and ctx['repeated_sends']:
        return True, rule.reason.format(**ctx)
    if rid == 'bare_ip_relay'   and ctx['bare_ip_relay']:
        return True, rule.reason.format(**ctx)
    if rid == 'sender_lookalike'     and ctx['sender_lookalike_brand']:
        return True, rule.reason.format(**ctx)
    if rid == 'reply_to_mismatch'    and ctx['reply_to_mismatch']:
        return True, rule.reason.format(**ctx)
    if rid == 'return_path_mismatch' and ctx['return_path_mismatch']:
        return True, rule.reason.format(**ctx)

    if rid == 'lookalike_domain' and ctx['lookalike_brand']:
        return True, rule.reason.format(**ctx)
    if rid == 'ip_url'           and ctx['ip_urls']:
        return True, rule.reason.format(**ctx)
    if rid == 'homoglyph_url'    and ctx['homoglyphs']:
        return True, rule.reason.format(**ctx)
    if rid == 'url_shortener'    and ctx['shorteners']:
        return True, rule.reason.format(**ctx)
    if rid == 'suspicious_tld'   and ctx['bad_tld']:
        return True, rule.reason.format(**ctx)
    if rid == 'suspicious_url'   and ctx['suspicious']:
        return True, rule.reason.format(**ctx)
    if rid == 'many_urls'        and ctx['url_count'] > 3:
        return True, rule.reason.format(**ctx)

    if rid == 'urgency_language'  and ctx['has_urgency']:   return True, rule.reason
    if rid == 'credential_harvest' and ctx['has_cred_harvest']: return True, rule.reason
    if rid == 'bec_pattern'       and ctx['has_bec']:
        return True, rule.reason.format(**ctx)
    if rid == 'impersonation_body' and ctx['has_impersonation']:
        return True, rule.reason.format(**ctx)
    if rid == 'attachment_lure'   and ctx['has_attachment_lure']: return True, rule.reason

    if rid == 'url_mismatch_html' and ctx['has_url_mismatch']:  return True, rule.reason
    if rid == 'hidden_content'    and ctx['has_hidden_content']: return True, rule.reason
    if rid == 'credential_form'   and ctx['has_credential_form']: return True, rule.reason
    if rid == 'inline_script'     and ctx['has_inline_script']:  return True, rule.reason

    if rid == 'sender_url_spoof_high'   and ctx['imp_has_high']:
        return True, rule.reason.format(**ctx)
    if rid == 'sender_url_spoof_medium' and ctx['imp_has_medium'] and not ctx['imp_has_high']:
        return True, rule.reason.format(**ctx)
    if rid == 'sender_known_spoof'      and ctx['imp_has_business']:
        return True, rule.reason.format(**ctx)
    if rid == 'sender_homoglyph'        and ctx['imp_has_homoglyph']:
        return True, rule.reason.format(**ctx)
    if rid == 'redirect_service'        and ctx['imp_has_redirect']:
        return True, rule.reason.format(**ctx)

    if rid == 'vt_high_risk'   and ctx['ti_vt_high']:
        return True, rule.reason.format(**ctx)
    if rid == 'vt_medium_risk' and ctx['ti_vt_medium'] and not ctx['ti_vt_high']:
        return True, rule.reason.format(**ctx)
    if rid == 'ismal_flagged'  and ctx['ti_ismal_flagged']:
        return True, rule.reason
    if rid == 'abipdb_high'    and ctx['ti_abipdb_high']:
        return True, rule.reason

    return False, ''


def _build_context(h, u, c, html, imp=None, ti=None):
    imp = imp or {}
    ti  = ti  or {}
    ctx = {}
    ctx.update(h)
    ctx.update({
        'url_count':        u.get('count', 0),
        'ip_urls':          u.get('ip_urls', []),
        'ip_url_sample':    u['ip_urls'][0] if u.get('ip_urls') else '',
        'shorteners':       u.get('shorteners', []),
        'shortener_sample': u['shorteners'][0] if u.get('shorteners') else '',
        'lookalikes':       u.get('lookalikes', []),
        'lookalike_brand':  u['lookalikes'][0]['brand'] if u.get('lookalikes') else '',
        'sender_lookalike_brand': '',
        'homoglyphs':       u.get('homoglyphs', []),
        'homoglyph_domain': u['homoglyphs'][0]['domain'] if u.get('homoglyphs') else '',
        'homoglyph_brand':  u['homoglyphs'][0]['brand']  if u.get('homoglyphs') else '',
        'bad_tld':          u.get('bad_tld', []),
        'bad_tld_sample':   u['bad_tld'][0] if u.get('bad_tld') else '',
        'suspicious':       u.get('suspicious', []),
        'susp_url_sample':  u['suspicious'][0] if u.get('suspicious') else '',
    })
    ctx['sender_lookalike_brand'] = h.get('sender_lookalike_brand', '')
    ctx.update({
        'has_urgency':       c.get('has_urgency', False),
        'has_cred_harvest':  c.get('has_cred_harvest', False),
        'has_bec':           c.get('has_bec', False),
        'bec_hint':          c['bec_hits'][0] if c.get('bec_hits') else '',
        'has_attachment_lure': c.get('has_attachment_lure', False),
        'has_impersonation': c.get('has_impersonation', False),
        'impersonation_brand': c.get('impersonation_brand', ''),
    })
    ctx.update({
        'has_url_mismatch':   html.get('has_url_mismatch',   False),
        'has_hidden_content': html.get('has_hidden_content', False),
        'has_credential_form': html.get('has_credential_form', False),
        'has_inline_script':  html.get('has_inline_script',  False),
    })

    primary = imp.get('primary') or {}
    biz     = imp.get('business_hit') or {}
    homo    = imp.get('homoglyph_hit') or {}
    redir   = (imp.get('redirect_hits') or [{}])[0] if imp.get('redirect_hits') else {}
    ctx.update({
        'imp_has_high':      imp.get('has_high_similarity',   False),
        'imp_has_medium':    imp.get('has_medium_similarity', False),
        'imp_has_business':  imp.get('has_business_match',    False),
        'imp_has_homoglyph': imp.get('has_homoglyph',         False),
        'imp_has_redirect':  imp.get('has_redirect',          False),
        'sender_domain':  imp.get('sender_domain', h.get('from_domain', '')),
        'sender_sld':     imp.get('sender_sld', ''),
        'matched_domain': primary.get('matched_domain', primary.get('matched_sld', '')),
        'matched_sld':    biz.get('matched_sld', primary.get('matched_sld', '')),
        'distance':       primary.get('distance', 0),
        'tactic':         primary.get('tactic', 'Typosquatting'),
        'normalised':     homo.get('normalised', ''),
        'service':        redir.get('service', ''),
    })

    ctx.update({
        'ti_vt_high':         ti.get('vt_high',         False),
        'ti_vt_medium':       ti.get('vt_medium',        False),
        'ti_vt_max_malicious': ti.get('vt_max_malicious', 0),
        'ti_ismal_flagged':   ti.get('ismal_flagged',    False),
        'ti_abipdb_high':     ti.get('abipdb_high',      False),
        'vt_max_malicious':   ti.get('vt_max_malicious', 0),
    })
    return ctx
