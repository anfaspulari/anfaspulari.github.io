# PhishScan v2 — Multi-Layer Phishing Detection Engine

A professional-grade command-line tool for SOC analysts to triage suspicious emails. PhishScan runs six independent intelligence layers against a `.eml` file and aggregates findings into a weighted risk score (0-100) with a human-readable verdict.

---

## Real-World SOC Relevance

Phishing is the #1 initial access vector in breach reports. Manual email triage is slow and inconsistent. PhishScan automates first-pass triage by extracting the same signals a skilled analyst would look for.

Key use cases:
- **Tier 1 triage automation** — quickly classify reported phishing emails
- **BEC / fraud investigation** — detect lookalike domains and Gmail API abuse
- **IOC extraction** — pull defanged URLs, IPs, and domains for blocklisting
- **Awareness training** — demonstrate why technically "clean" emails are phishing

---

## Architecture

```
phishscan-cli/
├── main.py                        <- CLI entry point
├── analyzer/
│   ├── header_analyzer.py         <- SPF/DKIM/DMARC, MS headers, relay chain
│   ├── url_analyzer.py            <- IP URLs, lookalike, homoglyph, TLD analysis
│   ├── content_analyzer.py        <- Urgency language, BEC patterns, impersonation
│   ├── html_analyzer.py           <- Hidden links, credential forms, URL mismatch
│   ├── impersonation_detector.py  <- Levenshtein typosquatting, homoglyph, redirects
│   ├── scoring_engine.py          <- Weighted rule model -> risk score + verdict
│   └── threat_intel.py            <- VirusTotal, isMalicious, AbuseIPDB APIs
├── utils/
│   ├── parser.py                  <- Email loading and MIME body extraction
│   └── helpers.py                 <- Defang, brand list, lookalike detection, TLD lists
├── analyzers/
│   └── iocs.py                    <- IOC extractor (domains, IPs, hashes)
├── .env.example                   <- API key template (copy to .env)
└── README.md
```

---

## Detection Layers

### 1. Header Analysis
| Signal | What it means |
|--------|---------------|
| SPF FAIL / NONE | Sending IP not authorised for the domain |
| DKIM absent / invalid | Message not cryptographically signed |
| DMARC `bestguesspass` | No published DMARC policy — spoofing risk |
| Microsoft SCL >= 5 / SFV:SPM | Exchange anti-spam engine flagged it |
| Gmail API relay | Business email sent via `gmailapi.google.com` — red flag |
| Reply-To mismatch | Replies go to attacker-controlled address |

### 2. URL Intelligence
| Signal | What it means |
|--------|---------------|
| IP-based URL | `http://185.1.2.3/login` — never legitimate |
| Lookalike domain | Edit-distance <= 2 from a known brand |
| Homoglyph attack | Digit/letter substitution (`paypa1`, `rnicrosoft`) |
| Suspicious TLD | `.xyz`, `.top`, `.tk` — high-abuse registrations |
| URL shortener | `bit.ly`, `t.co` — hides the actual landing page |

### 3. Content Analysis
| Signal | Example |
|--------|--------|
| Urgency / fear | "Your account has been suspended" |
| Credential harvesting | "Enter your password below" |
| BEC pattern | "Request for Quote", "wire transfer" |
| Brand impersonation | Body claims Zendesk but From is zendesks.ca |

### 4. HTML Structure Analysis
| Signal | What it means |
|--------|---------------|
| URL display/destination mismatch | Shows `paypal.com` but links elsewhere |
| Hidden elements | `display:none` — filter evasion |
| Credential form | `<input type=password>` in email body |

### 5. Impersonation Detector
Cross-references the sender domain against all URL domains in the email body using Levenshtein edit distance. A domain registered 1 edit from the target (e.g. `grosvernor.com` vs `grosvenor.com`) passes SPF/DKIM — this is the only reliable detection method.

| Risk | Distance | Points |
|------|----------|--------|
| HIGH | <= 2 edits | +40 |
| MEDIUM | <= 3 edits | +20 |

Also detects: homoglyph attacks, Mimecast/SafeLinks/Proofpoint redirect wrapping.

### 6. Threat Intelligence (optional)
Queries external APIs to corroborate internal findings:
- **VirusTotal v3** — domain + URL reputation (70+ AV engines)
- **isMalicious** — fast domain / IP reputation
- **AbuseIPDB** — IP abuse confidence score

External API signals are capped at 40 pts total to prevent API over-reliance.

---

## Risk Scoring

| Score | Verdict |
|-------|---------|
| 0 - 30 | **LOW RISK** |
| 31 - 70 | **SUSPICIOUS** |
| 71 - 100 | **HIGH RISK PHISHING** |

---

## Installation

```bash
git clone https://github.com/anfaspulari/anfaspulari.github.io
cd anfaspulari.github.io/phishscan-cli
pip install colorama          # optional -- enables coloured output
```

### API Keys (optional)

Copy `.env.example` to `.env` and fill in your keys to enable threat intelligence:

```bash
cp .env.example .env
# Edit .env with your keys
```

The `.env` file is git-ignored and never committed. Keys are auto-loaded at runtime.

---

## Usage

```bash
# Standard analysis (with threat intel if .env configured)
python main.py suspicious_email.eml

# Skip external API lookups (offline mode)
python main.py suspicious_email.eml --no-api

# JSON output (for SIEM ingestion)
python main.py suspicious_email.eml --json

# Show all rules (not just hits)
python main.py suspicious_email.eml --verbose

# Disable colour
python main.py suspicious_email.eml --no-color
```

---

## Example: Zendesk BEC Campaign

The Zendesk BEC phishing email scored **0/100** in legacy tools (SPF/DKIM both PASS). PhishScan v2 scores it **100/100** because:

```
  Score   : 100/100  [####################]
  Verdict : HIGH RISK PHISHING

  DETECTION REASONS
    [HEADER]
    +10  DMARC not enforced (bestguesspass) -- spoofing risk
    +25  Microsoft Exchange flagged as spam (SCL:5, SFV:SPM, CAT:SPM)
    +20  Email sent via Gmail API -- unusual for business email
    +10  Email re-sent 3x via Gmail API -- automated campaign behaviour
    +30  Sender domain "zendesks.ca" is a lookalike of brand "zendesk"
    [CONTENT]
    +15  BEC pattern detected (request  quote)
    +20  Body claims to be from "zendesk" but From domain does not match
```

- SPF/DKIM **passed** for `zendesks.ca` -- the attacker registered and controls this lookalike domain
- **DMARC `bestguesspass`** -- Microsoft infers a policy that was never published
- **Microsoft's own spam engine** already flagged it (SCL:5, CAT:SPM)
- **Gmail API relay** -- legitimate companies don't use Gmail API to send business email
- **Lookalike domain** -- `zendesks.ca` is 1 edit away from `zendesk`
