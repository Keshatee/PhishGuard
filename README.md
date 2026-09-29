# PhishGuard 🛡️

PhishGuard analyzes emails (`.eml` files) for phishing indicators across four
categories — **sender identity, links, attachments, and content language** —
and produces an explainable risk score instead of a black-box verdict.

```
============================================================
PhishGuard Report — sample_phishing.eml
============================================================
Overall Risk Score: 69/100
Verdict: High Risk

Category Breakdown:
  - Sender       100/100 (5 finding(s))
  - Links        60/100 (2 finding(s))
  - Attachments  35/100 (1 finding(s))
  - Content      80/100 (5 finding(s))

Key Findings (highest weight first):
  [links] (+40) Hostname contains 'paypal' but isn't the real paypal.com domain: paypal.com.verify-account-login.xyz
  [sender] (+35) Display name references 'paypal' but sending domain is 'paypa1-support.xyz'.
  [attachments] (+35) Attachment 'Account_Verification_Form.docm' is a macro-enabled Office document (.docm).
  [content] (+35) Uses urgency/pressure phrasing: act now, urgent, unusual activity.
  ...
============================================================
```

## Why explainable, not just a score

A bare "82% phishing" number isn't actionable and isn't trustworthy. Every
score PhishGuard produces traces back to the specific signals that caused it
— SPF failure, a typosquatted domain, a macro-enabled attachment, urgency
language — so you (or your user) can verify the reasoning, not just believe it.

## How scoring works

Each analyzer returns a list of findings (`{signal, weight, detail}`).
Findings within a category are summed and capped at 100, then categories are
combined with fixed weights:

| Category    | Weight | Why                                                          |
|-------------|--------|---------------------------------------------------------------|
| Sender      | 30%    | Spoofing/SPF/DKIM/DMARC failures are strong, hard-to-fake signals |
| Links       | 30%    | Malicious URLs are the actual attack delivery mechanism       |
| Attachments | 25%    | Executable/macro payloads are high-confidence indicators      |
| Content     | 15%    | Easiest for an attacker to "clean up," so weighted lowest      |

Final score maps to a verdict tier: **Likely Safe → Low → Moderate → High → Critical.**

See `phishguard/scoring.py` for the exact math and `phishguard/analyzers/`
for every individual signal each category checks.

## Installation

```bash
git clone https://github.com/yourusername/phishguard.git
cd phishguard
pip install -r requirements.txt
cp .env.example .env   # optional -- see "Optional live threat-intel" below
```

No API keys are required to run PhishGuard. All core analysis is done via
local heuristics and works fully offline.

## Usage

**Single email:**
```bash
python cli.py sample_data/sample_phishing.eml
```

**Batch mode (folder of `.eml` files) with a CSV summary:**
```bash
python cli.py path/to/inbox_export/ --csv results.csv
```

**JSON output** (for piping into other tools / a future API layer):
```bash
python cli.py sample_data/sample_phishing.eml --json
```

**Show the installed version:**
```bash
python cli.py --version
```

**Run the local web dashboard:**
```bash
python web.py
```
Then open `http://127.0.0.1:5000` and upload an `.eml` file.

Every report includes recommended actions. High-risk messages are explicitly
marked as messages that should not be clicked, replied to, or opened, and the
recommendations identify whether the user should verify the sender, avoid a
link, or submit an attachment to security staff.

## What it checks

**Sender (`analyzers/sender.py`)**
- SPF / DKIM / DMARC pass/fail
- Display name impersonation (e.g. "PayPal Support" from a non-PayPal domain)
- Typosquatted sending domains (`paypa1.com`, `micros0ft.com`, etc.)
- Reply-To / Return-Path domain mismatches
- Brand names sent from free webmail providers
- Optional: WHOIS domain-age lookup (`try_domain_age_lookup`)

**Links (`analyzers/links.py`)**
- Raw IP-address URLs
- Known URL shorteners masking the real destination
- Suspicious/commonly-abused TLDs (`.xyz`, `.top`, `.click`, etc.)
- Excessive subdomain nesting used to disguise the real domain
- `user@host` URL obfuscation tricks
- Brand-lookalike hostnames (`paypal.com.verify-login.xyz`)
- Optional: Google Safe Browsing lookup (`check_url_reputation`)

**Attachments (`analyzers/attachments.py`)**
- Dangerous executable/script extensions (`.exe`, `.js`, `.vbs`, `.ps1`, ...)
- Macro-enabled Office documents (`.docm`, `.xlsm`, ...)
- Double-extension disguises (`invoice.pdf.exe`)
- Declared MIME type vs. extension mismatches
- Optional: VirusTotal hash lookup (`check_attachment_hash`)

**Content (`analyzers/content.py`)**
- Urgency/pressure language ("act now", "account suspended", ...)
- Credential/payment-info harvesting phrases
- Generic, non-personalized greetings
- Excessive punctuation/caps-lock shouting

## Optional live threat-intel

Sender-domain age, URL reputation, and attachment-hash checks can call out
to WHOIS / Google Safe Browsing / VirusTotal if you add API keys to `.env`.
**These are entirely optional** — every lookup function soft-fails to `None`
(meaning "unknown," never "safe") if no key is configured, so the core tool
never depends on network access or paid APIs to function.

## Project structure

```
phishguard/
├── cli.py                      # entry point
├── phishguard/
│   ├── parser.py                # .eml -> structured dict
│   ├── utils.py                  # dependency-free domain parsing
│   ├── scoring.py                # combines findings into a risk score
│   ├── report.py                 # text / JSON formatting
│   └── analyzers/
│       ├── sender.py
│       ├── links.py
│       ├── attachments.py
│       └── content.py
├── sample_data/                 # sample phishing + legit .eml for demos
├── tests/
└── requirements.txt
```

## Running tests

```bash
python -m pip install -r requirements.txt pytest
pytest tests/
```

## Roadmap / ideas for contribution

- [ ] ML layer: TF-IDF + logistic regression classifier as a second opinion alongside the rule-based score
- [ ] Add unit tests for malformed emails, HTML-only messages, nested MIME parts, and false-positive cases
- [ ] Add CI with a supported Python-version matrix, linting, and sample CLI smoke tests
- [ ] Add a FastAPI or Flask service only after the CLI/report contract is stable
- [ ] Add privacy controls: redact message bodies in logs and make all network lookups opt-in
- [ ] Browser extension that flags suspicious links on hover
- [ ] FastAPI wrapper for a hosted API mode
- [ ] Redirect-chain following for shortened/obfuscated URLs
- [ ] Expand the known-brand list and load it from an external JSON file
- [ ] Labeled benchmark dataset + precision/recall reporting in CI

Contributions welcome — open an issue or PR.

## Disclaimer

PhishGuard is a heuristic educational/portfolio security tool. It is **not**
a substitute for enterprise email security products, and a low score does
not guarantee an email is safe. Always verify suspicious emails through an
independent channel before acting on them.

## License

MIT — see `LICENSE`.
