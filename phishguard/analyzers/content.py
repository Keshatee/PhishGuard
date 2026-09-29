"""Analyze suspicious email language."""

URGENCY = ['act now', 'urgent', 'verify your account', 'account suspended', 'final notice', 'within 24 hours', 'unusual activity']
CREDENTIALS = ['enter your password', 'social security number', 'credit card number', 'verify your payment', 'login credentials', 'gift card', 'one-time password']
GREETINGS = ['dear customer', 'dear user', 'dear valued customer', 'dear account holder']

def _hits(text, phrases):
    lowered = text.lower()
    return [phrase for phrase in phrases if phrase in lowered]

def analyze_content(parsed_email):
    subject = parsed_email.get('subject', '') or ''
    body = parsed_email.get('body_text', '') or ''
    combined = f'{subject}\n{body}'
    findings = []
    urgency = _hits(combined, URGENCY)
    if urgency:
        findings.append({'signal': 'urgency_language', 'weight': min(10 * len(urgency), 35), 'detail': f"Uses urgency/pressure phrasing: {', '.join(urgency[:3])}."})
    credentials = _hits(combined, CREDENTIALS)
    if credentials:
        findings.append({'signal': 'credential_request', 'weight': min(15 * len(credentials), 45), 'detail': f"Requests sensitive information: {', '.join(credentials[:3])}."})
    greetings = _hits(combined, GREETINGS)
    if greetings:
        findings.append({'signal': 'generic_greeting', 'weight': 10, 'detail': f"Uses a generic greeting ('{greetings[0]}')."})
    if combined.count('!') >= 3:
        findings.append({'signal': 'excessive_punctuation', 'weight': 10, 'detail': 'Subject/body contain excessive exclamation marks.'})
    return findings
