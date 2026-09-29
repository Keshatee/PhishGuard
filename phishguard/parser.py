"""Parse .eml files into analyzer input."""

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
import hashlib

def parse_eml(path: Path):
    with path.open('rb') as stream:
        message = BytesParser(policy=policy.default).parse(stream)
    text, html, attachments = '', '', []
    for part in message.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b''
        filename = part.get_filename()
        if filename or part.get_content_disposition() == 'attachment':
            attachments.append({'filename': filename or 'unnamed', 'content_type': part.get_content_type(), 'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()})
        elif part.get_content_type() == 'text/plain':
            text += part.get_content() or ''
        elif part.get_content_type() == 'text/html':
            html += part.get_content() or ''
    from_header = message.get('From', '')
    def address(name):
        return parseaddr(message.get(name, ''))[1].strip().lower() or None
    auth = {}
    for value in message.get_all('Authentication-Results', []):
        for token in value.lower().replace(';', ' ').split():
            if '=' in token:
                key, result = token.split('=', 1)
                if key in {'spf', 'dkim', 'dmarc'}:
                    auth[key] = result
    return {'subject': message.get('Subject', ''), 'from_address': address('From') or '', 'from_display_name': parseaddr(from_header)[0], 'reply_to_address': address('Reply-To'), 'return_path': address('Return-Path'), 'auth_results': auth, 'body_text': text, 'body_html': html, 'attachments': attachments}
