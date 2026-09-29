"""Analyze attachment filenames and metadata."""

DANGEROUS = {'.exe', '.scr', '.bat', '.cmd', '.js', '.vbs', '.ps1', '.hta'}
MACRO = {'.docm', '.xlsm', '.pptm', '.dotm', '.xltm'}
ARCHIVES = {'.zip', '.rar', '.7z', '.iso', '.img'}

def analyze_attachments(attachments):
    findings = []
    for attachment in attachments:
        filename = attachment.get('filename', 'unnamed')
        extensions = [f'.{part.lower()}' for part in filename.split('.')[1:]]
        final = extensions[-1] if extensions else ''
        if final in DANGEROUS:
            findings.append({'signal': 'dangerous_extension', 'weight': 50, 'detail': f"Attachment '{filename}' has an executable/script extension ({final})."})
        if final in MACRO:
            findings.append({'signal': 'macro_enabled_document', 'weight': 35, 'detail': f"Attachment '{filename}' is a macro-enabled Office document ({final})."})
        if len(extensions) >= 2 and final in DANGEROUS | MACRO:
            findings.append({'signal': 'double_extension', 'weight': 40, 'detail': f"Attachment '{filename}' uses a double extension to disguise its real type."})
        if final in ARCHIVES:
            findings.append({'signal': 'archive_attachment', 'weight': 15, 'detail': f"Attachment '{filename}' is a compressed archive that was not inspected."})
    return findings
