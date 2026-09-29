"""Format PhishGuard reports."""

import json
from dataclasses import asdict

def format_json(report, source_label=None):
    data = asdict(report)
    data['category_scores'] = {key: {'score': round(value['raw_score']), 'findings': value['findings']} for key, value in data['category_scores'].items()}
    if source_label: data['source'] = source_label
    return json.dumps(data, indent=2)

def format_text(report, source_label=None):
    lines = [f'PhishGuard Report - {source_label or "email"}', f'Overall Risk Score: {report.overall_score}/100', f'Verdict: {report.verdict}', '', 'Category Breakdown:']
    lines.extend(f'  - {name.title():12} {round(score.raw_score):3}/100 ({len(score.findings)} finding(s))' for name, score in report.category_scores.items())
    lines.extend(['', 'Recommended Actions:'])
    lines.extend(f'  - {action}' for action in report.recommendations)
    return '\n'.join(lines)
