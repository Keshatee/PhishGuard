"""Calculate explainable risk scores."""

from dataclasses import dataclass

CATEGORY_WEIGHTS = {'sender': .30, 'links': .30, 'attachments': .25, 'content': .15}
@dataclass(frozen=True)
class CategoryScore:
    raw_score: float
    findings: list
@dataclass(frozen=True)
class RiskReport:
    overall_score: int
    verdict: str
    category_scores: dict
    recommendations: list

def _verdict(score):
    if score >= 80: return 'Critical Risk'
    if score >= 60: return 'High Risk'
    if score >= 35: return 'Moderate Risk'
    if score >= 15: return 'Low Risk'
    return 'Likely Safe'

def compute_risk_score(sender, links, attachments, content):
    grouped = {'sender': sender, 'links': links, 'attachments': attachments, 'content': content}
    scores = {name: CategoryScore(min(100, sum(item.get('weight', 0) for item in findings)), findings) for name, findings in grouped.items()}
    overall = round(sum(scores[name].raw_score * weight for name, weight in CATEGORY_WEIGHTS.items()))
    recommendations = ['Do not click links, open attachments, or reply to this message.'] if overall >= 60 else ['No strong phishing indicators were detected; remain cautious with unexpected messages.']
    return RiskReport(overall, _verdict(overall), scores, recommendations)
