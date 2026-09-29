import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishguard.analyzers.attachments import analyze_attachments
from phishguard.analyzers.content import analyze_content
from phishguard.analyzers.links import analyze_links, extract_urls
from phishguard.analyzers.sender import analyze_sender
from phishguard.parser import parse_eml
from phishguard.scoring import compute_risk_score

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"


def _score_file(filename: str):
    parsed = parse_eml(SAMPLE_DIR / filename)
    sender_findings = analyze_sender(parsed)
    urls = extract_urls(parsed)
    link_findings = analyze_links(urls)
    attachment_findings = analyze_attachments(parsed["attachments"])
    content_findings = analyze_content(parsed)
    return compute_risk_score(sender_findings, link_findings, attachment_findings, content_findings)


def test_phishing_sample_scores_high():
    report = _score_file("sample_phishing.eml")
    assert report.overall_score >= 60
    assert report.verdict in ("High Risk", "Critical Risk")


def test_legit_sample_scores_low():
    report = _score_file("sample_legit.eml")
    assert report.overall_score < 35
    assert report.verdict in ("Likely Safe", "Low Risk")


def test_phishing_sample_flags_typosquat_and_macro():
    parsed = parse_eml(SAMPLE_DIR / "sample_phishing.eml")
    sender_findings = analyze_sender(parsed)
    attachment_findings = analyze_attachments(parsed["attachments"])

    sender_signals = {f["signal"] for f in sender_findings}
    attachment_signals = {f["signal"] for f in attachment_findings}

    assert "typosquat_domain" in sender_signals or "display_name_mismatch" in sender_signals
    assert "macro_enabled_document" in attachment_signals


def test_sender_flags_brand_impersonation_and_reply_to_mismatch():
    findings = analyze_sender(
        {
            "from_address": "security@paypa1-support.xyz",
            "from_display_name": "PayPal Security",
            "reply_to_address": "help@external-mail.example",
            "auth_results": {"spf": "fail", "dkim": "pass", "dmarc": "fail"},
        }
    )

    signals = {finding["signal"] for finding in findings}
    assert "display_name_mismatch" in signals
    assert "reply_to_mismatch" in signals
    assert "spf_fail" in signals
    assert "dmarc_fail" in signals


def test_links_flag_obfuscation_but_allow_official_subdomain():
    findings = analyze_links(
        [
            "https://paypal.com.verify-account.xyz/login",
            "https://login.paypal.com/account",
            "http://192.0.2.10/verify",
        ]
    )

    signals = {finding["signal"] for finding in findings}
    assert "brand_lookalike_hostname" in signals
    assert "ip_based_url" in signals

    lookalike_details = [
        finding["detail"]
        for finding in findings
        if finding["signal"] == "brand_lookalike_hostname"
    ]
    assert all("login.paypal.com" not in detail for detail in lookalike_details)
