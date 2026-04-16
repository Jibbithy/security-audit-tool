import asyncio, uuid
from unittest.mock import patch, MagicMock
from probes.base import Finding, Severity
from datetime import datetime, timezone


def make_finding():
    return Finding(
        id=str(uuid.uuid4()), run_id="run1", target_url="https://example.com",
        title="Missing HSTS", description="No HSTS", severity=Severity.MEDIUM,
        cvss_score=5.3, cvss_vector="", cwe_id="CWE-319", owasp_category="A05:2021",
        component="HSTS header", remediation="Add HSTS",
        detected_at=datetime.now(timezone.utc).isoformat(),
    )


def test_audit_target_returns_findings():
    from claude_agent import audit_target_with_claude
    findings_input = [make_finding()]
    fake_message = MagicMock()
    fake_message.content = [MagicMock(
        text='{"risk_level":"MEDIUM","summary":"One medium finding.","false_positive_ids":[],"additional_notes":""}'
    )]
    with patch("claude_agent.anthropic.Anthropic") as mock_cls:
        mock_cls.return_value.messages.create.return_value = fake_message
        result = asyncio.run(audit_target_with_claude(
            target_url="https://example.com",
            run_id="run1",
            findings=findings_input,
            api_key="sk-test",
            timeout=30,
        ))
    assert isinstance(result, list)
    assert len(result) == 1


def test_audit_target_filters_false_positives():
    from claude_agent import audit_target_with_claude
    f = make_finding()
    fake_message = MagicMock()
    fake_message.content = [MagicMock(
        text=f'{{"risk_level":"LOW","summary":"FP found.","false_positive_ids":["{f.id}"],"additional_notes":""}}'
    )]
    with patch("claude_agent.anthropic.Anthropic") as mock_cls:
        mock_cls.return_value.messages.create.return_value = fake_message
        result = asyncio.run(audit_target_with_claude(
            target_url="https://example.com",
            run_id="run1",
            findings=[f],
            api_key="sk-test",
            timeout=30,
        ))
    assert result == []  # finding filtered as false positive
