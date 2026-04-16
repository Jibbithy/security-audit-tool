import uuid, os
from datetime import datetime, timezone
from probes.base import Finding, Severity, RunDelta


def make_finding(run_id="run1"):
    return Finding(
        id=str(uuid.uuid4()), run_id=run_id, target_url="https://example.com",
        title="Missing HSTS", description="No HSTS", severity=Severity.MEDIUM,
        cvss_score=5.3, cvss_vector="", cwe_id="CWE-319", owasp_category="A05:2021",
        component="HSTS header", remediation="Add HSTS",
        detected_at=datetime.now(timezone.utc).isoformat(),
    )


def test_reporter_generates_html(tmp_path):
    from reporter import generate_report
    html_path = generate_report(
        target_url="https://example.com",
        run_id="run1",
        scope="FULL_PASSIVE",
        findings=[make_finding()],
        delta=None,
        output_dir=str(tmp_path),
        generate_pdf=False,
    )
    assert os.path.exists(html_path)
    content = open(html_path).read()
    assert "Missing HSTS" in content
    assert "example.com" in content
    assert "CWE-319" in content


def test_reporter_includes_delta_highlights(tmp_path):
    from reporter import generate_report
    f = make_finding()
    delta = RunDelta(new_findings=[f], fixed_finding_ids=[], regressed_findings=[])
    html_path = generate_report(
        target_url="https://example.com",
        run_id="run1",
        scope="FULL_PASSIVE",
        findings=[f],
        delta=delta,
        output_dir=str(tmp_path),
        generate_pdf=False,
    )
    content = open(html_path).read()
    assert "NEW" in content


def test_reporter_computes_correct_summary_for_critical(tmp_path):
    from reporter import generate_report
    f = make_finding()
    f.severity = Severity.CRITICAL
    f.cvss_score = 9.8
    html_path = generate_report(
        target_url="https://example.com",
        run_id="run1",
        scope="FULL_PASSIVE",
        findings=[f],
        delta=None,
        output_dir=str(tmp_path),
        generate_pdf=False,
    )
    content = open(html_path).read()
    assert "CRITICAL" in content or "critical" in content.lower()
