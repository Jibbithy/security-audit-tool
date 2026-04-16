from probes.base import Finding, Severity, AuditTarget, RunDelta


def test_finding_fields():
    f = Finding(
        id="abc", run_id="run1", target_url="https://example.com",
        title="Missing HSTS", description="No HSTS header",
        severity=Severity.MEDIUM, cvss_score=5.3,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cwe_id="CWE-319", owasp_category="A05:2021",
        component="Strict-Transport-Security header",
        remediation="Add Strict-Transport-Security: max-age=31536000",
        detected_at="2026-04-16T00:00:00Z",
    )
    assert f.severity == Severity.MEDIUM
    assert f.cvss_score == 5.3


def test_severity_values():
    assert Severity.CRITICAL != Severity.HIGH
    assert Severity.LOW != Severity.INFO


def test_audit_target_fields():
    t = AuditTarget(url="https://example.com", scope="FULL_PASSIVE", priority="HIGH", row_index=2)
    assert t.url == "https://example.com"


def test_run_delta_empty():
    d = RunDelta(new_findings=[], fixed_finding_ids=[], regressed_findings=[])
    assert d.new_findings == []
