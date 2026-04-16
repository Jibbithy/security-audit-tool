import uuid
from datetime import datetime, timezone
from probes.base import Finding, Severity


def make_finding(run_id="run1", cwe_id="CWE-319", cvss=5.3) -> Finding:
    return Finding(
        id=str(uuid.uuid4()), run_id=run_id, target_url="https://example.com",
        title="Missing HSTS", description="No HSTS header present",
        severity=Severity.MEDIUM, cvss_score=cvss,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cwe_id=cwe_id, owasp_category="A05:2021",
        component="Strict-Transport-Security header",
        remediation="Add HSTS header",
        detected_at=datetime.now(timezone.utc).isoformat(),
    )


def test_insert_and_fetch_findings():
    from db import Database
    db = Database(":memory:")
    db.save_run("run1", "https://example.com", "2026-04-16T00:00:00Z", "2026-04-16T00:05:00Z")
    db.save_finding(make_finding(run_id="run1"))
    results = db.get_findings_for_target("https://example.com")
    assert len(results) == 1
    assert results[0].title == "Missing HSTS"


def test_delta_detects_new_finding():
    from db import Database
    db = Database(":memory:")
    db.save_run("run1", "https://example.com", "2026-04-16T00:00:00Z", "2026-04-16T00:05:00Z")
    db.save_finding(make_finding(run_id="run1", cwe_id="CWE-319"))
    db.save_run("run2", "https://example.com", "2026-04-16T01:00:00Z", "2026-04-16T01:05:00Z")
    db.save_finding(make_finding(run_id="run2", cwe_id="CWE-693"))  # new CWE
    delta = db.compute_delta("https://example.com", "run2")
    assert any(f.cwe_id == "CWE-693" for f in delta.new_findings)


def test_delta_detects_fixed_finding():
    from db import Database
    db = Database(":memory:")
    db.save_run("run1", "https://example.com", "2026-04-16T00:00:00Z", "2026-04-16T00:05:00Z")
    f1 = make_finding(run_id="run1", cwe_id="CWE-319")
    db.save_finding(f1)
    db.save_run("run2", "https://example.com", "2026-04-16T01:00:00Z", "2026-04-16T01:05:00Z")
    # run2 has no findings — CWE-319 is fixed
    delta = db.compute_delta("https://example.com", "run2")
    assert f1.id in delta.fixed_finding_ids


def test_delta_detects_regression():
    from db import Database
    db = Database(":memory:")
    db.save_run("run1", "https://example.com", "2026-04-16T00:00:00Z", "2026-04-16T00:05:00Z")
    db.save_finding(make_finding(run_id="run1", cwe_id="CWE-319", cvss=5.3))
    db.save_run("run2", "https://example.com", "2026-04-16T01:00:00Z", "2026-04-16T01:05:00Z")
    db.save_finding(make_finding(run_id="run2", cwe_id="CWE-319", cvss=7.5))  # same CWE, higher CVSS
    delta = db.compute_delta("https://example.com", "run2")
    assert any(f.cwe_id == "CWE-319" for f in delta.regressed_findings)
