import uuid
from datetime import datetime, timezone
import requests
from probes.base import BaseProbe, Finding, Severity

_HEADERS = [
    {
        "header": "Strict-Transport-Security",
        "title": "Missing HSTS Header",
        "description": "The Strict-Transport-Security header is not set, allowing HTTP downgrade attacks.",
        "severity": Severity.MEDIUM, "cvss_score": 5.3,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-319", "owasp_category": "A05:2021 - Security Misconfiguration",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "header": "X-Frame-Options",
        "title": "Missing X-Frame-Options Header",
        "description": "Without X-Frame-Options, the page may be embedded in an iframe enabling clickjacking.",
        "severity": Severity.MEDIUM, "cvss_score": 6.1,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe_id": "CWE-1021", "owasp_category": "A05:2021 - Security Misconfiguration",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    {
        "header": "X-Content-Type-Options",
        "title": "Missing X-Content-Type-Options Header",
        "description": "Without nosniff, browsers may MIME-sniff responses, enabling content injection.",
        "severity": Severity.MEDIUM, "cvss_score": 4.3,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-693", "owasp_category": "A05:2021 - Security Misconfiguration",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "header": "Content-Security-Policy",
        "title": "Missing Content-Security-Policy Header",
        "description": "No CSP header found. Increases risk of XSS and data injection attacks.",
        "severity": Severity.MEDIUM, "cvss_score": 6.1,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe_id": "CWE-693", "owasp_category": "A03:2021 - Injection",
        "remediation": "Add a Content-Security-Policy header. Minimum: default-src 'self'",
    },
    {
        "header": "Referrer-Policy",
        "title": "Missing Referrer-Policy Header",
        "description": "Without Referrer-Policy, sensitive URL parameters may leak to third parties.",
        "severity": Severity.LOW, "cvss_score": 3.1,
        "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-200", "owasp_category": "A05:2021 - Security Misconfiguration",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "header": "Permissions-Policy",
        "title": "Missing Permissions-Policy Header",
        "description": "Without Permissions-Policy, browser features (camera, mic, geolocation) are unrestricted.",
        "severity": Severity.LOW, "cvss_score": 3.1,
        "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-732", "owasp_category": "A05:2021 - Security Misconfiguration",
        "remediation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
]


class HeadersProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        try:
            resp = requests.get(target_url, timeout=10, allow_redirects=True)
        except requests.RequestException:
            return []
        findings = []
        now = datetime.now(timezone.utc).isoformat()
        for spec in _HEADERS:
            if spec["header"] not in resp.headers:
                findings.append(Finding(
                    id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                    title=spec["title"], description=spec["description"],
                    severity=spec["severity"], cvss_score=spec["cvss_score"],
                    cvss_vector=spec["cvss_vector"], cwe_id=spec["cwe_id"],
                    owasp_category=spec["owasp_category"],
                    component=f"{spec['header']} header",
                    remediation=spec["remediation"], detected_at=now,
                ))
        return findings
