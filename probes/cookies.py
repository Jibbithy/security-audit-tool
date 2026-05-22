import uuid
import requests
from datetime import datetime, timezone
from probes.base import BaseProbe, Finding, Severity

_CHECKS = [
    (
        "Secure",
        "Cookie Missing Secure Flag",
        "The cookie can be transmitted over unencrypted HTTP, exposing it to network interception.",
        Severity.MEDIUM, 5.9, "CWE-614",
        "A05:2021 - Security Misconfiguration",
        "Add the Secure flag to all cookies: Set-Cookie: name=value; Secure",
    ),
    (
        "HttpOnly",
        "Cookie Missing HttpOnly Flag",
        "JavaScript running on the page can read this cookie, making it vulnerable to theft via XSS.",
        Severity.MEDIUM, 5.4, "CWE-1004",
        "A05:2021 - Security Misconfiguration",
        "Add the HttpOnly flag to session and auth cookies: Set-Cookie: name=value; HttpOnly",
    ),
    (
        "SameSite",
        "Cookie Missing SameSite Attribute",
        "Without SameSite, the cookie is sent with cross-site requests, enabling CSRF attacks.",
        Severity.MEDIUM, 4.3, "CWE-352",
        "A01:2021 - Broken Access Control",
        "Add SameSite=Strict or SameSite=Lax to all cookies: Set-Cookie: name=value; SameSite=Lax",
    ),
]


class CookiesProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        try:
            resp = requests.get(target_url, timeout=10, allow_redirects=True)
        except requests.RequestException:
            return []

        # urllib3 stores multiple Set-Cookie headers correctly
        raw_cookies: list[str] = resp.raw.headers.getlist("Set-Cookie")
        if not raw_cookies:
            return []

        findings = []
        now = datetime.now(timezone.utc).isoformat()
        already_reported: set[str] = set()

        for cookie_str in raw_cookies:
            parts = [p.strip().lower() for p in cookie_str.split(";")]
            cookie_name = cookie_str.split("=")[0].strip()

            for flag, title, description, severity, cvss, cwe_id, owasp, remediation in _CHECKS:
                dedup_key = f"{flag}"
                if dedup_key in already_reported:
                    continue
                if flag.lower() not in parts:
                    already_reported.add(dedup_key)
                    findings.append(Finding(
                        id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                        title=title,
                        description=f"{description} (seen on cookie: {cookie_name})",
                        severity=severity, cvss_score=cvss, cvss_vector="",
                        cwe_id=cwe_id, owasp_category=owasp,
                        component=f"Set-Cookie: {cookie_name}",
                        remediation=remediation, detected_at=now,
                    ))
        return findings
