import uuid
import requests
from datetime import datetime, timezone
from urllib.parse import urljoin
from probes.base import BaseProbe, Finding, Severity

_SENSITIVE_PATHS = [
    "/admin", "/admin/", "/administrator",
    "/api/docs", "/api/swagger", "/swagger-ui.html", "/swagger.json",
    "/.env", "/config.json", "/phpinfo.php",
    "/wp-admin", "/wp-login.php",
    "/actuator", "/actuator/env", "/actuator/health",
    "/.git/config", "/backup.zip", "/dump.sql",
]


class AuthProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        findings = []
        now = datetime.now(timezone.utc).isoformat()
        base = target_url.rstrip("/")
        for path in _SENSITIVE_PATHS:
            url = urljoin(base + "/", path.lstrip("/"))
            try:
                resp = requests.get(url, timeout=8, allow_redirects=False)
            except requests.RequestException:
                continue
            if resp.status_code == 200:
                findings.append(Finding(
                    id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                    title="Unauthenticated Access to Sensitive Path",
                    description=(
                        f"The path {path} returned HTTP 200 without authentication. "
                        "This may expose admin interfaces, configuration files, or API documentation."
                    ),
                    severity=Severity.HIGH, cvss_score=7.5,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-306", owasp_category="A01:2021 - Broken Access Control",
                    component=path,
                    remediation=(
                        f"Restrict access to {path} with authentication. "
                        "Return 401 or 403 for unauthenticated requests."
                    ),
                    detected_at=now,
                ))
        return findings
