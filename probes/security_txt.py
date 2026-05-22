import uuid
import requests
from datetime import datetime, timezone
from probes.base import BaseProbe, Finding, Severity


class SecurityTxtProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        base = target_url.rstrip("/")

        for path in ("/.well-known/security.txt", "/security.txt"):
            try:
                resp = requests.get(f"{base}{path}", timeout=8, allow_redirects=True)
                if resp.status_code == 200 and "contact" in resp.text.lower():
                    return []  # security.txt exists and looks valid
            except requests.RequestException:
                pass

        return [Finding(
            id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
            title="No security.txt Found",
            description=(
                "The site does not have a security.txt file (RFC 9116). This file tells security "
                "researchers how to responsibly report vulnerabilities they find on your site."
            ),
            severity=Severity.INFO, cvss_score=0.0,
            cvss_vector="",
            cwe_id="CWE-205", owasp_category="A05:2021 - Security Misconfiguration",
            component="/.well-known/security.txt",
            remediation=(
                "Create a security.txt at /.well-known/security.txt with at minimum: "
                "Contact: mailto:security@yourdomain.com and Expires: <date>"
            ),
            detected_at=now,
        )]
